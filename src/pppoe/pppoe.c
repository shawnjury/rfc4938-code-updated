/***********************************************************************
*
* pppoe.c
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Copyright (C) 2000-2006 by Roaring Penguin Software Inc.
* Copyright (C) 2007-2008 by Cisco Systems, Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* LIC: GPL
*
* This file was modified on Feb 2008 by Cisco Systems, Inc.
***********************************************************************/

#include "pppoe.h"
#include "pppoe_rfc4938.h"
#include "pppoe_rfc4938_nbr.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef USE_LINUX_PACKET
#include <sys/ioctl.h>
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef HAVE_N_HDLC
#ifndef N_HDLC
#include <linux/termios.h>
#endif
#endif

/* Default interface if no -I option given */
#define DEFAULT_IF "eth0"

/* Global variables -- options */
int optInactivityTimeout = 0;        /* Inactivity timeout */
int optClampMSS          = 0;        /* Clamp MSS to this value */
int optSkipSession       = 0;        /* Perform discovery, print session info
                                   and exit */
int optFloodDiscovery    = 0;   /* Flood server with discovery requests.
                                   USED FOR STRESS-TESTING ONLY.  DO NOT
                                   USE THE -F OPTION AGAINST A REAL ISP */

PPPoEConnection *Connection = NULL; /* Must be global -- used
                                       in signal handler */

int persist = 0;                 /* We are not a pppd plugin */


/***********************************************************************
*%FUNCTION: sendSessionPacket
*%ARGUMENTS:
* conn -- PPPoE connection
* packet -- the packet to send
* len -- length of data to send
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Transmits a session packet to the peer.
***********************************************************************/
void
sendSessionPacket(PPPoEConnection *conn, PPPoEPacket *packet, int len)
{
    UINT16_t credits_consumed;
    packet->length = htons(len);

    if (conn->local_credits < compute_local_credits(conn, packet)) {
        
        /* 
         * Not enough credits to send packet.  A more complete implementation
         * may decide to queue this packet instead of dropping it.  We are going
         * to drop it.
         */
     
        return;
    }

    if (conn->send_inband_grant) {
        /* send an inband grant inside this packet */
        credits_consumed = sendInbandGrant(conn, packet, conn->grant_amount);
    } else {
        /* decrement local credits to send packet to peer */
        credits_consumed = compute_local_credits(conn, packet);
    }

    conn->local_credits -= credits_consumed;

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): decremented %u local credits.  local_credits 0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), credits_consumed, conn->local_credits);

    /* if an inband grant was added, the length has changed */
    len = ntohs(packet->length);
    
    if (sendPacket(conn, conn->sessionSocket, packet, len + HDR_SIZE) < 0) {
        if (errno == ENOBUFS) {
            /* No buffer space is a transient error */
            return;
        }
        exit(EXIT_FAILURE);
    }
}

#ifdef USE_BPF
/**********************************************************************
*%FUNCTION: sessionDiscoveryPacket
*%ARGUMENTS:
* packet -- the discovery packet that was received
*%RETURNS:
* Nothing
*%DESCRIPTION:
* We got a discovery packet during the session stage.  This most likely
* means a PADT.
*
* The BSD version uses a single socket for both discovery and session
* packets.  When a packet comes in over the wire once we are in
* session mode, either syncReadFromEth() or asyncReadFromEth() will
* have already read the packet and determined it to be a discovery
* packet before passing it here.
***********************************************************************/
static void
sessionDiscoveryPacket(PPPoEPacket *packet)
{
    /* Sanity check */
    if (packet->code != CODE_PADT) {
        return;
    }

    /* It's a PADT, all right.  Is it for us? */
    if (packet->session != Connection->session) {
        /* Nope, ignore it */
        return;
    }
    if (memcmp(packet->ethHdr.h_dest, Connection->myEth, ETH_ALEN)) {
        return;
    }

    if (memcmp(packet->ethHdr.h_source, Connection->peerEth, ETH_ALEN)) {
        return;
    }

    PPPOE_DEBUG_EVENT(
           "pppoe(%s,%u): Session %d terminated -- received PADT from peer\n",
           conn->peer_ip, ntohs(conn->session),
           (int) ntohs(packet->session));
    parsePacket(packet, parseLogErrs, NULL);
    sendPADT(Connection, "Received PADT from peer");
    exit(EXIT_SUCCESS);
}
#else
/**********************************************************************
*%FUNCTION: sessionDiscoveryPacket
*%ARGUMENTS:
* conn -- PPPoE connection
*%RETURNS:
* Nothing
*%DESCRIPTION:
* We got a discovery packet during the session stage.  This most likely
* means a PADT, PADC, PADG, or PADQ packet.
***********************************************************************/
static void
sessionDiscoveryPacket(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    int len;

    if (receivePacket(conn->discoverySocket, &packet, &len) < 0) {
        return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus PPPoE length field (%u)\n",
                          conn->peer_ip, ntohs(conn->session),
                          (unsigned int) ntohs(packet.length));
        return;
    }

    /* check for our session */
    if (packet.session != conn->session) {
        /* Nope, ignore it */
        return;
    }

    switch (packet.code) {
    case (CODE_PADT):
        if (memcmp(packet.ethHdr.h_dest, conn->myEth, ETH_ALEN)) {
            return;
        }
        
        if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) {
            return;
        }
        PPPOE_DEBUG_EVENT("pppoe(%s,%u): Session %d terminated -- received PADT from peer\n",
                          conn->peer_ip, ntohs(conn->session), (int) ntohs(packet.session));
        parsePacket(&packet, parseLogErrs, NULL);
        sendPADT(conn, "Received PADT from peer");
        exit(EXIT_SUCCESS);
    case (CODE_PADG):
        recvPADG(conn, &packet);
        break;        
    case (CODE_PADC):
        recvPADC(conn, &packet);
        break;
    case (CODE_PADQ):
        recvPADQ(conn, &packet);
        break;
    default:
        return;
    }
}
#endif /* USE_BPF */

/**********************************************************************
*%FUNCTION: session
*%ARGUMENTS:
* conn -- PPPoE connection info
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Handles the "session" phase of PPPoE
***********************************************************************/
void
session(PPPoEConnection *conn)
{
    fd_set readable;
    PPPoEPacket packet;
    struct timeval tv;
    struct timeval *tvp = NULL;
    int maxFD = 0;
    int r,z;

    /* Open a session socket */
    conn->sessionSocket = openInterface(conn->ifName, Eth_PPPOE_Session, conn->myEth);

    /* Drop privileges */
    dropPrivs();

    /* Prepare for select() */
    if (conn->sessionSocket > maxFD)   maxFD = conn->sessionSocket;
    if (conn->discoverySocket > maxFD) maxFD = conn->discoverySocket;
    maxFD++;

    /* Fill in the constant fields of the packet to save time */
    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);
    packet.ethHdr.h_proto = htons(Eth_PPPOE_Session);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_SESS;
    packet.session = conn->session;

    initPPP();

#ifdef USE_BPF
    /* check for buffered session data */
    while (BPF_BUFFER_HAS_DATA) {
        if (conn->synchronous) {
            syncReadFromEth(conn, conn->sessionSocket, optClampMSS);
        } else {
            asyncReadFromEth(conn, conn->sessionSocket, optClampMSS);
        }
    }
#endif

    for (;;) {
      if (optInactivityTimeout > 0) {
            tv.tv_sec = optInactivityTimeout;
            tv.tv_usec = 0;
            tvp = &tv;
        }
        FD_ZERO(&readable);
        FD_SET(conn->socket, &readable);

        if (conn->discoverySocket >= 0) {
            FD_SET(conn->discoverySocket, &readable);
        }
        FD_SET(conn->sessionSocket, &readable);
        while(1) {
            r = select(maxFD+1, &readable, NULL, NULL, tvp);
            if (r >= 0 || errno != EINTR) break;
        }
        if (r < 0) {
            fatalSys("select (session)");
        }
        if (r == 0) { /* Inactivity timeout */
            PPPOE_DEBUG_ERROR("pppoe(%s,%u): Inactivity timeout... something wicked"
                              " happened on session %d\n",
                              conn->peer_ip, ntohs(conn->session),
                              (int) ntohs(conn->session));
            sendPADT(conn, "RP-PPPoE: Inactivity timeout");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(conn->sessionSocket, &readable)) {
            do {
                asyncReadFromEth(conn, conn->sessionSocket, optClampMSS);
            } while (BPF_BUFFER_HAS_DATA);
        }
        
        if (FD_ISSET(conn->socket, &readable)) {
            z = recvUDPPacket(conn, &packet);
            if (z > 0)
                sendSessionPacket(conn, &packet, z);

        } 

#ifndef USE_BPF
        /* BSD uses a single socket, see *syncReadFromEth() */
        /* for calls to sessionDiscoveryPacket() */
        if (conn->discoverySocket >= 0) {
            if (FD_ISSET(conn->discoverySocket, &readable)) {
                sessionDiscoveryPacket(conn);
            } 
        }
#endif

    }
}


/***********************************************************************
*%FUNCTION: sigPADT
*%ARGUMENTS:
* src -- signal received
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If an established session exists send PADT to terminate from session
*  from our end
***********************************************************************/
static void
sigPADT(int src)
{
    PPPOE_DEBUG_EVENT("pppoe(): Received signal %d on session %d.\n",
                      (int)src, (int) ntohs(Connection->session));
    sendPADTf(Connection, "RP-PPPoE: Received signal %d", src);
    exit(EXIT_SUCCESS);
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- program name
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage information and exits.
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
#ifdef USE_BPF
    fprintf(stderr, "   -I if_name     -- Specify interface (REQUIRED)\n");
#else
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
            DEFAULT_IF);
#endif
    fprintf(stderr,
            "   -T timeout     -- Specify inactivity timeout in seconds.\n"
            "   -t timeout     -- Initial timeout for discovery packets in seconds\n"
            "   -V             -- Print version and exit.\n"
            "   -A             -- Print access concentrator names and exit.\n"
            "   -S name        -- Set desired service name.\n"
            "   -C name        -- Set desired access concentrator name.\n"
            "   -U             -- Use Host-Unique to allow multiple PPPoE sessions.\n"
            "   -s             -- Use synchronous PPP encapsulation.\n"
            "   -m MSS         -- Clamp incoming and outgoing MSS options.\n"
            "   -p pidfile     -- Write process-ID to pidfile.\n"
            "   -e sess:mac    -- Skip discovery phase; use existing session.\n"
            "   -n             -- Do not open discovery socket.\n"
            "   -k             -- Kill a session with PADT (requires -e)\n"
            "   -d             -- Perform discovery, print session info and exit.\n"
            "   -f disc:sess   -- Set Ethernet frame types (hex).\n"
            "   -g             -- Initial credit grant amount.\n"
            "   -x             -- credit scaling factor.\n"
            "                      NOTE: a scaling factor of 0 specifies rfc4938 compliance only\n"
            "   -y             -- IP address to send pppoe packets to\n"
            "   -r             -- starting port to listen to\n"
            "   -R             -- neighbor port\n"
            "   -c             -- parent process port\n"
            "   -z             -- RFC4938 debug level\n"
            "                      0: off 1(default): errors 2: events 3: packets\n"
            "   -h             -- Print usage information.\n\n"
            "PPPoE Version %s, Copyright (C) 2001-2006 Roaring Penguin Software Inc.\n"
            "\t                   Copyright (C) 2007-2008 by Cisco Systems, Inc.\n"
            "\t\n"
            "PPPoE comes with ABSOLUTELY NO WARRANTY.\n"
            "This is free software, and you are welcome to redistribute it under the terms\n"
            "of the GNU General Public License, version 2 or any later version.\n"
            "http://www.roaringpenguin.com\n"
            "This program was modified by Cisco Systems, Inc.\n"
            " to implement RFC4938 and draft-bberry-pppoe-scaled-credits-metrics-01", VERSION);

    exit(EXIT_SUCCESS);
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- count and values of command-line arguments
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Main program
***********************************************************************/
int
main(int argc, char *argv[])
{
    int opt;
    int n;
    unsigned int m[6];                /* MAC address in -e option */
    unsigned int s;                /* Temporary to hold session */
    FILE *pidfile;
    unsigned int discoveryType, sessionType;
    UINT16_t scalar = 0;
    UINT16_t my_port = 0;
    UINT16_t peer_port = 0;
    UINT16_t parent_port = 0;
    UINT16_t grant_amount = 0;
    int rfc4938_debug = 0;
    
    PPPoEConnection conn;

#ifdef HAVE_N_HDLC
    int disc = N_HDLC;
    long flags;
#endif

    if (getuid() != geteuid() ||
        getgid() != getegid()) {
        IsSetID = 1;
    }

    /* Initialize connection info */
    memset(&conn, 0, sizeof(conn));
    conn.discoverySocket = -1;
    conn.sessionSocket = -1;
    conn.discoveryTimeout = PADI_TIMEOUT;

    /* For signal handler */
    Connection = &conn;

    /* Initialize syslog */
    /* openlog("pppoe", LOG_PID, LOG_DAEMON); */

    char const *options;
#ifdef DEBUGGING_ENABLED
    options = "I:VAT:hS:C:Usm:np:e:kdf:F:t:y:x:z:r:R:c:g:";
#else
    options = "I:VAT:hS:C:Usm:np:e:kdf:F:t:y:x:z:r:R:c:g:";
#endif
    while((opt = getopt(argc, argv, options)) != -1) {
        switch(opt) {
        case 't':
            if (sscanf(optarg, "%d", &conn.discoveryTimeout) != 1) {
                fprintf(stderr, "Illegal argument to -t: Should be -t timeout\n");
                exit(EXIT_FAILURE);
            }
            if (conn.discoveryTimeout < 1) {
                conn.discoveryTimeout = 1;
            }
            break;
        case 'F':
            if (sscanf(optarg, "%d", &optFloodDiscovery) != 1) {
                fprintf(stderr, "Illegal argument to -F: Should be -F numFloods\n");
                exit(EXIT_FAILURE);
            }
            if (optFloodDiscovery < 1) optFloodDiscovery = 1;
            fprintf(stderr,
                    "WARNING: DISCOVERY FLOOD IS MEANT FOR STRESS-TESTING\n"
                    "A PPPOE SERVER WHICH YOU OWN.  DO NOT USE IT AGAINST\n"
                    "A REAL ISP.  YOU HAVE 5 SECONDS TO ABORT.\n");
            sleep(5);
            break;
        case 'f':
            if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
                fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
                exit(EXIT_FAILURE);
            }
            Eth_PPPOE_Discovery = (UINT16_t) discoveryType;
            Eth_PPPOE_Session   = (UINT16_t) sessionType;
            break;
        case 'd':
            optSkipSession = 1;
            break;

        case 'k':
            conn.killSession = 1;
            break;

        case 'n':
            /* Do not even open a discovery socket -- used when invoked
               by pppoe-server */
            conn.noDiscoverySocket = 1;
            break;

        case 'e':
            /* Existing session: "sess:xx:yy:zz:aa:bb:cc" where "sess" is
               session-ID, and xx:yy:zz:aa:bb:cc is MAC-address of peer */
            n = sscanf(optarg, "%u:%2x:%2x:%2x:%2x:%2x:%2x",
                       &s, &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
            if (n != 7) {
                fprintf(stderr, "Illegal argument to -e: Should be sess:xx:yy:zz:aa:bb:cc\n");
                exit(EXIT_FAILURE);
            }

            /* Copy MAC address of peer */
            for (n=0; n<6; n++) {
                conn.peerEth[n] = (unsigned char) m[n];
            }

            /* Convert session */
            conn.session = htons(s);

            /* Skip discovery phase! */
            conn.skipDiscovery = 1;
            break;

        case 'p':
            switchToRealID();
            pidfile = fopen(optarg, "w");
            if (pidfile) {
                fprintf(pidfile, "%lu\n", (unsigned long) getpid());
                fclose(pidfile);
            }
            switchToEffectiveID();
            break;
        case 'S':
            SET_STRING(conn.serviceName, optarg);
            break;
        case 'C':
            SET_STRING(conn.acName, optarg);
            break;
        case 's':
            conn.synchronous = 1;
            break;
        case 'U':
            conn.useHostUniq = 1;
            break;
        case 'T':
            optInactivityTimeout = (int) strtol(optarg, NULL, 10);
            if (optInactivityTimeout < 0) {
                optInactivityTimeout = 0;
            }
            break;
        case 'm':
            optClampMSS = (int) strtol(optarg, NULL, 10);
            if (optClampMSS < 536) {
                fprintf(stderr, "-m: %d is too low (min 536)\n", optClampMSS);
                exit(EXIT_FAILURE);
            }
            if (optClampMSS > 1452) {
                fprintf(stderr, "-m: %d is too high (max 1452)\n", optClampMSS);
                exit(EXIT_FAILURE);
            }
            break;
        case 'I':
            SET_STRING(conn.ifName, optarg);
            break;
        case 'V':
            printf("Roaring Penguin PPPoE Version %s\n", VERSION);
            exit(EXIT_SUCCESS);
        case 'A':
            conn.printACNames = 1;
            break;
        case 'y':
            SET_STRING(conn.peer_ip, optarg);
            break;
        case 'g':
            grant_amount = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'x':
            scalar = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'z':
            rfc4938_debug = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'r':
            my_port = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'R':
            peer_port = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'c':
            parent_port = (UINT16_t) strtol(optarg, NULL, 10);
            break;
        case 'h':
            usage(argv[0]);
            break;
        default:
            usage(argv[0]);
        }
    }

    /* peer device that implements rfc4938 client */
    if(!(conn.peer_ip)) {
        fprintf(stderr, "peer ip must be specified with -y\n");
        exit(EXIT_FAILURE);
    }
    
    /* Pick a default interface name */
    if (!conn.ifName) {
#ifdef USE_BPF
        fprintf(stderr, "No interface specified (-I option)\n");
        exit(EXIT_FAILURE);
#else
        SET_STRING(conn.ifName, DEFAULT_IF);
#endif
    }

    if (!conn.printACNames) {

#ifdef HAVE_N_HDLC
        if (conn.synchronous) {
            if (ioctl(0, TIOCSETD, &disc) < 0) {
                printErr("Unable to set line discipline to N_HDLC.  Make sure your kernel supports the N_HDLC line discipline, or do not use the SYNCHRONOUS option.  Quitting.");
                exit(EXIT_FAILURE);
            } else {
                PPPOE_DEBUG_EVENT("pppoe(%s,%u): Changed pty line discipline to"
                                  " N_HDLC for synchronous mode\n",
                                  conn.peer_ip, ntohs(conn.session));
            }
            /* There is a bug in Linux's select which returns a descriptor
             * as readable if N_HDLC line discipline is on, even if
             * it isn't really readable.  This return happens only when
             * select() times out.  To avoid blocking forever in read(),
             * make descriptor 0 non-blocking */
            flags = fcntl(0, F_GETFL);
            if (flags < 0) fatalSys("fcntl(F_GETFL)");
            if (fcntl(0, F_SETFL, (long) flags | O_NONBLOCK) < 0) {
                fatalSys("fcntl(F_SETFL)");
            }
        }
#endif

    }

    if (optFloodDiscovery) {
        for (n=0; n < optFloodDiscovery; n++) {
            if (conn.printACNames) {
                fprintf(stderr, "Sending discovery flood %d\n", n+1);
            }
            discovery(&conn);
            conn.discoveryState = STATE_SENT_PADI;
            close(conn.discoverySocket);
        }
        exit(EXIT_SUCCESS);
    }

    /* Initialize rfc4938 values */    
    init_flow_control(&conn, scalar, rfc4938_debug, my_port, peer_port, 
                      parent_port, grant_amount);

    discovery(&conn);
    if (optSkipSession) {
        printf("%u:%02x:%02x:%02x:%02x:%02x:%02x\n",
               ntohs(conn.session),
               conn.peerEth[0],
               conn.peerEth[1],
               conn.peerEth[2],
               conn.peerEth[3],
               conn.peerEth[4],
               conn.peerEth[5]);
        exit(EXIT_SUCCESS);
    }

    /* Set signal handlers */
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, sigPADT);
    signal(SIGHUP, sigPADT);
    session(&conn);
    return 0;
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: Session %d: %.256s",
            str, (int) ntohs(Connection->session), strerror(errno));
    printErr(buf);

    /* alert parent rfc4938 process we are terminating */

    sendPADTf(Connection, "RP-PPPoE: System call error: %s",
              strerror(errno));
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    PPPoEConnection *conn = get_pppoe_conn();
    
    if (conn == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): rp_fatal", conn->peer_ip, ntohs(conn->session));
    } else {  
        PPPOE_DEBUG_ERROR("pppoe(): rp_fatal ");
    }

    printErr(str);
    sendPADTf(Connection, "RP-PPPoE: Session %d: %.256s",
              (int) ntohs(Connection->session), str);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: asyncReadFromEth
*%ARGUMENTS:
* conn -- PPPoE connection info
* sock -- Ethernet socket
* clampMss -- if non-zero, do MSS-clamping
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to async PPP
* device.
***********************************************************************/
void
asyncReadFromEth(PPPoEConnection *conn, int sock, int clampMss)
{
    PPPoEPacket packet;
    int len;
    int plen;
    
#ifdef USE_BPF
    int type;
#endif

    if (receivePacket(sock, &packet, &len) < 0) {
        return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus PPPoE length field (%u)\n",
                          conn->peer_ip, ntohs(conn->session),
                          (unsigned int) ntohs(packet.length));
        return;
    }
#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(&packet);
    if (type == Eth_PPPOE_Discovery) {
        sessionDiscoveryPacket(&packet);
    } else if (type != Eth_PPPOE_Session) {
        return;
    }
#endif

    /* Sanity check */
    if (packet.code != CODE_SESS) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet code %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.code);
        return;
    }
    if (packet.ver != 1) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet version %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.ver);
        return;
    }
    if (packet.type != 1) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet type %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.type);
        return;
    }
    if (memcmp(packet.ethHdr.h_dest, conn->myEth, ETH_ALEN)) {
        return;
    }
    if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) {
        /* Not for us -- must be another session.  This is not an error,
           so don't log anything.  */
        return;
    }

    if (packet.session != conn->session) {
        /* Not for us -- must be another session.  This is not an error,
           so don't log anything.  */
        return;
    }

    plen = ntohs(packet.length);

    if (plen + HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus length field in session packet %d (%d)\n",
                          conn->peer_ip, ntohs(conn->session), (int) plen, (int) len);
        return;
    }
    
    /* check for an inband grant from the peer */

    /* grab the first two byts of the payload looking for TAG_RFC4938_CREDITS */
    if ( TAG_RFC4938_CREDITS ==
         ((((UINT16_t) packet.payload[0]) << 8) + (UINT16_t) packet.payload[1]))
    {
        /* receive the grant */
        recvInbandGrant(conn, &packet);
            
        /* 
         * Check to make sure peer hasn't violated their credit allowance.
         * This also protects against roll-under
         */
        if (conn->peer_credits < compute_peer_credits_with_inband(conn, &packet)) {
            /* drop the packet */
            UINT16_t credits_needed =  compute_peer_credits_with_inband(conn, &packet);

            PPPOE_DEBUG_ERROR("pppoe(%s,%u): Peer exceeded their credit allowance in an "
                              "inband grant packet, dropping packet\n"
                              "Peer_credits: (%u), "
                              "packet_len/credits needed (%u/%u)\n",
                              conn->peer_ip, ntohs(conn->session),
                              conn->peer_credits,plen,credits_needed);

            return;
        }
        
        /* decrement peer credits taking into account inband grant tag */
        conn->peer_credits -= compute_peer_credits_with_inband(conn, &packet);

    } else {
   
             
        /* 
         * Check to make sure peer hasn't violated their credit allowance.
         * This also protects against roll-under
         */
         if (conn->peer_credits < compute_peer_credits(conn, &packet)) {
            /* drop the packet */
            UINT16_t credits_needed =  compute_peer_credits_with_inband(conn, &packet);

            PPPOE_DEBUG_ERROR("pppoe(%s,%u): Peer exceeded their credit allowance in an "
                              "inband grant packet, dropping packet\n"
                              "Peer_credits: (%u), "
                              "packet_len/credits needed (%u/%u)\n",
                              conn->peer_ip, ntohs(conn->session),
                              conn->peer_credits,plen,credits_needed);
            return;
        }

        /* decrement peer_credits */
        conn->peer_credits -= compute_peer_credits(conn, &packet);
    }
   

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): decremented %u peer credits, peer_credits %u\n", 
                       conn->peer_ip, ntohs(conn->session),
                       compute_peer_credits(conn, &packet), 
                       conn->peer_credits);


    sendUDPPacket(conn, &packet);
}

/**********************************************************************
*%FUNCTION: syncReadFromEth
*%ARGUMENTS:
* conn -- PPPoE connection info
* sock -- Ethernet socket
* clampMss -- if true, clamp MSS.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Reads a packet from the Ethernet interface and sends it to sync PPP
* device.
***********************************************************************/
void
syncReadFromEth(PPPoEConnection *conn, int sock, int clampMss)
{
    PPPoEPacket packet;
    int len;
    int plen;
    struct iovec vec[2];
    unsigned char dummy[2];
#ifdef USE_BPF
    int type;
#endif

    if (receivePacket(sock, &packet, &len) < 0) {
        return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus PPPoE length field (%u)\n",
                          conn->peer_ip, ntohs(conn->session), 
                          (unsigned int) ntohs(packet.length));
        return;
    }

#ifdef USE_BPF
    /* Make sure this is a session packet before processing further */
    type = etherType(&packet);
    if (type == Eth_PPPOE_Discovery) {
        sessionDiscoveryPacket(&packet);
    } else if (type != Eth_PPPOE_Session) {
        return;
    }
#endif

    /* Sanity check */
    if (packet.code != CODE_SESS) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet code %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.code);
        return;
    }
    if (packet.ver != 1) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet version %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.ver);
        return;
    }
    if (packet.type != 1) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Unexpected packet type %d\n", 
                          conn->peer_ip, ntohs(conn->session),
                          (int) packet.type);
        return;
    }
    if (memcmp(packet.ethHdr.h_dest, conn->myEth, ETH_ALEN)) {
        /* Not for us -- must be another session.  This is not an error,
           so don't log anything.  */
        return;
    }
    if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) {
        /* Not for us -- must be another session.  This is not an error,
           so don't log anything.  */
        return;
    }
    if (packet.session != conn->session) {
        /* Not for us -- must be another session.  This is not an error,
           so don't log anything.  */
        return;
    }
    plen = ntohs(packet.length);
    if (plen + HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus length field in session packet %d (%d)\n",
                          conn->peer_ip, ntohs(conn->session),
                          (int) plen, (int) len);
        return;
    }

    /* Clamp MSS */
    if (clampMss) {
        clampMSS(&packet, "incoming", clampMss);
    }

    /* Ship it out */
    vec[0].iov_base = (void *) dummy;
    dummy[0] = FRAME_ADDR;
    dummy[1] = FRAME_CTRL;
    vec[0].iov_len = 2;
    vec[1].iov_base = (void *) packet.payload;
    vec[1].iov_len = plen;

    if (writev(1, vec, 2) < 0) {
        fatalSys("syncReadFromEth: write");
    }
}



/**********************************************************************
*%FUNCTION: get_pppoe_conn()
*%ARGUMENTS:
*
*%RETURNS:
* PPPoEConnection
*%DESCRIPTION:
* Returns the global PPPoEConnection
***********************************************************************/
PPPoEConnection*
get_pppoe_conn()
{
    return (Connection);
}
