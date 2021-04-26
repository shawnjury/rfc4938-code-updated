/***********************************************************************
*
* discovery.c
*
* Perform PPPoE discovery
*
* Copyright (C) 1999 by Roaring Penguin Software Inc.
* Copyright (C) 2007-2008 by Cisco Systems, Inc.
*
* LIC: GPL
*
* This file was modified on Feb 2008 by Cisco Systems, Inc.
***********************************************************************/

#include "pppoe.h"
#include "pppoe_rfc4938.h"

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

/* Supplied by pppd if we're a plugin */
extern int persist;

/**********************************************************************
*%FUNCTION: parseForHostUniq
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data.
* extra -- user-supplied pointer.  This is assumed to be a pointer to int.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If a HostUnique tag is found which matches our PID, sets *extra to 1.
***********************************************************************/
static void
parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data,
		 void *extra)
{
    int *val = (int *) extra;
    if (type == TAG_HOST_UNIQ && len == sizeof(pid_t)) {
	pid_t tmp;
	memcpy(&tmp, data, len);
	if (tmp == getpid()) {
	    *val = 1;
	}
    }
}

/**********************************************************************
*%FUNCTION: packetIsForMe
*%ARGUMENTS:
* conn -- PPPoE connection info
* packet -- a received PPPoE packet
*%RETURNS:
* 1 if packet is for this PPPoE daemon; 0 otherwise.
*%DESCRIPTION:
* If we are using the Host-Unique tag, verifies that packet contains
* our unique identifier.
***********************************************************************/
static int
packetIsForMe(PPPoEConnection *conn, PPPoEPacket *packet)
{
    int forMe = 0;

    /* If packet is not directed to our MAC address, forget it */
    if (memcmp(packet->ethHdr.h_dest, conn->myEth, ETH_ALEN)) return 0;

    /* If we're not using the Host-Unique tag, then accept the packet */
    if (!conn->useHostUniq) return 1;

    parsePacket(packet, parseForHostUniq, &forMe);
    return forMe;
}

/**********************************************************************
*%FUNCTION: parsePADOTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.  Should point to a PacketCriteria structure
*          which gets filled in according to selected AC name and service
*          name.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADO packet
***********************************************************************/
static void
parsePADOTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    struct PacketCriteria *pc = (struct PacketCriteria *) extra;
    PPPoEConnection *conn = pc->conn;
    int i;

    switch(type) {
    case TAG_AC_NAME:
	pc->seenACName = 1;
	if (conn->printACNames) {
	    printf("Access-Concentrator: %.*s\n", (int) len, data);
	}
	if (conn->acName && len == strlen(conn->acName) &&
	    !strncmp((char *) data, conn->acName, len)) {
	    pc->acNameOK = 1;
	}
	break;
    case TAG_SERVICE_NAME:
	pc->seenServiceName = 1;
	if (conn->printACNames && len > 0) {
	    printf("       Service-Name: %.*s\n", (int) len, data);
	}
	if (conn->serviceName && len == strlen(conn->serviceName) &&
	    !strncmp((char *) data, conn->serviceName, len)) {
	    pc->serviceNameOK = 1;
	}
	break;
    case TAG_AC_COOKIE:
	if (conn->printACNames) {
	    printf("Got a cookie:");
	    /* Print first 20 bytes of cookie */
	    for (i=0; i<len && i < 20; i++) {
		printf(" %02x", (unsigned) data[i]);
	    }
	    if (i < len) printf("...");
	    printf("\n");
	}
	conn->cookie.type = htons(type);
	conn->cookie.length = htons(len);
	memcpy(conn->cookie.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	if (conn->printACNames) {
	    printf("Got a Relay-ID:");
	    /* Print first 20 bytes of relay ID */
	    for (i=0; i<len && i < 20; i++) {
		printf(" %02x", (unsigned) data[i]);
	    }
	    if (i < len) printf("...");
	    printf("\n");
	}
	conn->relayId.type = htons(type);
	conn->relayId.length = htons(len);
	memcpy(conn->relayId.payload, data, len);
	break;
    case TAG_SERVICE_NAME_ERROR:
	if (conn->printACNames) {
	    printf("Got a Service-Name-Error tag: %.*s\n", (int) len, data);
	} else {
	    pktLogErrs("PADO", type, len, data, extra);
	    exit(1);
	}
	break;
    case TAG_AC_SYSTEM_ERROR:
	if (conn->printACNames) {
	    printf("Got a System-Error tag: %.*s\n", (int) len, data);
	} else {
	    pktLogErrs("PADO", type, len, data, extra);
	    exit(1);
	}
	break;
    case TAG_GENERIC_ERROR:
	if (conn->printACNames) {
	    printf("Got a Generic-Error tag: %.*s\n", (int) len, data);
	} else {
	    pktLogErrs("PADO", type, len, data, extra);
	    exit(1);
	}
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADSTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data (pointer to PPPoEConnection structure)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADS packet
***********************************************************************/
static void
parsePADSTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    PPPoEConnection *conn = (PPPoEConnection *) extra;
    UINT16_t fcn;
    UINT16_t bcn;
    UINT16_t scalar;

    switch(type) {
    case TAG_SERVICE_NAME:
	PPPOE_DEBUG_EVENT("pppoe(%s,%u): PADS Service-Name: '%.*s'\n", 
                          conn->peer_ip, ntohs(conn->session), (int) len, data);
	break;
    case TAG_GENERIC_ERROR:
    case TAG_AC_SYSTEM_ERROR:
    case TAG_SERVICE_NAME_ERROR:
	pktLogErrs("PADS", type, len, data, extra);
	conn->PADSHadError = 1;
	break;
    case TAG_RELAY_SESSION_ID:
	conn->relayId.type = htons(type);
	conn->relayId.length = htons(len);
	memcpy(conn->relayId.payload, data, len);
	break;
    case TAG_RFC4938_CREDITS:
	fcn = (((UINT16_t) data[0]) << 8) + (UINT16_t) data[1];
	bcn = (((UINT16_t) data[2]) << 8) + (UINT16_t) data[3];

        conn->local_credits = fcn;
        conn->peer_credits = bcn;

        PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received fcn:0x%04x bcn:0x%04x in PADS\n", 
                          conn->peer_ip, ntohs(conn->session), fcn, bcn);
        break;
    case TAG_RFC4938_SCALAR:
        if (conn->mode == RFC4938_SCALING) {
            scalar = (((UINT16_t) data[0]) << 8) + (UINT16_t) data[1];
            conn->peer_credits_scalar = scalar;
            conn->scalar_state = SCALAR_RECEIVED;
            
            PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received scalar:0x%04x in PADS\n", 
                              conn->peer_ip, ntohs(conn->session), scalar);
        } else {

            /* 
             * Something is wrong. The user has requested a rfc4938 session only, 
             * one without credit/metric scaling but the peer has sent a credit
             * scaling tag.  We're going to send a padt and let the user figure 
             * it out.
             */

            PPPOE_DEBUG_PACKET("pppoe(%s,%u): A scaling tag was detected in the PADS packet"
                              " but the session was RFC4938_ONLY\n",
                              conn->peer_ip, ntohs(conn->session));

            sendPADT(conn, "credit/scaling mismatch");              
        }

            break;  
    }
}

/***********************************************************************
*%FUNCTION: sendPADI
*%ARGUMENTS:
* conn -- PPPoEConnection structure
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADI packet
***********************************************************************/
static void
sendPADI(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    unsigned char *cursor = packet.payload;
    PPPoETag *svc = (PPPoETag *) (&packet.payload);
    UINT16_t namelen = 0;
    UINT16_t plen;
    int omit_service_name = 0;

    if (conn->serviceName) {
	namelen = (UINT16_t) strlen(conn->serviceName);
	if (!strcmp(conn->serviceName, "NO-SERVICE-NAME-NON-RFC-COMPLIANT")) {
	    omit_service_name = 1;
	}
    }

    /* Set destination to Ethernet broadcast address */
    memset(packet.ethHdr.h_dest, 0xFF, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADI;
    packet.session = 0;

    if (!omit_service_name) {
	plen = TAG_HDR_SIZE + namelen;
	CHECK_ROOM(cursor, packet.payload, plen);

	svc->type = TAG_SERVICE_NAME;
	svc->length = htons(namelen);

	if (conn->serviceName) {
	    memcpy(svc->payload, conn->serviceName, strlen(conn->serviceName));
	}
	cursor += namelen + TAG_HDR_SIZE;
    } else {
	plen = 0;
    }

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq) {
	PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	CHECK_ROOM(cursor, packet.payload, sizeof(pid) + TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	cursor += sizeof(pid) + TAG_HDR_SIZE;
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);

    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: waitForPADO
*%ARGUMENTS:
* conn -- PPPoEConnection structure
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADO packet and copies useful information
***********************************************************************/
static void
waitForPADO(PPPoEConnection *conn, int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    PPPoEPacket packet;
    int len;

    struct PacketCriteria pc;
    pc.conn          = conn;
    pc.acNameOK      = (conn->acName)      ? 0 : 1;
    pc.serviceNameOK = (conn->serviceName) ? 0 : 1;
    pc.seenACName    = 0;
    pc.seenServiceName = 0;

    do {
	if (BPF_BUFFER_IS_EMPTY) {
	    tv.tv_sec = timeout;
	    tv.tv_usec = 0;

	    FD_ZERO(&readable);
	    FD_SET(conn->discoverySocket, &readable);

	    while(1) {
		r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
		if (r >= 0 || errno != EINTR) break;
	    }
	    if (r < 0) {
		fatalSys("select (waitForPADO)");
	    }
	    if (r == 0) return;        /* Timed out */
	}

	/* Get the packet */
	receivePacket(conn->discoverySocket, &packet, &len);

	/* Check length */
	if (ntohs(packet.length) + HDR_SIZE > len) {
	    PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus PPPoE length field (%u)\n",
                              conn->peer_ip, ntohs(conn->session),
                              (unsigned int) ntohs(packet.length));
	    continue;
	}

#ifdef USE_BPF
	/* If it's not a Discovery packet, loop again */
	if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif

	/* If it's not for us, loop again */
	if (!packetIsForMe(conn, &packet)) continue;

	if (packet.code == CODE_PADO) {
	    if (NOT_UNICAST(packet.ethHdr.h_source)) {
		PPPOE_DEBUG_ERROR("pppoe(%s,%u): Ignoring PADO packet from "
                                  "non-unicast MAC address",
                                  conn->peer_ip, ntohs(conn->session));
		continue;
	    }
	    parsePacket(&packet, parsePADOTags, &pc);
	    if (!pc.seenACName) {
		PPPOE_DEBUG_ERROR("pppoe(%s,%u): Ignoring PADO packet with no "
                                  "AC-Name tag", conn->peer_ip, ntohs(conn->session));
		continue;
	    }
	    if (!pc.seenServiceName) {
		PPPOE_DEBUG_ERROR("pppoe(%s,%u): Ignoring PADO packet with "
                                  "no Service-Name tag",
                                  conn->peer_ip, ntohs(conn->session));
		continue;
	    }
	    conn->numPADOs++;
	    if (pc.acNameOK && pc.serviceNameOK) {
		memcpy(conn->peerEth, packet.ethHdr.h_source, ETH_ALEN);
		if (conn->printACNames) {
		    printf("AC-Ethernet-Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			   (unsigned) conn->peerEth[0],
			   (unsigned) conn->peerEth[1],
			   (unsigned) conn->peerEth[2],
			   (unsigned) conn->peerEth[3],
			   (unsigned) conn->peerEth[4],
			   (unsigned) conn->peerEth[5]);
		    printf("--------------------------------------------------\n");
		    continue;
		}
		conn->discoveryState = STATE_RECEIVED_PADO;
		break;
	    }
	}
    } while (conn->discoveryState != STATE_RECEIVED_PADO);
}

/***********************************************************************
*%FUNCTION: sendPADR
*%ARGUMENTS:
* conn -- PPPoE connection structur
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADR packet
***********************************************************************/
static void
sendPADR(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    PPPoETag *svc = (PPPoETag *) packet.payload;
    unsigned char *cursor = packet.payload;

    UINT16_t namelen = 0;
    UINT16_t plen;

    if (conn->serviceName) {
	namelen = (UINT16_t) strlen(conn->serviceName);
    }
    plen = TAG_HDR_SIZE + namelen;
    CHECK_ROOM(cursor, packet.payload, plen);

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADR;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    if (conn->serviceName) {
	memcpy(svc->payload, conn->serviceName, namelen);
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq) {
	PPPoETag hostUniq;
	pid_t pid = getpid();
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(sizeof(pid));
	memcpy(hostUniq.payload, &pid, sizeof(pid));
	CHECK_ROOM(cursor, packet.payload, sizeof(pid)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
	cursor += sizeof(pid) + TAG_HDR_SIZE;
	plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (conn->cookie.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(conn->cookie.length) + TAG_HDR_SIZE);
	memcpy(cursor, &conn->cookie, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
	cursor += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
	plen += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
    }

    if (conn->relayId.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(conn->relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &conn->relayId, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
    }

    /* add credit tag */
    PPPoETag creditTag;
    add_credit_tag(&creditTag, htons(conn->grant_amount), 0);
    
    CHECK_ROOM(cursor, packet.payload, TAG_CREDITS_LENGTH+TAG_HDR_SIZE);
    memcpy(cursor, &creditTag, TAG_CREDITS_LENGTH + TAG_HDR_SIZE);
    cursor += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;
    plen += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;
    
    /* add scalar tag if requested */
    if (conn->mode == RFC4938_SCALING) {
        PPPoETag scalarTag;
        
        add_scalar_tag(&scalarTag, htons(conn->local_credits_scalar));
        CHECK_ROOM(cursor, packet.payload, TAG_SCALAR_LENGTH+TAG_HDR_SIZE);
        memcpy(cursor, &scalarTag, TAG_SCALAR_LENGTH + TAG_HDR_SIZE);
        cursor += TAG_SCALAR_LENGTH + TAG_HDR_SIZE;
        plen += TAG_SCALAR_LENGTH + TAG_HDR_SIZE;

        PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent PADR with scalar:0x%04x\n", 
                          conn->peer_ip, ntohs(conn->session), 
                          conn->local_credits_scalar);
    }

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent PADR with fcn:0x%04x\n", 
                      conn->peer_ip, ntohs(conn->session), 
                      conn->grant_amount);

}

/**********************************************************************
*%FUNCTION: waitForPADS
*%ARGUMENTS:
* conn -- PPPoE connection info
* timeout -- how long to wait (in seconds)
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Waits for a PADS packet and copies useful information
***********************************************************************/
static void
waitForPADS(PPPoEConnection *conn, int timeout)
{
    fd_set readable;
    int r;
    struct timeval tv;
    PPPoEPacket packet;
    int len;

    do {
	if (BPF_BUFFER_IS_EMPTY) {
	    tv.tv_sec = timeout;
	    tv.tv_usec = 0;

	    FD_ZERO(&readable);
	    FD_SET(conn->discoverySocket, &readable);

	    while(1) {
		r = select(conn->discoverySocket+1, &readable, NULL, NULL, &tv);
		if (r >= 0 || errno != EINTR) break;
	    }
	    if (r < 0) {
		fatalSys("select (waitForPADS)");
	    }
	    if (r == 0) return;
	}

	/* Get the packet */
	receivePacket(conn->discoverySocket, &packet, &len);

	/* Check length */
	if (ntohs(packet.length) + HDR_SIZE > len) {
	    PPPOE_DEBUG_ERROR("pppoe(%s,%u): Bogus PPPoE length field (%u)\n",
                              conn->peer_ip, ntohs(conn->session),
                              (unsigned int) ntohs(packet.length));
	    continue;
	}

#ifdef USE_BPF
	/* If it's not a Discovery packet, loop again */
	if (etherType(&packet) != Eth_PPPOE_Discovery) continue;
#endif
	/* If it's not from the AC, it's not for me */
	if (memcmp(packet.ethHdr.h_source, conn->peerEth, ETH_ALEN)) continue;

	/* If it's not for us, loop again */
	if (!packetIsForMe(conn, &packet)) continue;

	/* Is it PADS?  */
	if (packet.code == CODE_PADS) {
	    /* Parse for goodies */
	    conn->PADSHadError = 0;
	    parsePacket(&packet, parsePADSTags, conn);
	    if (!conn->PADSHadError) {
		conn->discoveryState = STATE_SESSION;
		break;
	    }
            if (conn->scalar_state == SCALAR_NEEDED) {
                /* 
                 * Time to bail.  We sent a credit scalar, but we did not received 
                 * a scalar back, this is not compliant with the spec.
                 */
                rp_fatal("Did not receive credit scalar tag when one was sent.\n");
            }
	}
    } while (conn->discoveryState != STATE_SESSION);

    /* Don't bother with ntohs; we'll just end up converting it back... */
    conn->session = packet.session;

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): PPP session is %d (0x%x)\n", 
                      conn->peer_ip, ntohs(conn->session),
                      (int) ntohs(conn->session),
                      (unsigned int) ntohs(conn->session));

    /* RFC 2516 says session id MUST NOT be zero or 0xFFFF */
    if (ntohs(conn->session) == 0 || ntohs(conn->session) == 0xFFFF) {
	PPPOE_DEBUG_ERROR("Access concentrator used a session value of"
                          " %x -- the AC is violating RFC 2516\n", 
                          (unsigned int) ntohs(conn->session));
    }
}

/**********************************************************************
*%FUNCTION: discovery
*%ARGUMENTS:
* conn -- PPPoE connection info structure
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Performs the PPPoE discovery phase
***********************************************************************/
void
discovery(PPPoEConnection *conn)
{
    int padiAttempts = 0;
    int padrAttempts = 0;
    int timeout = conn->discoveryTimeout;

    /* Skip discovery and don't open discovery socket? */
    if (conn->skipDiscovery && conn->noDiscoverySocket) {
	conn->discoveryState = STATE_SESSION;
	return;
    }

    conn->discoverySocket =
	openInterface(conn->ifName, Eth_PPPOE_Discovery, conn->myEth);

    /* Skip discovery? */
    if (conn->skipDiscovery) {
	conn->discoveryState = STATE_SESSION;
	if (conn->killSession) {
	    sendPADT(conn, "RP-PPPoE: Session killed manually\n");
	    exit(0);
	}
	return;
    }

    do {
	padiAttempts++;
	if (padiAttempts > MAX_PADI_ATTEMPTS) {
	    if (persist) {
		padiAttempts = 0;
		timeout = conn->discoveryTimeout;
		PPPOE_DEBUG_ERROR("pppoe(%s,%u): Timeout waiting for PADO packets", 
                                  conn->peer_ip, ntohs(conn->session));
	    } else {
		rp_fatal("Timeout waiting for PADO packets");
	    }
	}
	sendPADI(conn);
	conn->discoveryState = STATE_SENT_PADI;
	waitForPADO(conn, timeout);

	/* If we're just probing for access concentrators, don't do
	   exponential backoff.  This reduces the time for an unsuccessful
	   probe to 15 seconds. */
	if (!conn->printACNames) {
	    timeout *= 2;
	}
	if (conn->printACNames && conn->numPADOs) {
	    break;
	}
    } while (conn->discoveryState == STATE_SENT_PADI);

    /* If we're only printing access concentrator names, we're done */
    if (conn->printACNames) {
	exit(0);
    }

    timeout = conn->discoveryTimeout;
    do {
	padrAttempts++;
	if (padrAttempts > MAX_PADI_ATTEMPTS) {
	    if (persist) {
		padrAttempts = 0;
		timeout = conn->discoveryTimeout;
		PPPOE_DEBUG_ERROR("pppoe(%s,%u): Timeout waiting for PADS packets",
                                  conn->peer_ip, ntohs(conn->session));
	    } else {
		rp_fatal("Timeout waiting for PADS packets");
	    }
	}
	sendPADR(conn);
	conn->discoveryState = STATE_SENT_PADR;
	waitForPADS(conn, timeout);
	timeout *= 2;
    } while (conn->discoveryState == STATE_SENT_PADR);

    /* We're done. */
    conn->discoveryState = STATE_SESSION;
    return;
}
