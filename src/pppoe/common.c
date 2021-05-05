/***********************************************************************
*
* common.c
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Common functions used by PPPoE client and server
*
* Copyright (C) 2000 by Roaring Penguin Software Inc.
* Copyright (C) 2007-2008 Cisco Systems, Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* LIC: GPL
*
* This file was modified on Feb 2008 by Cisco Systems, Inc.
***********************************************************************/

/* For vsnprintf prototype */
#define _ISOC99_SOURCE 1

/* For seteuid prototype */
//#define _BSD_SOURCE 1
#define _DEFAULT_SOURCE 1

#include "pppoe.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include "pppoe_rfc4938_nbr.h"
#include <pwd.h>

/* Are we running SUID or SGID? */
int IsSetID = 0;

static uid_t saved_uid = -2;
static uid_t saved_gid = -2;

/**********************************************************************
*%FUNCTION: parsePacket
*%ARGUMENTS:
* packet -- the PPPoE discovery packet to parse
* func -- function called for each tag in the packet
* extra -- an opaque data pointer supplied to parsing function
*%RETURNS:
* 0 if everything went well; -1 if there was an error
*%DESCRIPTION:
* Parses a PPPoE discovery packet, calling "func" for each tag in the packet.
* "func" is passed the additional argument "extra".
***********************************************************************/
int
parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra)
{
    UINT16_t len = ntohs(packet->length);
    unsigned char *curTag;
    UINT16_t tagType, tagLen;

    if (packet->ver != 1) {
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE version (%d)\n", 
                          (int) packet->ver);
        return -1;
    }
    if (packet->type != 1) {
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE type (%d)\n", 
                          (int) packet->type);
        return -1;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_DATA_LEN - 6) { /* 6-byte overhead for PPPoE header */
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE packet length (%u)\n", 
                          len);
        return -1;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while(curTag - packet->payload < len) {
        /* Alignment is not guaranteed, so do this by hand... */
        tagType = (((UINT16_t) curTag[0]) << 8) +
            (UINT16_t) curTag[1];
        tagLen = (((UINT16_t) curTag[2]) << 8) +
            (UINT16_t) curTag[3];
        if (tagType == TAG_END_OF_LIST) {
            return 0;
        }
        if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
            PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE tag length (%u)\n", 
                              tagLen);
            return -1;
        }
        func(tagType, tagLen, curTag+TAG_HDR_SIZE, extra);
        curTag = curTag + TAG_HDR_SIZE + tagLen;
    }
    return 0;
}

/**********************************************************************
*%FUNCTION: findTag
*%ARGUMENTS:
* packet -- the PPPoE discovery packet to parse
* type -- the type of the tag to look for
* tag -- will be filled in with tag contents
*%RETURNS:
* A pointer to the tag if one of the specified type is found; NULL
* otherwise.
*%DESCRIPTION:
* Looks for a specific tag type.
***********************************************************************/
unsigned char *
findTag(PPPoEPacket *packet, UINT16_t type, PPPoETag *tag)
{
    UINT16_t len = ntohs(packet->length);
    unsigned char *curTag;
    UINT16_t tagType, tagLen;

    if (packet->ver != 1) {
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE version (%d)", 
                          (int) packet->ver);
        return NULL;
    }
    if (packet->type != 1) {
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE type (%d)", 
                          (int) packet->type);
        return NULL;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_DATA_LEN - 6) { /* 6-byte overhead for PPPoE header */
        PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE packet length (%u)", 
                          len);
        return NULL;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while(curTag - packet->payload < len) {
        /* Alignment is not guaranteed, so do this by hand... */
        tagType = (((UINT16_t) curTag[0]) << 8) +
            (UINT16_t) curTag[1];
        tagLen = (((UINT16_t) curTag[2]) << 8) +
            (UINT16_t) curTag[3];
        if (tagType == TAG_END_OF_LIST) {
            return NULL;
        }
        if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
            PPPOE_DEBUG_ERROR("pppoe(): Invalid PPPoE tag length (%u)", 
                              tagLen);
            return NULL;
        }
        if (tagType == type) {
            memcpy(tag, curTag, tagLen + TAG_HDR_SIZE);
            return curTag;
        }
        curTag = curTag + TAG_HDR_SIZE + tagLen;
    }
    return NULL;
}

/**********************************************************************
*%FUNCTION: switchToRealID
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sets effective user-ID and group-ID to real ones.  Aborts on failure
***********************************************************************/
void
switchToRealID (void) {
    if (IsSetID) {
        if (saved_uid < 0) saved_uid = geteuid();
        if (saved_gid < 0) saved_gid = getegid();
        if (setegid(getgid()) < 0) {
            printErr("pppoe(): setgid failed");
            exit(EXIT_FAILURE);
        }
        if (seteuid(getuid()) < 0) {
            printErr("pppoe(): seteuid failed");
            exit(EXIT_FAILURE);
        }
    }
}

/**********************************************************************
*%FUNCTION: switchToEffectiveID
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sets effective user-ID and group-ID back to saved gid/uid
***********************************************************************/
void
switchToEffectiveID (void) {
    if (IsSetID) {
        if (setegid(saved_gid) < 0) {
            printErr("pppoe(): setgid failed");
            exit(EXIT_FAILURE);
        }
        if (seteuid(saved_uid) < 0) {
            printErr("pppoe(): seteuid failed");
            exit(EXIT_FAILURE);
        }
    }
}

/**********************************************************************
*%FUNCTION: dropPrivs
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If effective ID is root, try to become "nobody".  If that fails and
* we're SUID, switch to real user-ID
***********************************************************************/
void
dropPrivs(void)
{
    struct passwd *pw = NULL;
    int ok = 0;
    if (geteuid() == 0) {
        pw = getpwnam("nobody");
        if (pw) {
            if (setgid(pw->pw_gid) < 0) ok++;
            if (setuid(pw->pw_uid) < 0) ok++;
        }
    }
    if (ok < 2 && IsSetID) {
        // Checking status to clear compiler error.  Not doing anything per 
        // original code.
        if (setegid(getgid()) != 0) {};
        if (seteuid(getuid()) != 0) {};
    }
}

/**********************************************************************
*%FUNCTION: printErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog.
***********************************************************************/
void
printErr(char const *str)
{
    /* fprintf(stderr, "pppoe: %s\n", str); */
    PPPOE_DEBUG_ERROR("%s\n", str);
}


/**********************************************************************
*%FUNCTION: strDup
*%ARGUMENTS:
* str -- string to copy
*%RETURNS:
* A malloc'd copy of str.  Exits if malloc fails.
***********************************************************************/
char *
strDup(char const *str)
{
    char *copy = malloc(strlen(str)+1);
    if (!copy) {
        rp_fatal("strdup failed");
    }
    strcpy(copy, str);
    return copy;
}

/**********************************************************************
*%FUNCTION: computeTCPChecksum
*%ARGUMENTS:
* ipHdr -- pointer to IP header
* tcpHdr -- pointer to TCP header
*%RETURNS:
* The computed TCP checksum
***********************************************************************/
UINT16_t
computeTCPChecksum(unsigned char *ipHdr, unsigned char *tcpHdr)
{
    UINT32_t sum = 0;
    UINT16_t count = ipHdr[2] * 256 + ipHdr[3];
    UINT16_t tmp;

    unsigned char *addr = tcpHdr;
    unsigned char pseudoHeader[12];

    /* Count number of bytes in TCP header and data */
    count -= (ipHdr[0] & 0x0F) * 4;

    memcpy(pseudoHeader, ipHdr+12, 8);
    pseudoHeader[8] = 0;
    pseudoHeader[9] = ipHdr[9];
    pseudoHeader[10] = (count >> 8) & 0xFF;
    pseudoHeader[11] = (count & 0xFF);

    /* Checksum the pseudo-header */
    sum += * (UINT16_t *) pseudoHeader;
    sum += * ((UINT16_t *) (pseudoHeader+2));
    sum += * ((UINT16_t *) (pseudoHeader+4));
    sum += * ((UINT16_t *) (pseudoHeader+6));
    sum += * ((UINT16_t *) (pseudoHeader+8));
    sum += * ((UINT16_t *) (pseudoHeader+10));

    /* Checksum the TCP header and data */
    while (count > 1) {
        memcpy(&tmp, addr, sizeof(tmp));
        sum += (UINT32_t) tmp;
        addr += sizeof(tmp);
        count -= sizeof(tmp);
    }
    if (count > 0) {
        sum += (unsigned char) *addr;
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (UINT16_t) ((~sum) & 0xFFFF);
}

/**********************************************************************
*%FUNCTION: clampMSS
*%ARGUMENTS:
* packet -- PPPoE session packet
* dir -- either "incoming" or "outgoing"
* clampMss -- clamp value
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Clamps MSS option if TCP SYN flag is set.
***********************************************************************/
void
clampMSS(PPPoEPacket *packet, char const *dir, int clampMss)
{
    unsigned char *tcpHdr;
    unsigned char *ipHdr;
    unsigned char *opt;
    unsigned char *endHdr;
    unsigned char *mssopt = NULL;
    UINT16_t csum;

    int len, minlen;

    /* check PPP protocol type */
    if (packet->payload[0] & 0x01) {
        /* 8 bit protocol type */

        /* Is it IPv4? */
        if (packet->payload[0] != 0x21) {
            /* Nope, ignore it */
            return;
        }

        ipHdr = packet->payload + 1;
        minlen = 41;
    } else {
        /* 16 bit protocol type */

        /* Is it IPv4? */
        if (packet->payload[0] != 0x00 ||
            packet->payload[1] != 0x21) {
            /* Nope, ignore it */
            return;
        }

        ipHdr = packet->payload + 2;
        minlen = 42;
    }

    /* Is it too short? */
    len = (int) ntohs(packet->length);
    if (len < minlen) {
        /* 20 byte IP header; 20 byte TCP header; at least 1 or 2 byte PPP protocol */
        return;
    }

    /* Verify once more that it's IPv4 */
    if ((ipHdr[0] & 0xF0) != 0x40) {
        return;
    }

    /* Is it a fragment that's not at the beginning of the packet? */
    if ((ipHdr[6] & 0x1F) || ipHdr[7]) {
        /* Yup, don't touch! */
        return;
    }
    /* Is it TCP? */
    if (ipHdr[9] != 0x06) {
        return;
    }

    /* Get start of TCP header */
    tcpHdr = ipHdr + (ipHdr[0] & 0x0F) * 4;

    /* Is SYN set? */
    if (!(tcpHdr[13] & 0x02)) {
        return;
    }

    /* Compute and verify TCP checksum -- do not touch a packet with a bad
       checksum */
    csum = computeTCPChecksum(ipHdr, tcpHdr);
    if (csum) {
        PPPOE_DEBUG_ERROR("Bad TCP checksum %x\n", (unsigned int) csum);

        /* Upper layers will drop it */
        return;
    }

    /* Look for existing MSS option */
    endHdr = tcpHdr + ((tcpHdr[12] & 0xF0) >> 2);
    opt = tcpHdr + 20;
    while (opt < endHdr) {
        if (!*opt) break;        /* End of options */
        switch(*opt) {
        case 1:
            opt++;
            break;

        case 2:
            if (opt[1] != 4) {
                /* Something fishy about MSS option length. */
                PPPOE_DEBUG_ERROR("Bogus length for MSS option (%u) from %u.%u.%u.%u\n",
                       (unsigned int) opt[1],
                       (unsigned int) ipHdr[12],
                       (unsigned int) ipHdr[13],
                       (unsigned int) ipHdr[14],
                       (unsigned int) ipHdr[15]);
                return;
            }
            mssopt = opt;
            break;
        default:
            if (opt[1] < 2) {
                /* Someone's trying to attack us? */
                PPPOE_DEBUG_ERROR(
                    "Bogus TCP option length (%u) from %u.%u.%u.%u\n",
                    (unsigned int) opt[1],
                    (unsigned int) ipHdr[12],
                    (unsigned int) ipHdr[13],
                    (unsigned int) ipHdr[14],
                    (unsigned int) ipHdr[15]);
                return;
            }
            opt += (opt[1]);
            break;
        }
        /* Found existing MSS option? */
        if (mssopt) break;
    }

    /* If MSS exists and it's low enough, do nothing */
    if (mssopt) {
        unsigned mss = mssopt[2] * 256 + mssopt[3];
        if (mss <= clampMss) {
            return;
        }

        mssopt[2] = (((unsigned) clampMss) >> 8) & 0xFF;
        mssopt[3] = ((unsigned) clampMss) & 0xFF;
    } else {
        /* No MSS option.  Don't add one; we'll have to use 536. */
        return;
    }

    /* Recompute TCP checksum */
    tcpHdr[16] = 0;
    tcpHdr[17] = 0;
    csum = computeTCPChecksum(ipHdr, tcpHdr);
    (* (UINT16_t *) (tcpHdr+16)) = csum;
}

/***********************************************************************
*%FUNCTION: sendPADT
*%ARGUMENTS:
* conn -- PPPoE connection
* msg -- if non-NULL, extra error message to include in PADT packet.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADT packet
***********************************************************************/
void
sendPADT(PPPoEConnection *conn, char const *msg)
{
    PPPoEPacket packet;
    unsigned char *cursor = packet.payload;

    UINT16_t plen = 0;

    PPPOE_DEBUG_EVENT("pppoe(%s): sending padt for session (%d)\n",
                      conn->peer_ip, ntohs(conn->session));
    PPPOE_DEBUG_EVENT("pppoe(%s,%u): At termination peer_credits %u\n",
                       conn->peer_ip, ntohs(conn->session),
                       conn->peer_credits);

    /* Inform rfc4938 process that session is closing */
    send_session_stop(conn, conn->peer_ip);

    /* close UDP socket to neighbor if open */
    if (conn->socket) {
        close(conn->socket);
    }

    /* Do nothing if no session established yet */
    if (!conn->session) return;

    /* Do nothing if no discovery socket */
    if (conn->discoverySocket < 0) return;

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADT;
    packet.session = conn->session;

    /* Reset Session to zero so there is no possibility of
       recursive calls to this function by any signal handler */
    conn->session = 0;

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq) {
        PPPoETag hostUniq;
        pid_t pid = getpid();
        hostUniq.type = htons(TAG_HOST_UNIQ);
        hostUniq.length = htons(sizeof(pid));
        memcpy(hostUniq.payload, &pid, sizeof(pid));
        memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
        cursor += sizeof(pid) + TAG_HDR_SIZE;
        plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    /* Copy error message */
    if (msg) {
        PPPoETag err;
        size_t elen = strlen(msg);
        err.type = htons(TAG_GENERIC_ERROR);
        err.length = htons(elen);
        strcpy((char *) err.payload, msg);
        memcpy(cursor, &err, elen + TAG_HDR_SIZE);
        cursor += elen + TAG_HDR_SIZE;
        plen += elen + TAG_HDR_SIZE;
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

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
    PPPOE_DEBUG_EVENT("pppoe(%s,%u,%u): Sent PADT\n",
                      conn->peer_ip, 
                      ntohs(conn->session),
                      getpid());

    exit(EXIT_SUCCESS);
}

/***********************************************************************
*%FUNCTION: sendPADTf
*%ARGUMENTS:
* conn -- PPPoE connection
* msg -- printf-style format string
* args -- arguments for msg
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADT packet with a formatted message
***********************************************************************/
void
sendPADTf(PPPoEConnection *conn, char const *fmt, ...)
{
    char msg[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    msg[511] = 0;

    sendPADT(conn, msg);
}

/**********************************************************************
*%FUNCTION: pktLogErrs
*%ARGUMENTS:
* pkt -- packet type (a string)
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Logs error tags
***********************************************************************/
void
pktLogErrs(char const *pkt,
           UINT16_t type, UINT16_t len, unsigned char *data,
           void *extra)
{
    char const *str;
    char const *fmt = "pppoe(): %s: %s: %.*s";
    switch(type) {
    case TAG_SERVICE_NAME_ERROR:
        str = "Service-Name-Error";
        break;
    case TAG_AC_SYSTEM_ERROR:
        str = "System-Error";
        break;
    default:
        str = "Generic-Error";
    }

    PPPOE_DEBUG_ERROR(fmt, pkt, str, (int) len, data);
    fprintf(stderr, fmt, pkt, str, (int) len, data);
    fprintf(stderr, "\n");
}

/**********************************************************************
*%FUNCTION: parseLogErrs
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks error tags out of a packet and logs them.
***********************************************************************/
void
parseLogErrs(UINT16_t type, UINT16_t len, unsigned char *data,
             void *extra)
{
    pktLogErrs("pppoe(): PADT", type, len, data, extra);
}
