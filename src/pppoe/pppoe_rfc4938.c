/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: pppoe_rfc4938.c
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C) 2007-2008 Cisco Systems, Inc.     
 *
 * ===========================
 *
 * This file implements functions related to rfc4938, "PPP Over Ethernet (PPPoE) 
 * Extensions for Credit Flow and Link Metrics" and "PPP Over Ethernet (PPPoE) 
 * Extensions for Scaled Credits and Link Metrics"
 *
 * ===========================
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *----------------------------------------------------------------------------*/

#include "pppoe_rfc4938.h"
#include "pppoe_rfc4938_nbr.h"

#include <signal.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef USE_LINUX_PACKET
#include <sys/ioctl.h>
#endif

static UINT16_t seq_num = 0;
static struct itimerval padg_timer;
static PPPoEConnection *saved_conn;

/***********************************************************************
 *%FUNCTION: init_flow_control
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * scalar -- local credit scalar to advertise in PADR
 * rfc4938_debug -- debug level
 * my_port -- port to listen on
 * peer_port -- port to send packets to
 * grant_amount -- grant_amount to set for PADR grant and 1 second grant
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Inits flow control related parameters
 ***********************************************************************/
void
init_flow_control (PPPoEConnection *conn, UINT16_t scalar, int rfc4938_debug,
                   UINT16_t my_port, UINT16_t peer_port, UINT16_t parent_port, 
                   UINT16_t grant_amount)
{
    int ret, z, flag;
    socklen_t len_inet;

    if (scalar == 0) {
        conn->local_credits_scalar = RFC4938_CREDIT_SCALAR;
        conn->peer_credits_scalar = RFC4938_CREDIT_SCALAR;
        conn->mode = RFC4938_ONLY;
        conn->scalar_state = SCALAR_NOT_NEEDED;
    } else {
        conn->local_credits_scalar = scalar;
        conn->mode = RFC4938_SCALING;
        conn->scalar_state = SCALAR_NEEDED;

        /* set the default credit to 64 for peer until we learn it */
        conn->peer_credits_scalar = RFC4938_CREDIT_SCALAR;
    }
    
    conn->local_credits = 0;
    conn->peer_credits = 0;

    conn->grant_state = PADC_RECEIVED;
    conn->padg_retries = 0;
    conn->send_inband_grant = 0;

    /* setup credit grant amount */
    if (grant_amount == 0) {
        conn->grant_amount = INITIAL_GRANT;
    } else {
        conn->grant_amount = grant_amount;
    }
    
    /* setup padg grant timer */
    signal (SIGALRM, grant_event);
 
    padg_timer.it_value.tv_sec = PADG_TIMER_VAL;
    padg_timer.it_value.tv_usec = 0;
    padg_timer.it_interval.tv_sec = PADG_TIMER_VAL;;
    padg_timer.it_interval.tv_usec = 0;

    ret = setitimer (ITIMER_REAL, &padg_timer, NULL);

    if (ret) {
        fatalSys("init_flow_control: setitimer");
        return;
    }
    
    saved_conn = conn;
    
    /* setup neighbor ports */
    conn->peer_port = peer_port;
    conn->my_port = my_port;
    conn->parent_port = parent_port;

    /* setup debugs */
    if (rfc4938_debug >= 1) {
        pppoe_set_debug_mask(PPPOE_G_ERROR_DEBUG);
    }
    if (rfc4938_debug >= 2) {
        pppoe_set_debug_mask(PPPOE_G_EVENT_DEBUG);
    }
    if (rfc4938_debug >= 3) {
        pppoe_set_debug_mask(PPPOE_G_PACKET_DEBUG);
    }

    /*
     * Create a UDP socket
     */
    conn->socket = socket(AF_INET,SOCK_DGRAM,0);
    if ( conn->socket == -1 ) {
        fatalSys("init_flow_control: unable to create socket\n");
        return;
    }

    /* setup socket to receive packets on */
    memset(&conn->my_sock,0,sizeof conn->my_sock);
    conn->my_sock.sin_family = AF_INET;
    conn->my_sock.sin_port = htons(conn->my_port);
    conn->my_sock.sin_addr.s_addr = INADDR_ANY;
    
    len_inet = sizeof (conn->my_sock);

    z = bind(conn->socket,
             (struct sockaddr *)&conn->my_sock,
             len_inet);

    if ( z == -1 ) {
        while ( z == -1 && errno == EADDRINUSE ){
            /* increment port and try again if it was already in use */
            conn->my_port = conn->my_port + 1;
            conn->my_sock.sin_port = htons(conn->my_port);
            
            len_inet = sizeof (conn->my_sock);
            
            z = bind(conn->socket,
                     (struct sockaddr *)&conn->my_sock,
                     len_inet);       
        }
    }

    if ( z == -1 ) {
        fatalSys("Unable to bind to socket");
        return;
    }

    /* set socket to nonblocking for the select */
    ioctl(conn->socket, FIONBIO, &flag);
  
    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Succesfully bound to port %d\n", 
                      conn->peer_ip, ntohs(conn->session), conn->my_port);
    
    /* Alert parent rfc4938 process which port has been bound to */
    send_session_start_ready(conn, LOCALHOST, conn->parent_port);
        
    /* 
     * If this is the first neighbor to come up, we need to contact their 
     * rfc4938 daemon with a CTL_SESSION_START msg
     */
    if (conn->peer_port == 0){
        
        send_session_start(conn, conn->peer_ip);

    } else {
        /* 
         * We are not the first to come up, send a CTL_SESSION_START_READY 
         * msg to the other pppoe neighbor
         */
        send_session_start_ready(conn, conn->peer_ip, conn->peer_port);
    }
}

/***********************************************************************
 *%FUNCTION: grantEvent
 *%ARGUMENTS:
 * signo -- signal number of event
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Sends a PADG packet based on timer event
 ***********************************************************************/
void
grant_event (int signo)
{
    PPPoEConnection *conn = saved_conn;
    UINT16_t credits_to_grant;
    
    /* check to see if we are waiting on a PADC */
    if (conn->grant_state == PADG_SENT) {
        /* the padc response was missed */

        PPPOE_DEBUG_EVENT("pppoe(%s,%u): PADC missed\n", conn->peer_ip, ntohs(conn->session));

        /* have we exceeded the number of retries? */
        if (conn->padg_retries > MAX_PADG_RETRIES) {
            /* terminate session */
            PPPOE_DEBUG_ERROR("pppoe(%s,%u): Too many PADCs missed.  Terminating conn\n",
                              conn->peer_ip, ntohs(conn->session));
            sendPADT(conn, "Number of padg retries exceeded");
        } else {
            /* no, try again */
            sendPADG(conn, 0);
        }
        
    } else {
        
        /* 
         * We are sending a normal grant.  In this simplified implementation
         * we send credits grants on a one second interval.  By modifying the
         * grant_amount, we can throttle amount of traffic the peer can send.
         * For example, the default grant_amount is 1953 credits with a credit 
         * scalar of 64 bytes.  If we are granting 1953 credits a second, that 
         * represents (1953 credits * 64 bytes * 8bits/byte) ~ 1Mbps of PPPoE 
         * payload traffic.  We are going to check to make sure we don't grant 
         * the peer more than this amount, otherwise they could exceed this rate.
         */
        
        if (conn->peer_credits > conn->grant_amount) {
            credits_to_grant = 0;
        } else {
            credits_to_grant = conn->grant_amount - conn->peer_credits;
        }

        PPPOE_DEBUG_PACKET("pppoe(%s,%u): granting %u credits in PADG, "
                           "conn->peer_credits %u conn->grant_amount %u\n", 
                           conn->peer_ip, ntohs(conn->session), conn->peer_credits, 
                           conn->grant_amount, credits_to_grant);

        sendPADG(conn, credits_to_grant);
    }
    
    signal (SIGALRM, grant_event);
}


/***********************************************************************
 *%FUNCTION: sendPADG
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * credits -- credits to grant in host order
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Sends a PADG packet
 ***********************************************************************/
void
sendPADG (PPPoEConnection *conn, UINT16_t credits)
{
    PPPoEPacket packet;
    PPPoETag creditTag;
    PPPoETag sequenceTag;
    unsigned char *cursor = packet.payload;

    UINT16_t plen = 0;
    UINT16_t fcn;
    UINT16_t bcn = htons(conn->local_credits);

    /* Do nothing if no session established yet */
    if (!conn->session) return;

    /* Do nothing if no discovery socket */
    if (conn->discoverySocket < 0) return;

    if (conn->grant_state == PADG_SENT && credits != 0) {
        /* 
         * Our previous PADG has not been acknowledged.  No *new* credit grants can
         * be given until that grant is acknowledged.  We are going to send a grant with
         * 0 credits and the previous sequence number per the rfc to resolve this.
         */

        PPPOE_DEBUG_ERROR("pppoe(%s,%u): grant_state is PADG_SENT, bailing. "
                          " Waiting on seq_num %u\n", conn->peer_ip, ntohs(conn->session), seq_num);

        return;
    }

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADG;
    packet.session = conn->session;

    /* Add Sequence Number */
    if (conn->grant_state == PADC_RECEIVED) {
        seq_num++;
    } else {
        /*
         * since a grant has not been acknowldeged, we are going to send
         * a grant with zero credits and the same sequence number 
         * per the rfc to try to get it acknowledged 
         */
         PPPOE_DEBUG_EVENT("pppoe(%s,%u): resending PADG with seq_num 0x%04x\n", 
                              conn->peer_ip, ntohs(conn->session), seq_num);
    }
    add_sequence_tag(&sequenceTag, htons(seq_num));
    plen += sizeof(seq_num) + TAG_HDR_SIZE;
    memcpy(cursor, &sequenceTag, sizeof(seq_num) + TAG_HDR_SIZE);
    cursor += sizeof(seq_num) + TAG_HDR_SIZE;

    /* don't send more than max credits */
    if (MAX_CREDITS - conn->peer_credits < credits) {
        credits = MAX_CREDITS - conn->peer_credits;
    }

    fcn = htons(credits);

    /* Add credit Tag */
    add_credit_tag(&creditTag, fcn, bcn);
    plen += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;
    memcpy(cursor, &creditTag, TAG_CREDITS_LENGTH + TAG_HDR_SIZE);
    cursor += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;

    conn->peer_credits += credits;
    conn->padg_retries++;

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
    
    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent PADG packet with fcn:0x%04x bcn:0x%04x seq:0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), credits, conn->local_credits, seq_num);

    /* set PADG_SENT state */
    conn->grant_state = PADG_SENT;
}


/***********************************************************************
 *%FUNCTION: sendPADC
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * seq -- sequence number in host order
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Sends a PADC packet
 ***********************************************************************/
void
sendPADC (PPPoEConnection *conn, UINT16_t seq)
{
    PPPoEPacket packet;
    PPPoETag creditTag;
    PPPoETag sequenceTag;
    unsigned char *cursor = packet.payload;

    UINT16_t plen = 0;
    UINT16_t fcn = htons(conn->peer_credits);
    UINT16_t bcn = htons(conn->local_credits);

    /* Do nothing if no session established yet */
    if (!conn->session) return;

    /* Do nothing if no discovery socket */
    if (conn->discoverySocket < 0) return;

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADC;
    packet.session = conn->session;

    /* Add Sequence Number */
    add_sequence_tag(&sequenceTag, htons(seq));
    memcpy(cursor, &sequenceTag, sizeof(seq) + TAG_HDR_SIZE);
    cursor += sizeof(seq) + TAG_HDR_SIZE;
    plen += sizeof(seq) + TAG_HDR_SIZE;
    
    /* Add credit Tag */
    add_credit_tag(&creditTag, fcn, bcn);
    memcpy(cursor, &creditTag, TAG_CREDITS_LENGTH + TAG_HDR_SIZE);
    cursor += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;
    plen += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));

    PPPOE_DEBUG_PACKET("pppoe(%s,%u); Sent PADC packet with fcn:0x%04x bcn:0x%04x seq:0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), 
                       conn->peer_credits, conn->local_credits, seq);
}


/***********************************************************************
 *%FUNCTION: recvPADG
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * packet -- PPPoE Packet
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Receives a PADG packet
 ***********************************************************************/
void
recvPADG (PPPoEConnection *conn, PPPoEPacket *packet)
{
    PPPoETag creditTag;
    PPPoETag sequenceTag;

    UINT16_t fcn;
    UINT16_t bcn;
    UINT16_t seq;

    /* find sequence tag */
    if (findTag(packet, TAG_RFC4938_SEQ_NUM, &sequenceTag) == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): No sequence tag in PADG packet\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }

    /* find credit tag */
    if (findTag(packet, TAG_RFC4938_CREDITS, &creditTag) == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): No credit tag in PADG packet\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }
    
    fcn = get_fcn_from_credit_tag(&creditTag);
    bcn = get_bcn_from_credit_tag(&creditTag);
    seq = get_seq_from_sequence_tag(&sequenceTag);
        
    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received PADG packet with "
                       "fcn:0x%04x bcn:0x%04x seq:0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), fcn, bcn, seq);

    /* add credits, but check to make sure you don't exceed max credits */
    if ((MAX_CREDITS - conn->local_credits) < fcn) {
        conn->local_credits = MAX_CREDITS;
    } else {
        conn->local_credits += fcn;
    }
    
    /* send PADC in response */
    sendPADC(conn, seq);    
}

/***********************************************************************
 *%FUNCTION: recvPADC
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * packet -- PPPoE Packet
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Receives a PADC packet
 ***********************************************************************/
void
recvPADC (PPPoEConnection *conn, PPPoEPacket *packet)
{
    PPPoETag creditTag;
    PPPoETag sequenceTag;

    UINT16_t fcn;
    UINT16_t bcn;
    UINT16_t seq;

    /* find sequence tag */
    if (findTag(packet, TAG_RFC4938_SEQ_NUM, &sequenceTag) == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): No sequence tag in PADC packet\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }

    /* findTag to pull out credits */
    if (findTag(packet, TAG_RFC4938_CREDITS, &creditTag) == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): No credit tag in PADC packet\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }
    
    fcn = get_fcn_from_credit_tag(&creditTag);
    bcn = get_bcn_from_credit_tag(&creditTag);
    seq = get_seq_from_sequence_tag(&sequenceTag);
    
    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received PADC packet with fcn:0x%04x"
                       " bcn:0x%04x seq:0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), fcn, bcn, seq);
        
    /* prevent mismatch.  Always trust your peers bcn */
    conn->peer_credits = bcn;
    
    /* make sure this is an acknowledgement of the last padg that you sent */
    if (seq == seq_num) {
        /* set PADC_RECEIVED state */
        conn->grant_state = PADC_RECEIVED;
        conn->padg_retries = 0;
    } else {
         PPPOE_DEBUG_EVENT("pppoe(%s,%u): Received PADC with incorrect"
                           " sequence number.  Expected 0x%04x Received"
                           " 0x%04x", conn->peer_ip, ntohs(conn->session),
                           seq_num, seq);
    }

}

/***********************************************************************
 *%FUNCTION: sendPADQ
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * mdr -- Maximum Data Rate
 * mdr_scalar -- Maximum Data Rate scalar (0-kbps, 1-Mbps, 2-Gbps, 3-Tbps)
 * cdr -- Current Data Rate
 * cdr_scalar -- Current Data Rate scalar (0-kbps, 1-Mbps, 2-Gbps, 3-Tbps)
 * latency
 * resources
 * rlq -- Relative Link Quality
 * receive_only -- true (1) or false (0) 
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Sends a PADQ packet
 ***********************************************************************/
void
sendPADQ (PPPoEConnection *conn, UINT16_t mdr, UINT8_t mdr_scalar, 
          UINT16_t cdr, UINT8_t cdr_scalar, UINT16_t latency, 
          UINT8_t resources, UINT8_t rlq, UINT8_t receive_only)
{
    PPPoEPacket packet;
    PPPoETag padqTag;
    
    UINT8_t *padq_cursor = padqTag.payload;
    UINT8_t *cursor = packet.payload;
 
    UINT16_t plen = 0;
    UINT16_t reserved = 0;
    UINT16_t temp = 0;

    /* Do nothing if no session established yet */
    if (!conn->session) return;

    /* Do nothing if no discovery socket */
    if (conn->discoverySocket < 0) return;

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADQ;
    packet.session = conn->session;

    padqTag.type = htons(TAG_RFC4938_METRICS);
    padqTag.length = htons(TAG_METRICS_LENGTH);

    if (receive_only > 1) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): receive_only value must be <= 1\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }

    if (conn->mode != RFC4938_ONLY) {
        if (mdr_scalar > 3 ) {
            PPPOE_DEBUG_ERROR("pppoe(%s,%u): mdr_scalar value must be <= 3\n",
                              conn->peer_ip, ntohs(conn->session));
            return;
        }
        if (cdr_scalar > 3 ) {
            PPPOE_DEBUG_ERROR("pppoe(%s,%u): cdr_scalar value must be <= 3\n",
                              conn->peer_ip, ntohs(conn->session));
            return;
        }

        /* bitshift mdr_scalar 3 bits to the left */
        mdr_scalar = mdr_scalar << 3;

        /* bitshift cdr_scalar 1 bit to the left */
        cdr_scalar = cdr_scalar << 1;

        reserved = mdr_scalar | cdr_scalar | receive_only;
    } else {
        reserved = receive_only;
    }
    
    /* copy reserved field into the padq */
    temp = htons(reserved);
    memcpy(padq_cursor, &temp, sizeof(reserved));
    padq_cursor += sizeof(reserved);

    /* copy rlq */
    memcpy(padq_cursor, &rlq, sizeof(rlq));
    padq_cursor += sizeof(rlq);

    /* copy resources */
    memcpy(padq_cursor, &resources, sizeof(resources));
    padq_cursor += sizeof(resources);
    
    /* copy latency */
    temp = htons(latency);
    memcpy(padq_cursor, &temp, sizeof(latency));
    padq_cursor += sizeof(latency);
    
    /* copy cdr */
    temp = htons(cdr);
    memcpy(padq_cursor, &temp, sizeof(cdr));
    padq_cursor += sizeof(cdr);

    /* copy mdr */
    temp = htons(mdr);
    memcpy(padq_cursor, &temp, sizeof(mdr));
    padq_cursor += sizeof(mdr);

    /* copy the tag into the packet */
    plen += TAG_METRICS_LENGTH + TAG_HDR_SIZE;
    memcpy(cursor, &padqTag, TAG_METRICS_LENGTH + TAG_HDR_SIZE);
    cursor += TAG_METRICS_LENGTH + TAG_HDR_SIZE;
    
    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent PADQ packet with mdr:%u cdr:%u latency:%u\n"
                       " resources 0x%02x rlq %u\n", 
                       conn->peer_ip, ntohs(conn->session), mdr, cdr, latency, resources, rlq);
}


/***********************************************************************
 *%FUNCTION: recvPADQ
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- PPPoE Packet
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Receives a PADQ packet
 ***********************************************************************/
void
recvPADQ (PPPoEConnection *conn, PPPoEPacket *packet)
{
    PPPoETag padqTag;

    /* find credit tag */
    if (findTag(packet, TAG_RFC4938_METRICS, &padqTag) == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): No credit tag in PADG packet\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }
    
    if (padqTag.length == 0 ) {
        PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received PADQ query packet\n",
                           conn->peer_ip, ntohs(conn->session));

        /* 
         * Send PADQ in response.  Normally you would want to send PADQ data 
         * that represents your current link, but since we are only providing
         * padq's with data from the user, we are going to send "dummy" values
         * here.
         */

        sendPADQ(conn, 1000, 0, 2000, 0, 1, 100, 90, 0);
    } else {

        /* ignore this PADQ */
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Received a PADQ packet from the server.\n",
                          conn->peer_ip, ntohs(conn->session));
    }
}

/***********************************************************************
 *%FUNCTION: sendInbandGrant
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- PPPoE Packet
 * credits -- credits to grant in host order
 * 
 *%RETURNS:
 * Amount of credits consumed by packet
 *%DESCRIPTION:
 * Receives an inband credit grant
 ***********************************************************************/
UINT16_t
sendInbandGrant (PPPoEConnection *conn, PPPoEPacket *packet, UINT16_t credits)
{
    /* 
     * NOTE: This function is not currently used, but was included for completeness.
     * credits are currently sent on a 1 second interval using the out-of-band
     * credit mechanism (PADG)
     */
    
    PPPoETag creditTag;
    UINT8_t payload_data[ETH_DATA_LEN];
    UINT16_t len = ntohs(packet->length);
    unsigned char *cursor = packet->payload;

    UINT16_t adjusted_length;
    UINT16_t credits_consumed;
    UINT16_t fcn;
    UINT16_t bcn = htons(conn->local_credits);

    /* 
     * check to make sure the mtu would not be exceeded if the credit tag
     * were to be added
     */
    if ( len + TAG_CREDITS_LENGTH +  TAG_HDR_SIZE + PPPOE_OVERHEAD > MAX_PPPOE_MTU) {
        /* don't add tag */

        /* compute credits normally for this packet */
        conn->local_credits -= compute_local_credits(conn, packet);
        return 0;
    }

    /* 
     * Credits are calculated based on ppp payload, therefore you must 
     * subtract the PPP header out from the PPPoE payload, but we don't
     * want to count the inband credit tag in this total
     */
    adjusted_length = (ntohs(packet->length) - PPP_OVERHEAD - 
                       TAG_CREDITS_LENGTH - TAG_HDR_SIZE);

    credits_consumed = adjusted_length / conn->local_credits_scalar;

    if (adjusted_length % conn->local_credits_scalar != 0) {
        credits_consumed++;
    }

    /* don't send more than max credits */
    if (MAX_CREDITS - conn->peer_credits < credits) {
        credits = MAX_CREDITS - conn->peer_credits;
    }

    fcn = htons(credits);

    /* copy the original payload to our tmp buffer */
    memcpy(&payload_data, packet->payload, len);
    
    /* insert credit tag into payload */
    add_credit_tag(&creditTag, fcn, bcn);
    memcpy(cursor, &creditTag, TAG_CREDITS_LENGTH + TAG_HDR_SIZE);
    cursor += TAG_CREDITS_LENGTH + TAG_HDR_SIZE;

    /* copy old packet over */
    memcpy(cursor, payload_data, len);

    /* update new packet length */
    packet->length = htons(len + TAG_CREDITS_LENGTH + TAG_HDR_SIZE);
    
    /* add credits granted to peer credits */
    conn->peer_credits += credits;

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent inband grant with fcn:0x%04x"
                       " bcn:0x%04x\n", conn->peer_ip, ntohs(conn->session),
                       credits, conn->local_credits);

    /* reset the inband_grant flag */
    conn->send_inband_grant = 0;
    return (credits_consumed);
}



/***********************************************************************
 *%FUNCTION: recvInbandGrant
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- PPPoE Packet
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Receives an inband credit grant
 ***********************************************************************/
void
recvInbandGrant (PPPoEConnection *conn, PPPoEPacket *packet)
{
    UINT8_t *curTag;
    PPPoETag creditTag;
    
    UINT16_t fcn;
    UINT16_t bcn;

    UINT16_t tagType, tagLen;
    UINT16_t len = ntohs(packet->length);

    /* Step through the tags */
    curTag = packet->payload;

    /* Alignment is not guaranteed, so do this by hand... */
    tagType = (((UINT16_t) curTag[0]) << 8) +
        (UINT16_t) curTag[1];
    tagLen = (((UINT16_t) curTag[2]) << 8) +
        (UINT16_t) curTag[3];
    if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Invalid PPPoE tag length in"
                          " inband grant (%u,%u)", conn->peer_ip, 
                          ntohs(conn->session), tagType, tagLen);
        return;
    }

    /* copy the tag into our local structure */
    memcpy(&creditTag, curTag, tagLen + TAG_HDR_SIZE);
    
    fcn = get_fcn_from_credit_tag(&creditTag);
    bcn = get_bcn_from_credit_tag(&creditTag);
        
    PPPOE_DEBUG_PACKET("pppoe(%s,%u): Received inband grant with "
                       "fcn:0x%04x bcn:0x%04x\n", 
                       conn->peer_ip, ntohs(conn->session), fcn, bcn);

    /* add credits */
    
    /* check to make sure you don't exceed max credits */
    if ((MAX_CREDITS - conn->local_credits) < fcn) {
        conn->local_credits = MAX_CREDITS;
    } else {
        conn->local_credits += fcn;
    }
}

/***********************************************************************
 *%FUNCTION: add_credit_tag
 *%ARGUMENTS:
 * tag -- tag to fill in
 * fcn -- fcn value to use in network order
 * bcn -- bcn value to use in network order
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Adds a credit tag to a tag passed in
 ***********************************************************************/
void add_credit_tag (PPPoETag *tag, UINT16_t fcn, UINT16_t bcn)
{
    tag->type = htons(TAG_RFC4938_CREDITS);
    tag->length = htons(TAG_CREDITS_LENGTH);

    memcpy(tag->payload, &fcn, sizeof(fcn));
    memcpy(tag->payload + sizeof(bcn), &bcn, sizeof(bcn));
}


/***********************************************************************
 *%FUNCTION: add_sequence_tag
 *%ARGUMENTS:
 * tag -- tag to fill in
 * seq -- sequence number to use in network order
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Adds a sequence tag to a tag passed in
 ***********************************************************************/
void add_sequence_tag (PPPoETag *tag, UINT16_t seq)
{
    tag->type = htons(TAG_RFC4938_SEQ_NUM);
    tag->length = htons(sizeof(seq));

    memcpy(tag->payload, &seq, sizeof(seq));
}


/***********************************************************************
 *%FUNCTION: add_scalar_tag
 *%ARGUMENTS:
 * tag -- tag to fill in
 * scalar -- scalar value to use in network order
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * Adds a scalar tag to a tag passed in
 ***********************************************************************/
void add_scalar_tag (PPPoETag *tag, UINT16_t scalar)
{
    tag->type = htons(TAG_RFC4938_SCALAR);
    tag->length = htons(sizeof(scalar));

    memcpy(tag->payload, &scalar, TAG_SCALAR_LENGTH);
}


/***********************************************************************
 *%FUNCTION: compute_local_credits
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * packet -- PPPoE packet
 *%RETURNS:
 * UINT16_t -- credits consumed by packet
 *%DESCRIPTION:
 * Computes credit consumption of a local packet
 ***********************************************************************/
UINT16_t compute_local_credits (PPPoEConnection *conn, PPPoEPacket *packet)
{
    UINT16_t credits = 0;
    
    /* 
     * Credits are calculated based on ppp payload, therefore you must 
     * subtract the PPP header out from the PPPoE payload
     */
    UINT16_t len = ntohs(packet->length) - PPP_OVERHEAD;

    credits = len / conn->local_credits_scalar;

    if (len % conn->local_credits_scalar != 0) {
        credits++;
    }

    return (credits);
}

/***********************************************************************
 *%FUNCTION: compute_peer_credits
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * packet -- PPPoE packet
 *%RETURNS:
 * UINT16_t -- credits consumed by packet
 *%DESCRIPTION:
 * Computes credit consumption of a peer packet
 ***********************************************************************/
UINT16_t compute_peer_credits (PPPoEConnection *conn, PPPoEPacket *packet)
{
    UINT16_t credits = 0;

    /* 
     * Credits are calculated based on ppp payload, therefore you must 
     * subtract the PPP header out from the PPPoE payload
     */
    UINT16_t len = ntohs(packet->length) - PPP_OVERHEAD;

    credits = len / conn->peer_credits_scalar;
    
    if (len % conn->peer_credits_scalar != 0) {
        credits++;
    }

    return (credits);
}

/***********************************************************************
 *%FUNCTION: compute_peer_credits_with_inband
 *%ARGUMENTS:
 * conn -- PPPoE connection
 * packet -- PPPoE packet
 *%RETURNS:
 * UINT16_t -- credits consumed by packet
 *%DESCRIPTION:
 * Computes credit consumption of a peer packet
 ***********************************************************************/
UINT16_t compute_peer_credits_with_inband (PPPoEConnection *conn, PPPoEPacket *packet)
{
    UINT16_t credits = 0;

    /* 
     * Credits are calculated based on ppp payload, therefore you must 
     * subtract the PPP header out from the PPPoE payload
     */
    UINT16_t len = ntohs(packet->length) - PPP_OVERHEAD - 
        TAG_HDR_SIZE - TAG_CREDITS_LENGTH;

    credits = len / conn->peer_credits_scalar;

    if (len % conn->peer_credits_scalar != 0) {
        credits++;
    }

    return (credits);
}

/***********************************************************************
 *%FUNCTION: get_fcn_from_credit_tag
 *%ARGUMENTS:
 * tag -- tag to decode
 *%RETURNS:
 * UINT16_t -- fcn value
 *%DESCRIPTION:
 * decodes fcn value from a credit tag
 ***********************************************************************/
UINT16_t get_fcn_from_credit_tag (PPPoETag *tag)
{
    UINT16_t toReturn = (((UINT16_t) tag->payload[0]) << 8) + 
        (UINT16_t) tag->payload[1];

    return (toReturn);
}

/***********************************************************************
 *%FUNCTION: get_fcn_from_credit_tag
 *%ARGUMENTS:
 * tag -- tag to decode
 *%RETURNS:
 * UINT16_t -- fcn value
 *%DESCRIPTION:
 * decodes fcn value from a credit tag
 ***********************************************************************/
UINT16_t get_bcn_from_credit_tag (PPPoETag *tag)
{
    UINT16_t toReturn = (((UINT16_t) tag->payload[2]) << 8) + 
        (UINT16_t) tag->payload[3];
    
    return (toReturn);
}


/***********************************************************************
 *%FUNCTION: get_seq_from_sequence_tag
 *%ARGUMENTS:
 * tag -- tag to decode
 *%RETURNS:
 * UINT16_t -- seq value
 *%DESCRIPTION:
 * decodes sequence value from a sequence tag
 ***********************************************************************/
UINT16_t get_seq_from_sequence_tag (PPPoETag *tag)
{
    UINT16_t toReturn = (((UINT16_t) tag->payload[0]) << 8) + 
        (UINT16_t) tag->payload[1];

    return (toReturn);
}


