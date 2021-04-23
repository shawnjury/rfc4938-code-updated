/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: pppoe_rfc4938_nbr.c
 * version: 1.0
 * date: October 21, 2007
 *
 *      Copyright owner (c) 2007 by cisco Systems, Inc.
 *
 * ===========================
 *
 * This file implements functions in communicating with a neighbor
 * which also has the pppoe client side implmentation of rfc4938.
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

#include "pppoe.h"
#include "pppoe_rfc4938_nbr.h"

#include "../rfc4938ctl_message.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdlib.h>

static void packet_parser (unsigned char *rcv_buffer,
                           int bufsize,
                           struct sockaddr *source_addr,
                           socklen_t source_len);
static int recv_session_start_ready(rfc4938_ctl_message_t *p2ctlmsg,
                                    struct sockaddr *source_addr,
                                    int source_len);
static int recv_session_stop(rfc4938_ctl_message_t *p2ctlmsg,
                             struct sockaddr *source_addr,
                             int source_len);
static int recv_session_padq(rfc4938_ctl_message_t *p2ctlmsg,
                             struct sockaddr *source_addr,
                             int source_len);
static int recv_session_padg(rfc4938_ctl_message_t *p2ctlmsg,
                             struct sockaddr *source_addr,
                             int source_len);


/***********************************************************************
 *%FUNCTION: packet_parser
 *%ARGUMENTS:
 * rcv_buffer -- packet buffer
 * bufsize -- size of the buffer
 * source_addr -- source of the packet
 * source_len  -- length of source_addr
 *
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * receives a packet via UDP from a peer
 ***********************************************************************/
static void
packet_parser ( unsigned char *rcv_buffer,
                int bufsize,
                struct sockaddr *source_addr,
                socklen_t source_len)
{

    rfc4938_ctl_message_t  *p2ctlmsg;
    PPPoEConnection *conn = get_pppoe_conn();

    if (rcv_buffer == NULL) {
        PPPOE_DEBUG_ERROR("pppoe: NULL rcv_buffer reference in packet_parser()\n");
        return;
    }
    if (conn == NULL) {
        PPPOE_DEBUG_ERROR("pppoe: NULL conn reference in packet_parser()\n");
        return;
    }
    
    p2ctlmsg = (rfc4938_ctl_message_t *)rcv_buffer;

    switch (p2ctlmsg->header.cmd_code) {
    case CTL_SESSION_START_READY:
        recv_session_start_ready(p2ctlmsg, source_addr, source_len);
        break;
    case CTL_SESSION_STOP:
        recv_session_stop(p2ctlmsg, source_addr, source_len);
        break;
    case CTL_SESSION_PADQ:
        recv_session_padq(p2ctlmsg, source_addr, source_len);
        break;
    case CTL_SESSION_PADG:
        recv_session_padg(p2ctlmsg, source_addr, source_len);
        break;
    default:
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): unsupported command 0x%x \n",
                          conn->peer_ip, ntohs(conn->session),
                          p2ctlmsg->header.cmd_code);
        break;
    }

    return;
}


/***********************************************************************
 *%FUNCTION: sendUDPPacket
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- packet to send
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * sends a packet via UDP to a peer
 ***********************************************************************/
void 
sendUDPPacket (PPPoEConnection *conn, PPPoEPacket *packet)
{
    struct sockaddr_in peer_addr;
    socklen_t len_inet;
    int z;

    if (conn->peer_port == 0) {
        /* we have not learned the peer's port yet */
        PPPOE_DEBUG_EVENT("pppoe(%s,%u): Peer's port not yet known, dropping"
                           " PPP packet\n", conn->peer_ip, ntohs(conn->session));
        return;
    }

    memset(&peer_addr,0,sizeof (peer_addr));
    peer_addr.sin_family = AF_INET;    
    peer_addr.sin_port = htons(conn->peer_port);
    peer_addr.sin_addr.s_addr = inet_addr(conn->peer_ip);

    if ( peer_addr.sin_addr.s_addr == INADDR_NONE ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): sendUDPPacket: Bad address.",
                          conn->peer_ip, ntohs(conn->session));
        return;
    } 
    
    len_inet = sizeof (peer_addr);

    z = sendto(conn->socket,   
               packet->payload, 
               ntohs(packet->length), 
               0,               
               (struct sockaddr *)&peer_addr,
               len_inet);  

    if ( z < 0 ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): Error sending packet to peer\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    } else {
        PPPOE_DEBUG_PACKET("pppoe(%s,%u): Sent PPP packet to peer\n",
                           conn->peer_ip, ntohs(conn->session));
    }
    
}

/***********************************************************************
 *%FUNCTION: sendUDPPacket
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- packet to send
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * sends a packet via UDP to a peer
 ***********************************************************************/
static int 
sendUDPCTLPacket (PPPoEConnection *conn, char *ip, UINT16_t port, void *p2buffer)
{
    struct sockaddr_in peer_addr;
    socklen_t len_inet;
    int z;
    int buffer_length;
    rfc4938_ctl_message_t *p2ctlmsg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    if (port == 0) {
        return (ERANGE);
    }
    


    p2ctlmsg = (rfc4938_ctl_message_t *) p2buffer;

    switch (p2ctlmsg->header.cmd_code) {

    case CTL_SESSION_START:
        buffer_length = SIZEOF_CTL_START_REQUEST;
        break;
    case CTL_SESSION_START_READY:
        buffer_length = SIZEOF_CTL_START_READY;
        break;
    case CTL_SESSION_STOP:
        buffer_length = SIZEOF_CTL_STOP_REQUEST;
        break;
    case CTL_SESSION_PADQ:
        buffer_length = SIZEOF_CTL_PADQ_REQUEST;
        break;
    case CTL_SESSION_PADG:
        buffer_length = SIZEOF_CTL_PADG_REQUEST;
        break;
    default:
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): unsupported command 0x%x \n",
                          conn->peer_ip, ntohs(conn->session),
                          p2ctlmsg->header.cmd_code);
        return (ERANGE);
        break;
    }

    memset(&peer_addr,0,sizeof (peer_addr));
    peer_addr.sin_family = AF_INET;    
    peer_addr.sin_port = htons(port);
    peer_addr.sin_addr.s_addr = inet_addr(ip);

    if ( peer_addr.sin_addr.s_addr == INADDR_NONE ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): sendUDPCTLPacket: Bad address.\n",
                          conn->peer_ip, ntohs(conn->session));
        return (ERANGE);
    } 

    if ( peer_addr.sin_port == 0 ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): sendUDPCTLPacket: Bad port.\n",
                          conn->peer_ip, ntohs(conn->session));
        return (ERANGE);
    }     
    
    len_inet = sizeof (peer_addr);

    z = sendto(conn->socket,   
               p2buffer,
               buffer_length,
               0,               
               (struct sockaddr *)&peer_addr,
               len_inet);  

    if ( z < 0 ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): sendUDPCTLPacket(): Error sending"
                          " packet to peer\n", conn->peer_ip, ntohs(conn->session));
        return (ERANGE);
    }
    
    return (SUCCESS);
}


/***********************************************************************
 *%FUNCTION: recvUDPPacket
 *%ARGUMENTS:
 * conn -- PPPoE Connection
 * packet -- packet to receive
 *%RETURNS:
 * Nothing
 *%DESCRIPTION:
 * receives a packet via UDP from a peer
 ***********************************************************************/
int
recvUDPPacket(PPPoEConnection *conn, PPPoEPacket *packet)
{
    int z = 0;
    socklen_t len_inet;
    unsigned char rcv_buffer[ETH_DATA_LEN];
    UINT16_t hdr_check = 0;

    len_inet = sizeof (conn->peer_sock);

    z = recvfrom(conn->socket,
                 rcv_buffer,
                 ETH_DATA_LEN,                 
                 0,           
                 (struct sockaddr *)&(conn->peer_sock),
                 &len_inet);    

    if ( z < 0 ) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): recvUDPPacket: error with recvfrom\n",
                          conn->peer_ip, ntohs(conn->session));
        return 0;
    }

    hdr_check = ((((UINT16_t) rcv_buffer[0]) << 8) + (UINT16_t) rcv_buffer[1]);

    PPPOE_DEBUG_PACKET("pppoe(%s,%u): UDP pkt received with hdr_check"
                       " of 0x%04x\n", conn->peer_ip, ntohs(conn->session), hdr_check);

    /* check to see if it is a PPP packet */
    if (hdr_check != MSG_MAGIC_NUMBER) {
        memcpy(packet->payload, rcv_buffer, z);
    } else {
        packet_parser(rcv_buffer,
                      z,
                      (struct sockaddr *)&(conn->peer_sock),
                      len_inet);
        /* don't send the ctrl packet on to the router */
        z = 0;
    }
    return (z);
}


/***********************************************************************
 *%FUNCTION: send_session_start
 *%ARGUMENTS:
 * ip -- ip address to send session_start msg to
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Sends a session_start message to neighbor rfc4938 process
 ***********************************************************************/
int
send_session_start(PPPoEConnection *conn, char *ip)
{
    int retval;
    void *p2buffer;
    UINT16_t scalar;
    
    p2buffer = malloc(SIZEOF_CTL_START_REQUEST);

    if (p2buffer == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start(): unable "
                          "to malloc p2buffer\n", conn->peer_ip, ntohs(conn->session));
        return (EBADMSG);
    }
    
    if (conn->mode == RFC4938_ONLY) {
        scalar = 0;
    } else {
        scalar = conn->local_credits_scalar;
    }

    if (rfc4938_ctl_format_session_start(conn->my_port, 
                                         scalar,
                                         p2buffer) != SUCCESS) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start(): Unable"
                          " to format message\n", conn->peer_ip, ntohs(conn->session));
        free(p2buffer);
        return (EBADMSG);
    }
    
    retval = sendUDPCTLPacket (conn, ip, conn->parent_port, p2buffer);

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): sending session_start_msg()\n", 
                      conn->peer_ip, ntohs(conn->session));

    return (retval);
}

/***********************************************************************
 *%FUNCTION: send_session_start_ready
 *%ARGUMENTS:
 * conn        -- PPPoE connection
 * ip          -- ip address to send session_start_ready to
 * port        -- destination port to send to
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Sends session_start_ready msg.  This message is sent from the pppoe 
 * process to its local rfc4938 process to signal the port it succesfully
 * bound to, and the ip of the neighbor it is connecting to, if it was
 * the first neighbor to be started.  The second neighbor will send a
 * session_start_ready message to its rfc4938 process and the first
 * neighbor.
 ***********************************************************************/

int
send_session_start_ready(PPPoEConnection *conn, char *ip, UINT16_t port)
{
    int retval;
    void *p2buffer;
    UINT32_t ip_addr;

    p2buffer = malloc(SIZEOF_CTL_START_READY);

    if (p2buffer == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start_ready(): unable to"
                          " malloc p2buffer\n", conn->peer_ip, ntohs(conn->session));
        return (EBADMSG);
    }

    ip_addr = (UINT32_t) inet_addr(conn->peer_ip);
    if (ip_addr == INADDR_NONE) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start_ready(): bad ip for"
                          " nbr\n", conn->peer_ip, ntohs(conn->session));
        free(p2buffer);
        return (EBADMSG);
    }

    if (rfc4938_ctl_format_session_start_ready(ip_addr, 
                                               conn->my_port, 
                                               p2buffer) != SUCCESS) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start_ready(): "
                          "Unable to format message\n", conn->peer_ip, ntohs(conn->session));
        free(p2buffer);
    }
    
    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Sending session_start_ready message to %s on port %u\n",
                      conn->peer_ip, ntohs(conn->session), ip, port);

    retval = sendUDPCTLPacket (conn, ip, port, p2buffer);
    return (retval);
}

/***********************************************************************
 *%FUNCTION: recv_session_start_ready
 *%ARGUMENTS:
 * p2ctlmsg -- message recevied
 * source_addr -- source of the packet
 * source_len  -- length of source_addr
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Receives a session start ready message from its peer to learn its port
 ***********************************************************************/
static int
recv_session_start_ready(rfc4938_ctl_message_t *p2ctlmsg,
                         struct sockaddr *source_addr,
                         int source_len)
{
    PPPoEConnection *conn = get_pppoe_conn();
    
    if (p2ctlmsg == NULL) {
        return (EBADMSG);
    }

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Received session start ready message "
                      "from %s with port %u\n",
                      conn->peer_ip, ntohs(conn->session),
                      inet_ntoa(((struct sockaddr_in*) source_addr)->sin_addr),
                      htons(((struct sockaddr_in *) source_addr)->sin_port));

    if (conn != NULL) {
        conn->peer_port = ntohs(p2ctlmsg->ctl_start_ready_payload.port_number);

        PPPOE_DEBUG_EVENT("pppoe(%s,%u): Peer port set to %u\n",
                          conn->peer_ip, ntohs(conn->session),
                          conn->peer_port);
    } 

    return (SUCCESS);
}

/***********************************************************************
 *%FUNCTION: send_session_stop
 *%ARGUMENTS:
 * conn        -- PPPoE connection
 * ip          -- ip address to send session_start_ready to
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Sends session_stop message
 ***********************************************************************/
void
send_session_stop(PPPoEConnection *conn, char *ip)
{
    void *p2buffer;
    UINT32_t ip_addr;

    p2buffer = malloc(SIZEOF_CTL_STOP_REQUEST);

    if (p2buffer == NULL) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_stop(): unable to malloc p2buffer\n",
                          conn->peer_ip, ntohs(conn->session));
        return;
    }

    ip_addr = (UINT32_t) inet_addr(conn->peer_ip);
    if (ip_addr == INADDR_NONE) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_start_ready(): bad ip for nbr\n",
                          conn->peer_ip, ntohs(conn->session));
        free(p2buffer);
        return;
    }


    if (rfc4938_ctl_format_session_stop(ip_addr, p2buffer) != SUCCESS) {
        PPPOE_DEBUG_ERROR("pppoe(%s,%u): send_session_stop(): Unable to format message\n",
                          conn->peer_ip, ntohs(conn->session));
        free(p2buffer);
    }
    
    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Sending session_stop message to peer %s\n", 
                      conn->peer_ip, ntohs(conn->session), conn->peer_ip);

    /* send to peer */
    sendUDPCTLPacket(conn, ip, conn->peer_port, p2buffer);
    
    /* send to parent rfc4938 */
    sendUDPCTLPacket(conn, LOCALHOST, conn->parent_port, p2buffer);
}

/***********************************************************************
 *%FUNCTION: recv_session_stop
 *%ARGUMENTS:
 * p2ctlmsg -- message recevied
 * source_addr -- source of the packet
 * source_len  -- length of source_addr
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Receives a session stop message
 ***********************************************************************/
static int
recv_session_stop(rfc4938_ctl_message_t *p2ctlmsg,
                  struct sockaddr *source_addr,
                  int source_len)
{
    PPPoEConnection *conn = get_pppoe_conn();
    
    if (conn == NULL) {
        PPPOE_DEBUG_ERROR("pppoe: NULL conn reference in packet_parser()\n");
        return (EBADMSG);
    }
    
    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Received session stop message from %s\n",
                      conn->peer_ip, ntohs(conn->session),
                      inet_ntoa(((struct sockaddr_in *)source_addr)->sin_addr));

    /* 
     * not really an error, but fatalsys has everything we need setup 
     * to terminate session 
     */
    fatalSys("Received session_stop message from peer.");

    return (SUCCESS);
}

/***********************************************************************
 *%FUNCTION: recv_session_padq
 *%ARGUMENTS:
 * p2ctlmsg -- message recevied
 * source_addr -- source of the packet
 * source_len  -- length of source_addr
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Receives a session padq message
 ***********************************************************************/
static int
recv_session_padq(rfc4938_ctl_message_t *p2ctlmsg,
                  struct sockaddr *source_addr,
                  int source_len)
{
    PPPoEConnection *conn = get_pppoe_conn();

    if (p2ctlmsg == NULL) {
        return (EBADMSG);
    }

    UINT8_t receive_only = p2ctlmsg->ctl_padq_payload.receive_only;
    UINT8_t rlq = p2ctlmsg->ctl_padq_payload.rlq;
    UINT8_t resources = p2ctlmsg->ctl_padq_payload.resources;
    UINT16_t latency = ntohs(p2ctlmsg->ctl_padq_payload.latency);
    UINT8_t cdr_scale = p2ctlmsg->ctl_padq_payload.cdr_scale;
    UINT16_t cdr = ntohs(p2ctlmsg->ctl_padq_payload.current_data_rate);
    UINT8_t mdr_scale = p2ctlmsg->ctl_padq_payload.mdr_scale;
    UINT16_t mdr = ntohs(p2ctlmsg->ctl_padq_payload.max_data_rate);

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Received padg message from %s with port %u"
                      " and padq data of \n"
                      "\treceive_only: %u\n"
                      "\trlq: %u\n"
                      "\tresources: %u\n"
                      "\tlatency: %u\n"
                      "\tcdr_scale: %u\n"
                      "\tcurrent_data_rate: %u\n"
                      "\tmdr_scale: %u\n"
                      "\tmax_data_rate: %u\n",
                      conn->peer_ip, ntohs(conn->session),
                      inet_ntoa(((struct sockaddr_in *)source_addr)->sin_addr),
                      ((struct sockaddr_in *) source_addr)->sin_port,
                       receive_only, rlq, resources, latency,
                       cdr_scale, cdr, mdr_scale, mdr);

    if (conn != NULL) {
        sendPADQ(get_pppoe_conn(), mdr, mdr_scale, cdr, cdr_scale, latency,
                 resources, rlq, receive_only);
    }

    return (SUCCESS);
}

/***********************************************************************
 *%FUNCTION: recv_session_padg
 *%ARGUMENTS:
 * p2ctlmsg -- message recevied
 * source_addr -- source of the packet
 * source_len  -- length of source_addr
 *
 *%RETURNS:
 * SUCCESS or error code
 *%DESCRIPTION:
 * Receives a session padg message
 ***********************************************************************/
static int
recv_session_padg(rfc4938_ctl_message_t *p2ctlmsg,
                  struct sockaddr *source_addr,
                  int source_len)
{
    PPPoEConnection *conn = get_pppoe_conn();

    if (p2ctlmsg == NULL) {
        return (EBADMSG);
    }

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): Received padg message from %s with port %u"
                      " and grant amount of %u\n",
                      conn->peer_ip, ntohs(conn->session),
                      inet_ntoa(((struct sockaddr_in *)source_addr)->sin_addr),
                      ((struct sockaddr_in *) source_addr)->sin_port,
                      ntohs(p2ctlmsg->ctl_padg_payload.credits));

    if (conn != NULL) {
        conn->grant_amount = ntohs(p2ctlmsg->ctl_padg_payload.credits);
    }

    PPPOE_DEBUG_EVENT("pppoe(%s,%u): 1-second grant amount updated to %u\n", 
                      conn->peer_ip, ntohs(conn->session),
                      conn->grant_amount);

    return (SUCCESS);
}
