/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: pppoe_rfc4938.h
 * version: 1.0
 * date: October 4, 2007
 *
 * Copyright (C) 2007-2008, Cisco Systems, Inc.
 *
 * ===========================
 * This is the header file which implements functions related to
 * rfc4938, "PPP Over Ethernet (PPPoE) Extensions for Credit Flow and
 * Link Metrics" and "PPP Over Ethernet (PPPoE) Extensions for Scaled
 * Credits and Link Metrics"
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

#ifndef __PPPOE_RFC4938_H__
#define __PPPOE_RFC4938_H__

#include "pppoe.h"
#include "string.h"

#define CODE_PADG           ( 0x0A )
#define CODE_PADC           ( 0x0B )
#define CODE_PADQ           ( 0x0C )

#define TAG_RFC4938_CREDITS    ( 0x0106 )
#define TAG_RFC4938_METRICS    ( 0x0107 )
#define TAG_RFC4938_SEQ_NUM    ( 0x0108 )
#define TAG_RFC4938_SCALAR     ( 0x0109 )

#define TAG_CREDITS_LENGTH     ( 0x4 )
#define TAG_METRICS_LENGTH     ( 0xa )
#define TAG_SEQ_LENGTH         ( 0x2 )
#define TAG_SCALAR_LENGTH      ( 0x2 )

#define INITIAL_GRANT          ( 1953 )
#define CREDIT_MISMATCH        ( 100 )
#define MAX_CREDITS            ( 0xffff )
#define RFC4938_CREDIT_SCALAR  ( 64 )
#define PADG_TIMER_VAL         ( 1 )  /* 1 second */
#define MAX_PADG_RETRIES       ( 4 )

#define SCALING_KBPS           ( 0x00 )
#define SCALING_MBPS           ( 0x01 )
#define SCALING_GBPS           ( 0x10 )
#define SCALING_TBPS           ( 0x11 )

#define MAX_DEBUG_STRING       ( 2048 )

#define TRUE                   ( 1 )
#define FALSE                  ( 0 )

/* function declarations */
extern void init_flow_control(PPPoEConnection *conn, UINT16_t scalar, int rfc4938_debug,
                              UINT16_t my_port, UINT16_t peer_port, UINT16_t parent_port, 
                              UINT16_t grant_amount);
extern void grant_event(int signo);
extern void sendPADG(PPPoEConnection *conn, UINT16_t credits);
extern void sendPADC(PPPoEConnection *conn, UINT16_t seq);
extern void recvPADG(PPPoEConnection *conn, PPPoEPacket *packet);
extern void recvPADC(PPPoEConnection *conn, PPPoEPacket *packet);
extern void sendPADQ(PPPoEConnection *conn, UINT16_t mdr, UINT8_t mdr_scalar, 
                     UINT16_t cdr, UINT8_t cdr_scalar, UINT16_t latency, 
                     UINT8_t resources, UINT8_t rlq, UINT8_t receive);
extern void recvPADQ(PPPoEConnection *conn, PPPoEPacket *packet);
extern UINT16_t sendInbandGrant(PPPoEConnection *conn, PPPoEPacket *packet, UINT16_t credits);
extern void recvInbandGrant(PPPoEConnection *conn, PPPoEPacket *packet);
extern void add_credit_tag(PPPoETag *tag, UINT16_t fcn, UINT16_t bcn);
extern void add_sequence_tag(PPPoETag *tag, UINT16_t seq);
extern void add_scalar_tag(PPPoETag *tag, UINT16_t scalar);
extern UINT16_t compute_local_credits (PPPoEConnection *conn, PPPoEPacket *packet);
extern UINT16_t compute_peer_credits (PPPoEConnection *conn, PPPoEPacket *packet);
extern UINT16_t compute_peer_credits_with_inband (PPPoEConnection *conn, PPPoEPacket *packet);
extern UINT16_t get_fcn_from_credit_tag(PPPoETag *tag);
extern UINT16_t get_bcn_from_credit_tag(PPPoETag *tag);
extern UINT16_t get_seq_from_sequence_tag(PPPoETag *tag);


#endif
