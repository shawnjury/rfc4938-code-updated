/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: pppoe_rfc4938_nbr.h
 * version: 1.0
 * date: October 4, 2007
 *
 *      Copyright owner (c) 2007 by cisco Systems, Inc.
 *
 * ===========================
 * This is the header file for the functions to communicate with a neighbor
 * which also has the pppoe client side implmentation of rfc4938.
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

#ifndef __PPPOE_RFC4938_NBR_H__
#define __PPPOE_RFC4938_NBR_H__

#include "pppoe_rfc4938.h"
#include "../rfc4938_neighbor_manager.h"
#include "../rfc4938ctl_message.h"
#include "../rfc4938_types.h"

#define LOCALHOST "127.0.0.1"

extern int send_session_start(PPPoEConnection *conn, char *ip);
extern int send_session_start_ready(PPPoEConnection *conn, char *ip, UINT16_t port);
extern void send_session_stop(PPPoEConnection *conn, char *ip);
extern void sendUDPPacket(PPPoEConnection *conn, PPPoEPacket *packet);
extern int recvUDPPacket(PPPoEConnection *conn, PPPoEPacket *packet);

#endif
