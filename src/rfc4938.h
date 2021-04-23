/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938.h
 * version: 1.0
 * date: October 4, 2007
 *
 * Copyright (C) 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 * This is the header file for rfc4938.c and rfc4938ctl.c
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

#ifndef __RFC4938_H__
#define __RFC4938_H__

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <time.h>
#include <wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <net/ethernet.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>     
#include <sys/ioctl.h>
#include <sys/socketvar.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "pppoe_types.h"
#include "rfc4938_types.h"
#include "rfc4938_neighbor_manager.h"
#include "rfc4938ctl_message.h"
#include "rfc4938_debug.h"

#define PPPOEBINARY "/usr/sbin/pppoe"
#define MAXFILENAME ( 50 )
#define CONFIGPATH "/etc/rfc4938.conf"
#define LNLEN ( 100 )
#define SHOWLEN ( LNLEN * (get_max_nbrs() + 1) )
#define MAXARGS ( 20 )
#define DARGS "-T 0 -t 0 -U"
#define PORTARG ( 11 )
#define OPTLEN ( 4 ) /* length of an option, a space, and a \0 '-R ' */
#define PPPOE_START_PORT ( 10000 )

#define IPV4_STR_LENGTH ( 20 )
#define MAX_IFACES ( 10 )

/*** rfc4938ctl  ***/
#define SERVER_ADDRESS "127.0.0.1"

/* argv definitions */
#define CMD ( 1 )
#define PR_STR ( 2 )
#define PR ( 3 )
#define CREDS ( 4 )
#define MDR_STR ( 4 )
#define SCLR ( 4 )
#define MDR ( 5 )
#define MDR_S ( 6 )
#define CDR_STR ( 7 )
#define CDR ( 8 )
#define CDR_S ( 9 )
#define LTNCY_STR ( 10 )
#define LTNCY ( 11 )
#define RSRCS_STR ( 12 )
#define RSRCS ( 13 )
#define RLQ_STR ( 14 )
#define RLQ ( 15 )
#define RCV ( 16 )
#define END ( 17 )

/* base for stroul conversion */
#define BASE ( 10 )

/* MAX values for user input */
#define SCLR_MAX ( 65535 )
#define MDR_MAX  ( 65535 )
#define CDR_MAX  ( 65535 )
#define LTNCY_MAX ( 65535 )
#define CREDS_MAX ( 65535 )
#define MDR_SCLR_MAX ( 3 )
#define CDR_SCLR_MAX ( 3 )
#define RSRCS_MAX ( 100 )
#define RLQ_MAX ( 100 ) 

/*
 * rfc4938.c function declarations
 *
 * These functions are used to parse a config file that is used to create a
 * list of neighbors.  
 */
extern int config_neighbor (UINT32_t argc, char *argv[]);
extern int read_config_file (char *filename);
extern int check_ip (char *addr);
extern char* get_iface (void);
extern char* get_service_name (void);
extern UINT16_t get_max_nbrs (void);
extern UINT16_t get_rfc4938_port (void);
extern UINT16_t get_ctl_port (void);
extern UINT16_t get_debug_level (void);
extern int initiate_sessions (UINT32_t neighbor_id, 
                              UINT16_t credit_scalar);
extern int terminate_sessions (UINT32_t neighbor_id);
extern int padq_session (UINT32_t neighbor_id,
                UINT8_t receive_only,
                UINT8_t rlq,
                UINT8_t resources,
                UINT16_t latency,
                UINT16_t cdr_scale,
                UINT16_t current_data_rate,
                UINT16_t mdr_scale,
                UINT16_t max_data_rate);
extern int padg_session (UINT32_t neighbor_id,
                UINT16_t credits);
extern int show_session (void);
extern void initiate_neighbor (rfc4938_neighbor_element_t *pointer,
                               UINT16_t port, 
                               UINT16_t credit_scalar);
extern void terminate_neighbor (rfc4938_neighbor_element_t *pointer,
                                UINT16_t not_used, UINT16_t not_used2);
extern void recv_session_start (rfc4938_ctl_message_t *p2ctlmsg,
                                struct sockaddr *source_addr,
                                int source_len);
extern void recv_session_start_ready(UINT32_t ip_addr, UINT16_t port);
extern void recv_session_stop(UINT32_t ip_addr);

/*
 * rfc4938ctl.c function declarations
 *
 * These functions are commands that are used on the command line
 * to interface with rfc4938.c
 */
extern int show(void);
extern int padq(
	UINT32_t neighbor_id, 
	UINT16_t max_data_rate, 
	UINT16_t mdr_scale, 
	UINT16_t current_data_rate, 
	UINT16_t cdr_scale, 
	UINT16_t latency, 
	UINT8_t resources, 
	UINT8_t rlq, 
	UINT8_t receive_only);
extern int padg(UINT32_t neighbor_id, UINT16_t credits);
extern int initiate(int cmd, UINT32_t neighbor_id, UINT16_t credit_scalar);
extern int terminate(int cmd, UINT32_t neighbor_id);
extern int send_messages(void *p2buffer);
extern int ctl_read_config_file (char *filename);

/* config variables */
static struct config_vars {
    char *iface;
    char *service_name;
    UINT16_t max_nbrs;
    UINT16_t rfc4938_port;
    UINT16_t ctl_port;
    UINT16_t debug_level;
}CONFIG;

/*
 * number checker
 *
 * input:
 *   toCheck: string of characters to check
 *
 * return:
 *   1: true
 *   0: false
 */
static inline int isNums(char *toCheck) {
    int i;
    for(i = 0; i < strlen(toCheck); i++) {
	if(toCheck[i] > 57 || toCheck[i] < 48) {
	    return 0;
	}
    }
    return 1;
}

#endif
