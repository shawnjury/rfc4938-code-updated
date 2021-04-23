/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938ctl_message.h
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C) 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 *
 * This file provides message structures for the CLI and control messages.
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


#ifndef __RFC4938CTL_MESSAGE_H__
#define __RFC4938CTL_MESSAGE_H__

#include "rfc4938_types.h"

#define MSG_MAGIC_NUMBER 0xbaaf

/*
 * Message command codes
 */
typedef enum {

    /* control, box-box messages */
    CTL_SESSION_START = 0,
    CTL_SESSION_START_READY,
    CTL_SESSION_STOP,
    CTL_SESSION_PADQ,
    CTL_SESSION_PADG,

    /* CLI related messages */
    CLI_SESSION_INITIATE,
    CLI_SESSION_TERMINATE,
    CLI_SESSION_PADQ,
    CLI_SESSION_PADG,
    CLI_SESSION_SHOW,
    CLI_SESSION_SHOW_RESPONSE,

} rfc4938_ctl_message_cmd_t;



/*
 * Defines the header used for all messages sent to
 * and received from the rfc4938ctl process.
 */
typedef struct {
    UINT16_t   magic_number;
    UINT8_t    cmd_code;
} rfc4938_ctl_message_header_t;


/*
 * session start payload.
 */
typedef struct {
    UINT16_t   port_number;
    UINT16_t   credit_scalar;
} rfc4938_ctl_start_payload_t;

#define SIZEOF_CTL_START_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_ctl_start_payload_t))


/*
 * session start ready payload.
 */
typedef struct {
    UINT32_t   ip_addr;
    UINT16_t   port_number;
} rfc4938_ctl_start_ready_payload_t;

#define SIZEOF_CTL_START_READY  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_ctl_start_ready_payload_t))


/*
 * session stop payload.
 */
typedef struct {
    UINT32_t   ip_addr;
} rfc4938_ctl_stop_payload_t;

#define SIZEOF_CTL_STOP_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_ctl_stop_payload_t))


/*
 * inject padq values.
 */
#define data_rate_kbps_scale   ( 0x00 )
#define data_rate_mbps_scale   ( 0x01 )
#define data_rate_gbps_scale   ( 0x10 )
#define data_rate_tbps_scale   ( 0x11 )

typedef struct {
    UINT8_t    receive_only;    /* not used */
    UINT8_t    rlq;             /* 0 - 100 */
    UINT8_t    resources;       /* 0 - 100 */

    UINT16_t   latency;         /* milliseconds */

    UINT16_t   cdr_scale;
    UINT16_t   current_data_rate;

    UINT16_t   mdr_scale;
    UINT16_t   max_data_rate;
} rfc4938_ctl_padq_payload_t;

#define SIZEOF_CTL_PADQ_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_ctl_padq_payload_t))


/*
 * inject padg credits.
 */
typedef struct {
    UINT16_t   credits;
} rfc4938_ctl_padg_payload_t;

#define SIZEOF_CTL_PADG_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_ctl_padg_payload_t))



/*
 * cli initiate session.
 */
typedef struct {
    UINT32_t   neighbor_id;
    UINT16_t   credit_scalar;
    UINT16_t   mdr_scale;
} rfc4938_cli_initiate_payload_t;

#define SIZEOF_CLI_INITIATE_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_initiate_payload_t))


/*
 * cli terminate session.
 */
typedef struct {
    UINT32_t   neighbor_id;
} rfc4938_cli_terminate_payload_t;

#define SIZEOF_CLI_TERMINATE_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_terminate_payload_t))


/*
 * cli inject padq request.
 */
typedef struct {
    UINT32_t   neighbor_id;

    UINT8_t    receive_only;    /* not used */
    UINT8_t    rlq;             /* 0 - 100 */
    UINT8_t    resources;       /* 0 - 100 */
    UINT16_t   latency;         /* milliseconds */
    UINT16_t   cdr_scale;
    UINT16_t   current_data_rate;
    UINT16_t   mdr_scale;
    UINT16_t   max_data_rate;
} rfc4938_cli_padq_payload_t;

#define SIZEOF_CLI_PADQ_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_padq_payload_t))



/*
 * cli inject padg credits.
 */
typedef struct {
    UINT32_t neighbor_id;
    UINT16_t   credits;
} rfc4938_cli_padg_payload_t;

#define SIZEOF_CLI_PADG_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_padg_payload_t))


/*
 * cli show session request.
 */
typedef struct {
} rfc4938_cli_show_payload_t;

#define SIZEOF_CLI_SHOW_REQUEST  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_show_payload_t))


/*
 * cli show session response.
 */
typedef struct {
    UINT32_t   neighbor_id;
#define SHOW_TEXT_OUTPUT (1000)
    char       show_text[SHOW_TEXT_OUTPUT];
} rfc4938_cli_show_response_payload_t;

#define SIZEOF_CLI_SHOW_RESPONSE  \
          (sizeof(rfc4938_ctl_message_header_t) + sizeof(rfc4938_cli_show_response_payload_t))


/*
 * The message definition.
 */
typedef struct {
    rfc4938_ctl_message_header_t header;

    union {
        /* box-box */
        rfc4938_ctl_start_payload_t ctl_start_payload;

        rfc4938_ctl_start_ready_payload_t ctl_start_ready_payload;

        rfc4938_ctl_stop_payload_t  ctl_stop_payload;

        rfc4938_ctl_padq_payload_t  ctl_padq_payload;

        rfc4938_ctl_padg_payload_t  ctl_padg_payload;


        /* cli requests */
        rfc4938_cli_initiate_payload_t  cli_initiate_payload;

        rfc4938_cli_terminate_payload_t  cli_terminate_payload;

        rfc4938_cli_padq_payload_t  cli_padq_payload;

        rfc4938_cli_padg_payload_t  cli_padg_payload;

        rfc4938_cli_show_payload_t  cli_show_payload;

        rfc4938_cli_show_response_payload_t  cli_show_response_payload;

    };

} rfc4938_ctl_message_t;



/*
 * function prototypes
 */

extern int
rfc4938_ctl_format_session_start(
                        UINT16_t port_number,
                        UINT16_t credit_scalar,
                        void *p2buffer);

extern int
rfc4938_ctl_format_session_start_ready(
                UINT32_t ip_addr,
                UINT16_t port_number,
                 void *p2buffer);

extern int
rfc4938_ctl_format_session_stop(UINT32_t ip_addr,
                                void *p2buffer);

extern int
rfc4938_ctl_format_session_padq(
                UINT8_t receive_only,
                UINT8_t rlq,
                UINT8_t resources,
                UINT16_t latency,
                UINT8_t cdr_scale,
                UINT16_t current_data_rate,
                UINT8_t mdr_scale,
                UINT16_t max_data_rate,
                void *p2buffer);

extern int
rfc4938_ctl_format_session_padg (
                UINT16_t credits,
                void *p2buffer);


extern int
rfc4938_cli_format_session_initiate(
                UINT32_t neighbor_id,
                UINT16_t credit_scalar,
                void *p2buffer);

extern int
rfc4938_cli_format_session_terminate(
                UINT32_t neighbor_id,
                void *p2buffer);

extern int
rfc4938_cli_format_padq(
                UINT32_t neighbor_id,
                UINT8_t receive_only,
                UINT8_t rlq,
                UINT8_t resources,
                UINT16_t latency,
                UINT16_t cdr_scale,
                UINT16_t current_data_rate,
                UINT16_t mdr_scale,
                UINT16_t max_data_rate,
                void *p2buffer);

extern int
rfc4938_cli_format_session_padg(
		UINT32_t neighbor_id,
                UINT16_t credits,
                void *p2buffer);

extern int
rfc4938_cli_format_session_show(
                void *p2buffer);

extern int
rfc4938_cli_format_session_show_response(
                UINT32_t neighbor_id,
                void *p2buffer);

#endif
































