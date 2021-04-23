/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938ctl_message.c
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C), 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 *
 * This file provides APIs to format the CLI and control messages.
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


#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "rfc4938_types.h"
#include "rfc4938ctl_message.h"


/*
 * rfc4938_ctl_format_session_start
 *
 * Description
 *    This function formats the CTL session start message in the
 *    provided buffer.  This message is sent from one box to
 *    another to initiate the session.
 *
 * Inputs:
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_ctl_format_session_start (
                           UINT16_t port_number,
                           UINT16_t credit_scalar,
                           void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = htons(MSG_MAGIC_NUMBER);
    p2msg->header.cmd_code = CTL_SESSION_START;

    /*
     * and now the payload
     */
    p2msg->ctl_start_payload.port_number = htons(port_number);
    p2msg->ctl_start_payload.credit_scalar = htons(credit_scalar);

    return (SUCCESS);
}


/*
 * rfc4938_ctl_format_session_start_ready
 *
 * Description
 *    This function formats the session start ready message
 *    in the provided buffer.  This message is sent in response
 *    to the session start message, confirming the establishment
 *    of the neighbor session.  This is a box to box message.
 *
 * Inputs:
 *    ip_addr        The local ip addr
 *    port_number
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_ctl_format_session_start_ready (
                UINT32_t ip_addr,
                UINT16_t port_number,
                 void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = htons(MSG_MAGIC_NUMBER);
    p2msg->header.cmd_code = CTL_SESSION_START_READY;

    /*
     * and now the payload
     */
    p2msg->ctl_start_ready_payload.ip_addr = ip_addr;
    p2msg->ctl_start_ready_payload.port_number = htons(port_number);

    return (SUCCESS);
}


/*
 * rfc4938_ctl_format_session_stop
 *
 * Description
 *    This function formats the session stop message in the
 *    provided buffer.  This message is sent to tear down
 *    an active neighbor session.  This is a box to box
 *    message.
 *
 * Inputs:
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_ctl_format_session_stop (UINT32_t ip_addr, void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = htons(MSG_MAGIC_NUMBER);
    p2msg->header.cmd_code = CTL_SESSION_STOP;

    /*
     * and now the payload
     */
    p2msg->ctl_stop_payload.ip_addr = ip_addr;

    return (SUCCESS);
}


/*
 * rfc4938_ctl_format_session_padq
 *
 * Description
 *    This function formats the session PADQ message in the
 *    provided buffer.  This message is sent to manipulate
 *    the quality metrics of the specified active neighbor
 *    session.  This is a box to box message.
 *
 * Inputs:
 *    receive_only       present, but not used
 *    rlq                relative link quality, 0-100%
 *    resources          0-100%
 *    latency            milliseconds
 *    cdr_scale
 *    current_data_rate
 *    mdr_scale
 *    max_data_rate
 *    p2buffer           Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer           Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_ctl_format_session_padq (
                UINT8_t receive_only,
                UINT8_t rlq,
                UINT8_t resources,
                UINT16_t latency,
                UINT8_t cdr_scale,
                UINT16_t current_data_rate,
                UINT8_t mdr_scale,
                UINT16_t max_data_rate,
                void *p2buffer )
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = htons(MSG_MAGIC_NUMBER);
    p2msg->header.cmd_code = CTL_SESSION_PADQ;

    /*
     * and now the payload
     */
    p2msg->ctl_padq_payload.receive_only = receive_only;
    p2msg->ctl_padq_payload.rlq = rlq;
    p2msg->ctl_padq_payload.resources = resources;
    p2msg->ctl_padq_payload.latency = htons(latency);
    p2msg->ctl_padq_payload.cdr_scale = cdr_scale;
    p2msg->ctl_padq_payload.current_data_rate = htons(current_data_rate);
    p2msg->ctl_padq_payload.mdr_scale = mdr_scale;
    p2msg->ctl_padq_payload.max_data_rate = htons(max_data_rate);

    return (SUCCESS);
}


/*
 * rfc4938_ctl_format_session_padg
 *
 * Description
 *    This function formats the session PADG message in the
 *    provided buffer.  This message is sent to manipulate
 *    the credit grants of the specified active neighbor
 *    session.  This is a box to box message.
 *
 * Inputs:
 *    credits            credits to grant (inject)
 *    p2buffer           Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer           Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_ctl_format_session_padg (
                UINT16_t credits,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = htons(MSG_MAGIC_NUMBER);
    p2msg->header.cmd_code = CTL_SESSION_PADG;

    /*
     * and now the payload
     */
    p2msg->ctl_padg_payload.credits = htons(credits);

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_session_initiate
 *
 * Description
 *    This function formats the CLI session initiate
 *    message in the provided buffer.  This message
 *    is sent from the CLI process to the control
 *    process to initiate a neighbor session.
 *
 * Inputs:
 *    neighbor_id      ID of the neighbor  **** WHY HERE ****
 *    credit_scalar    Credit scalar to use for the neighbor
 *    p2buffer         Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer         Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_session_initiate (
                UINT32_t neighbor_id,
                UINT16_t credit_scalar,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_INITIATE;

    /*
     * and now the payload
     */
    p2msg->cli_initiate_payload.neighbor_id = neighbor_id;
    p2msg->cli_initiate_payload.credit_scalar = credit_scalar;

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_session_terminate
 *
 * Description
 *    This function formats the CLI session terminate
 *    message in the provided buffer.  This message
 *    is sent from the CLI process to the control
 *    process to terminate a neighbor session.
 *
 * Inputs:
 *    neighbor_id    ID of the neighbor
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_session_terminate (
                UINT32_t neighbor_id,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_TERMINATE;

    /*
     * and now the payload
     */
    p2msg->cli_terminate_payload.neighbor_id = neighbor_id;

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_padq
 *
 * Description
 *    This function formats the PADQ message in the
 *    provided buffer.  This message is sent from
 *    the CLI process to the control process to inject
 *    a set of quality metric into an active neighbor session.
 *
 * Inputs:
 *    neighbor_id
 *    receive_only       present, but not used
 *    rlq                relative link quality, 0-100%
 *    resources          0-100%
 *    latency            milliseconds
 *    cdr_scale
 *    current_data_rate
 *    mdr_scale
 *    max_data_rate
 *    p2buffer           Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer           Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_padq (
                UINT32_t neighbor_id,
                UINT8_t receive_only,
                UINT8_t rlq,
                UINT8_t resources,
                UINT16_t latency,
                UINT16_t cdr_scale,
                UINT16_t current_data_rate,
                UINT16_t mdr_scale,
                UINT16_t max_data_rate,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_PADQ;

    /*
     * and now the payload
     */
    p2msg->cli_padq_payload.neighbor_id = neighbor_id;

    p2msg->cli_padq_payload.receive_only = receive_only;
    p2msg->cli_padq_payload.rlq = rlq;
    p2msg->cli_padq_payload.resources = resources;
    p2msg->cli_padq_payload.latency = latency;
    p2msg->cli_padq_payload.cdr_scale = cdr_scale;
    p2msg->cli_padq_payload.current_data_rate = current_data_rate;
    p2msg->cli_padq_payload.mdr_scale = mdr_scale;
    p2msg->cli_padq_payload.max_data_rate = max_data_rate;

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_session_padg
 *
 * Description
 *    This function formats the session PADG message in the
 *    provided buffer.  This message is sent from
 *    the CLI process to the control process to manipulate
 *    the credits of an active neighbor session.
 *
 * Inputs:
 *    credit_scalar      scalar value
 *    credits            credits to grant (inject)
 *    p2buffer           Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer           Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_session_padg (
		UINT32_t neighbor_id,
                UINT16_t credits,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_PADG;

    /*
     * and now the payload
     */
    p2msg->cli_padg_payload.neighbor_id = neighbor_id;
    p2msg->cli_padg_payload.credits = credits;

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_session_show
 *
 * Description
 *    This function formats the session show message in the
 *    provided buffer.  This message is sent from
 *    the CLI process to the control process to display
 *    status information of an active neighbor session.
 *
 * Inputs:
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_session_show (
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_SHOW;

    /*
     * no payload
     */

    return (SUCCESS);
}


/*
 * rfc4938_cli_format_session_show_response
 *
 * Description
 *    This function formats the session show response
 *    message in the provided buffer.
 *    *** DO WE REALLY NEED THIS ***
 *
 * Inputs:
 *    p2buffer       Pointer to the buffer to be formatted
 *
 * Outputs:
 *    p2buffer       Formatted buffer. Only valid w/ SUCCESS.
 *
 * Returns:
 *    SUCCESS
 *    ERANGE
 */
int
rfc4938_cli_format_session_show_response (
                UINT32_t neighbor_id,
                void *p2buffer)
{
    rfc4938_ctl_message_t *p2msg;

    if (p2buffer == NULL) {
        return (ERANGE);
    }

    p2msg = p2buffer;

    /*
     * Insert the header
     */
    p2msg->header.magic_number = MSG_MAGIC_NUMBER;
    p2msg->header.cmd_code = CLI_SESSION_SHOW_RESPONSE;

    /*
     * and now the payload
     */
    p2msg->cli_show_response_payload.neighbor_id = neighbor_id;

    return (SUCCESS);
}


