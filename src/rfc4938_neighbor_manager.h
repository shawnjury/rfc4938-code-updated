/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938_neighbor_manager.h
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C), 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 *
 * These APIs are used to manage a pool of local port numbers
 * that are associated with client instances.  Port numbers
 * are allocated for use and freed when the client instance
 * is torn down.
 *
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


#ifndef __NEIGHBOR_MANAGER_H__
#define __NEIGHBOR_MANAGER_H__

#include "rfc4938_types.h"

#ifndef LNLEN
#define LNLEN ( 100 )
#endif

#ifndef SHOWLEN
#define SHOWLEN ( LNLEN * (get_max_nbrs() + 1) )
#endif

/*
 * Neighbor states
 */
typedef enum {
    ACTIVE = 33,
    INACTIVE = 55,
} neighbor_state_t;



/*
 * neighbor element
 */
typedef struct _rfc4938_neighbor_element_s {

    neighbor_state_t state;
    neighbor_state_t session_state;

    /*
     * neighbor that we're connected with
     */
    UINT32_t neighbor_id;
    UINT32_t neighbor_addr;
    UINT16_t neighbor_port;  /* this is the local pppoe port */
    UINT16_t send_session_start_ready;
    pid_t pid;

    struct _rfc4938_neighbor_element_s *next;
} rfc4938_neighbor_element_t;




/*
 * functional prototypes
 */
extern void
neighbor_print(UINT32_t neighbor_id);

extern void
neighbor_print_all(void);

extern void
neighbor_print_all_string (char **dgram);

extern int
neighbor_allocate(
         UINT32_t neighbor_id,
         UINT32_t neighbor_addr,
         UINT16_t neighbor_port);

extern int
neighbor_release(
           UINT32_t neighbor_id);

extern int
neighbor_query (
           UINT32_t neighbor_id,
           rfc4938_neighbor_element_t *p2neighbor);

extern int
neighbor_pointer (
           UINT32_t neighbor_id,
           rfc4938_neighbor_element_t **p2neighbor);

extern int
neighbor_pointer_by_addr (
           UINT32_t ip_addr,
           rfc4938_neighbor_element_t **p2neighbor);

extern int
neighbor_pointer_by_port (
           UINT16_t port,
           rfc4938_neighbor_element_t **p2neighbor);

extern int
neighbor_pointer_by_pid (
           pid_t pid,
           rfc4938_neighbor_element_t **p2neighbor);

extern int
neighbor_toggle_all (
    void (*pt2func)(rfc4938_neighbor_element_t *, UINT16_t, UINT16_t),
    UINT16_t credit_scalar);

extern int
neighbor_init(UINT16_t max_neighbors);

#endif

