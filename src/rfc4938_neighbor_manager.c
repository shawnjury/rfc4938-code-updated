/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938_neighbor_id_manager.c
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C), 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 *
 * These APIs are used to manage a pool of local neighbor_id numbers
 * that are associated with client instances.  Port numbers
 * are allocated for use and freed when the client instance
 * is torn down.
 *
 * The pool of neighbor_id numbers is a range from a base neighbor_id
 * through a max number of neighbor_ids.  The base neighbor_id is reserved
 * for the control process.  The (base+1) through the last
 * neighbor_id  number are associated with the clients.
 *
 * This implementation keeps it __very simple__, the allocation
 * scheme increments a working neighbor_id number pointer.  Once the
 * neighbor_id pointer reaches the last neighbor_id number, it wraps back around
 * to (base+1).  The user must validate the socket_open() return
 * to ensure success.
 *
 * It is possible to improve upon this simplicity by inserting
 * logic to dynamically track neighbor_id number allocation and free.
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
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rfc4938_types.h"
#include "rfc4938_neighbor_manager.h"


/* utest conditional */
#define NEIGHBOR_TESTING    ( 1 )




/*
 * The list of neighbors
 */
static rfc4938_neighbor_element_t *neighbor_head = NULL;





/*
 * print the requested neighbor id
 *
 * Description:
 *     Prints the requested active neighbor info to stdout.
 *
 * Inputs:
 *     neighbor_id - id number of the neighbor to print
 *
 * Outputs:
 *     Neighbor ID, address, and port
 * Returns:
 *     void
 */
void
neighbor_print (UINT32_t neighbor_id)
{
    rfc4938_neighbor_element_t *tmp;

    tmp = neighbor_head;

    while (tmp) {
        if (tmp->neighbor_id == neighbor_id) {

            if (tmp->state == ACTIVE) {
                printf("\nNeighbor ID %u  0x%x-%u  \n",
                          tmp->neighbor_id,
                          tmp->neighbor_addr,
                          tmp->neighbor_port);
                break;
            } else {

                printf("Neighbor ID %u is inactive \n",
                          tmp->neighbor_id);
                break;
            }
        }

        /* move to the next element */
        tmp = tmp->next;
    }
    printf("\n");

    return;
}


/*
 * print all active neighbors
 *
 * Description:
 *     Prints all active neighbor info to stdout.
 *
 * Inputs:
 *     void
 *
 * Outputs:
 *     Prints neighbor ID and ACTIVE/INACTIVE state
 *     
 * Returns:
 *     void
 *
 */
void
neighbor_print_all (void)
{
    rfc4938_neighbor_element_t *tmp;

    tmp = neighbor_head;
    
    printf("Neighbor\tIP\t\t Active\n");
    while (tmp) {
        if (tmp->state == ACTIVE) {
            if (tmp->neighbor_addr != 0 ) {
                printf("%u\t\t%s\t ", tmp->neighbor_id, 
                       inet_ntoa(*(struct in_addr *)&(tmp->neighbor_addr)));

                if (tmp->session_state == ACTIVE) {
                     printf("ACTIVE\n");
                } else {
                    printf("INACTIVE\n");
                }
            }
        }
        /* move to the next element */
        tmp = tmp->next;
    }
    printf("\n");

    return;
}


/*
 * print all active neighbors to a string
 *
 * Description:
 *     Prints all active neighbor info to a string.
 *
 * Inputs:
 *     *dgram: pointer to string of length SHOWLEN
 *
 * Outputs:
 *     dgram: formated string with neighbor information
 *
 * Returns:
 *
 */
void
neighbor_print_all_string (char **dgram)
{
    rfc4938_neighbor_element_t *tmp;
    tmp = neighbor_head;
    char tmp_str[LNLEN];
    
    sprintf(*dgram, "Neighbor\tIP\t\t Active\n");
    while (tmp) {
        if (tmp->state == ACTIVE) {
            if (tmp->neighbor_addr != 0 ) {
                sprintf(tmp_str, "%u\t\t%s\t ", tmp->neighbor_id, 
                        inet_ntoa(*(struct in_addr *)&(tmp->neighbor_addr)));
		strncat(*dgram, tmp_str, strlen(tmp_str));

                if (tmp->session_state == ACTIVE) {
                    sprintf(tmp_str, "ACTIVE\n");
		    strncat(*dgram, tmp_str, strlen(tmp_str));
                } else {
                    sprintf(tmp_str, "INACTIVE\n");
		    strncat(*dgram, tmp_str, strlen(tmp_str));
		}
            }
        }
        /* move to the next element */
        tmp = tmp->next;
    }
    strncat(*dgram, "\n", strlen("\n"));

    return;
}


/*
 * Allocate a neighbor id
 *
 * Description:
 *     Allocates the requested neighbor id if it is free.
 *
 * Inputs:
 *     neighbor_id      Requested neighbor ID
 *     neighbor_addr    Neighbor's ip address
 *     neighbor_port    Neighbor's port number
 *
 * Outputs:
 *
 * Returns:
 *     SUCCESS
 *     ENODEV
 */
int
neighbor_allocate (
         UINT32_t neighbor_id,
         UINT32_t neighbor_addr,
         UINT16_t neighbor_port)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    tmp = neighbor_head;

    if (tmp == NULL) {
        return (ENODEV);        
    }

    rc = ENODEV;
    while (tmp) {

        if (tmp->state == INACTIVE &&
            tmp->neighbor_id == neighbor_id) {

            tmp->neighbor_addr = neighbor_addr;
            tmp->neighbor_port = neighbor_port;

            tmp->state = ACTIVE;
            rc = SUCCESS;
            break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}


/*
 * Release a neighbor id
 *
 * Description:
 *     Releases a previously allocated session.
 *
 * Inputs:
 *     neighbor_id      Requested neighbor ID
 *
 * Outputs:
 *
 * Returns:
 *     SUCCESS
 *     ENODEV
 */
int
neighbor_release (
           UINT32_t neighbor_id)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    tmp = neighbor_head;

    rc = ENODEV;
    while (tmp) {

        if (tmp->state == ACTIVE &&
            tmp->neighbor_id == neighbor_id) {

            tmp->neighbor_addr = 0;
            tmp->neighbor_port = 0;
            tmp->send_session_start_ready = 0;
            
            tmp->state = INACTIVE;
            rc = SUCCESS;
            break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}


/*
 * Neighbor query
 *
 * Description:
 *     Returns a copy of the neighbor data if active.
 *
 * Inputs:
 *     neighbor_id      Requested neighbor ID
 *     p2neighbor       Pointer to data to receive the data
 *
 * Outputs:
 *     p2neighbor       Updated with the copied data.
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_query (
           UINT32_t neighbor_id,
           rfc4938_neighbor_element_t *p2neighbor)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    if (p2neighbor == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {

        if (tmp->state == ACTIVE &&
            tmp->neighbor_id == neighbor_id) {

            memcpy(p2neighbor, tmp, sizeof(rfc4938_neighbor_element_t));

            rc = SUCCESS;
            break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}


/*
 * Neighbor pointer
 *
 * Description:
 *     Returns a pointer to the neighbor data.
 *
 * Inputs:
 *     neighbor_id      Requested neighbor ID
 *     p2neighbor       Pointer to receive the pointer
 *
 * Outputs:
 *     p2neighbor       Updated with the pointer.
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_pointer (
           UINT32_t neighbor_id,
           rfc4938_neighbor_element_t **p2neighbor)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;
    
    if (p2neighbor == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {
        if (tmp->state == ACTIVE &&
            tmp->neighbor_id == neighbor_id) {

	  *p2neighbor = tmp;
	  
	  rc = SUCCESS;
	  break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}

/*
 * Neighbor pointer by address
 *
 * Description:
 *     Returns a pointer to the neighbor data.
 *
 * Inputs:
 *     ip_addr          Requested ip address
 *     p2neighbor       Pointer to receive the pointer
 *
 * Outputs:
 *     p2neighbor       Updated with the pointer.
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_pointer_by_addr (UINT32_t ip_addr, 
                          rfc4938_neighbor_element_t **p2neighbor)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    if (p2neighbor == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {
        
        if (tmp->state == ACTIVE &&
            tmp->neighbor_addr == ip_addr) {

	  *p2neighbor = tmp;
	  
	  rc = SUCCESS;
	  break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}


/*
 * Neighbor pointer by pid
 *
 * Description:
 *     Returns a pointer to the neighbor data.
 *
 * Inputs:
 *     pid              Requested pid
 *     p2neighbor       Pointer to receive the pointer
 *
 * Outputs:
 *     p2neighbor       Updated with the pointer.
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_pointer_by_pid (pid_t pid, 
                         rfc4938_neighbor_element_t **p2neighbor)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    if (p2neighbor == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {

        if (tmp->state == ACTIVE &&
            tmp->pid == pid) {

	  *p2neighbor = tmp;
	  
	  rc = SUCCESS;
	  break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}

/*
 * Neighbor pointer by port
 *
 * Description:
 *     Returns a pointer to the neighbor data.
 *
 * Inputs:
 *     port             Requested port
 *     p2neighbor       Pointer to receive the pointer
 *
 * Outputs:
 *     p2neighbor       Updated with the pointer.
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_pointer_by_port (UINT16_t port, 
                          rfc4938_neighbor_element_t **p2neighbor)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    if (p2neighbor == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {

        if (tmp->state == ACTIVE &&
            tmp->neighbor_port == port) {

	  *p2neighbor = tmp;
	  
	  rc = SUCCESS;
	  break;

        } else {
            /* move to the next element */
            tmp = tmp->next;
        }
    }

    return (rc);
}

/*
 * Neighbor toggle all
 *
 * Description:
 *     Changes state of all neighbors according to supplied function pointer
 *
 * Inputs:
 *     *pt2func         Function pointer to initiate or terminate
 *
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENODEV
 */
int
neighbor_toggle_all (
    void (*pt2func)(rfc4938_neighbor_element_t *, UINT16_t, UINT16_t),
    UINT16_t credit_scalar)
{
    rfc4938_neighbor_element_t *tmp;
    int rc;

    if (pt2func == NULL) {
        return (ERANGE);
    }

    rc = ENODEV;
    tmp = neighbor_head;

    while (tmp) {

        if (tmp->state == ACTIVE) {
            pt2func(tmp, 0, credit_scalar);
	}

        tmp = tmp->next;
    }
    rc = SUCCESS;
    return (rc);
}


/*
 * Initialize neighbor management
 *
 * Description:
 *     Initializes the neighbor management facility.
 *
 * Inputs:
 *     max_neighbors      The maximum number of meighbors
 *                        that can be configured.
 *
 * Outputs:
 *
 * Returns:
 *     SUCCESS
 *     ERANGE
 *     ENOMEM
 */
int
neighbor_init (
           UINT16_t max_neighbors)
{
    rfc4938_neighbor_element_t *tmp;
    UINT32_t i;
    int rc;

#define RC4938_MIN_SESSIONS  ( 5 )

    if (max_neighbors < RC4938_MIN_SESSIONS) {
        return (ERANGE);
    }

    rc = SUCCESS;
    tmp = neighbor_head;

    for (i=0; i<max_neighbors; i++) {

        tmp = malloc(sizeof(rfc4938_neighbor_element_t));
        if (tmp == NULL) {
            printf("rfc4938: Error, malloc fault \n");
            return (ENOMEM);
        }

        tmp->state = INACTIVE;
        tmp->session_state = INACTIVE;
        tmp->neighbor_id = i;
        tmp->neighbor_addr = 0;
        tmp->neighbor_port = 0;
        tmp->send_session_start_ready = 0;

        /* insert the next element */
        tmp->next = neighbor_head;
        neighbor_head = tmp;
    }

    return (rc);
}


