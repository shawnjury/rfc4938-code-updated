/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938_debug.h
 * version: 1.0
 * date: October 4, 2007
 *
 * Copyright (C), 2007-2008 by Cisco Systems, Inc.
 *
 * ===========================
 *
 * Debug definitions
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

#ifndef  __H_RFC4938_DEBUG_H__
#define  __H_RFC4938_DEBUG_H__

#include "rfc4938_types.h"
#include "stdio.h"

#include <syslog.h>

#define RFC4938_DEBUG_ENABLED ( 1 )  //enables debugs
//#undef RFC4938_DEBUG_ENABLED       //disables all debugs


// debug bit positions in global debug mask
#define  RFC4938_ALL_DEBUG                     ( 0xffffffff)
#define  RFC4938_G_PACKET_DEBUG                ( 0x04 )
#define  RFC4938_G_EVENT_DEBUG                 ( 0x08 )
#define  RFC4938_G_ERROR_DEBUG                 ( 0x10 )


#define RFC4938_DEBUG_PRINT(myargs...) \
    printf(myargs); \
    syslog(LOG_INFO, myargs);

/*
 *  macro packet debug
 */
#ifdef RFC4938_DEBUG_ENABLED
#define RFC4938_DEBUG_PACKET(args...)  \
        if (is_rfc4938_debug_flag_set(     \
                RFC4938_G_PACKET_DEBUG)){ RFC4938_DEBUG_PRINT(args)}
#else
#define RFC4938_DEBUG_PACKET(args...)  ((void)0)
#endif

/*
 *  macro event debug
 */
#ifdef RFC4938_DEBUG_ENABLED
#define RFC4938_DEBUG_EVENT(args...)  \
        if (is_rfc4938_debug_flag_set(     \
                RFC4938_G_EVENT_DEBUG)){ RFC4938_DEBUG_PRINT(args)}
#else
#define RFC4938_DEBUG_EVENT(args...)  ((void)0)
#endif


/*
 *  macro error debug
 */
#ifdef RFC4938_DEBUG_ENABLED
#define RFC4938_DEBUG_ERROR(args...)  \
        if (is_rfc4938_debug_flag_set(     \
                RFC4938_G_ERROR_DEBUG)){ RFC4938_DEBUG_PRINT(args)}
#else
#define RFC4938_DEBUG_ERROR(args...)  ((void)0)
#endif


extern void rfc4938_set_debug_mask (UINT32_t mask);
extern void rfc4938_clear_debug_mask (UINT32_t mask);
extern int is_rfc4938_debug_flag_set (UINT32_t flag);
extern void rfc4938_debug_all (int flag);


#endif
