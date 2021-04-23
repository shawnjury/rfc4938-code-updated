/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938_debug.c
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
#include "rfc4938_debug.h"
#define RFC4938_DEFAULT_DEBUG ( 0 )

static UINT32_t rfc4938_debugs = RFC4938_DEFAULT_DEBUG;

/*
 * Name
 *    void
 *    rfc4938_set_debug_mask(UINT32_t mask)
 *
 * Description
 *    Sets specific debug flags
 *
 * Parameters
 *    mask       bit mask indicating which flags to manipulate.
 *
 * Returns
 *    none
 *
 * Notes
 *    To set all flags      rfc4938_set_debug_mask( -1 )
 *
 *    Set all flags to 0    rfc4938_set_debug_mask( 0 )
 *
 */
void
rfc4938_set_debug_mask (UINT32_t mask)
{
    if (mask == 0) {
        rfc4938_debugs = 0;
    } else {
        rfc4938_debugs |= mask;
    }
    return;
}


/*
 * Name
 *     void
 *     rfc4938_clear_debug_mask(UINT32_t mask)
 *
 * Description
 *     Clears specific debug flags
 *
 * Parameters
 *     mask               bit mask indicating which flags to manipulate.
 *
 * Returns
 *     none
 *
 * Notes
 *     To clear all flags    rfc4938_clear_debug_mask( -1 )
 *
 *     Set all flags to 0    rfc4938_clear_debug_mask( 0 )
 *
 */
void
rfc4938_clear_debug_mask (UINT32_t mask)
{
    if (mask == 0) {
        rfc4938_debugs = 0;
    } else {
        rfc4938_debugs &= ~mask;
    }
    return;
}


/*
 * Name
 *     boolean
 *     is_rfc4938_debug_flag_set(UINT32_t flag)
 *
 * Description
 *     returns status of debug flag(s)
 *
 * Parameters
 *     mask               debug flag(s).
 *
 * Returns
 *     TRUE  flag(s) set
 *     FALSE flag(s) clear
 *
 */
int
is_rfc4938_debug_flag_set (UINT32_t flag)
{
    return ( ((rfc4938_debugs & flag) ? 1 : 0) );
}


/*
 * Name
 *     void
 *     rfc4938_debug_all(boolean flag)
 *
 * Description
 *     This function should be used to set or clear all RFC4938 debugs
 *
 * Parameter
 *     flag              TRUE to set all debugs
 *                       FALSE to clear all debugs
 * Returns
 *     none
 *
 */
void
rfc4938_debug_all (int flag)
{
    if (flag) {
        rfc4938_debugs = RFC4938_ALL_DEBUG;
    } else {
        rfc4938_debugs = RFC4938_DEFAULT_DEBUG;
    }
}
