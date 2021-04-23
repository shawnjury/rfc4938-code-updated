/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938_types.h
 * version: 1.0
 * date: October 21, 2007
 *
 * Copyright (C), 2007-2008 by cisco Systems, Inc.
 *
 * ===========================
 *
 * This file provides a set of typedefs used to promote
 * variable consistency.  It also includes the C standard
 * errno.h file and defines SUCCESS for return code
 * consistency.
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


#ifndef __RFC4938_TYPES_H__
#define __RFC4938_TYPES_H__


#include <errno.h>
#include "pppoe_types.h"

/* errno does not provide success */
#ifndef SUCCESS
#define SUCCESS 0
#endif

#endif

