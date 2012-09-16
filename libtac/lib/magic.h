/* magic.h - PPP Magic Number definitions.
 *
 * Copyright (C) 1989 Carnegie Mellon University.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */

#ifndef _MAGIC_H
#define _MAGIC_H

#include "libtac.h"

__BEGIN_DECLS
void magic_init __P((void));	/* Initialize the magic number generator */
u_int32_t magic __P((void));	/* Returns the next magic number */
__END_DECLS

#endif
