/* md5.h - header file for implementation of MD5
 * 
 * Copyright (C) 1990, RSA Data Security, Inc.
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

#ifndef __MD5_INCLUDE__

#include "libtac.h"

/* typedef a 32-bit type */
typedef unsigned int UINT4;

/* Data structure for MD5 (Message-Digest) computation */
typedef struct {
    UINT4 i[2];               /* number of _bits_ handled mod 2^64 */
    UINT4 buf[4];             /* scratch buffer */
    unsigned char in[64];     /* input buffer */
    unsigned char digest[16]; /* actual digest after MD5Final call */
} MD5_CTX;

__BEGIN_DECLS
void MD5Init __P((MD5_CTX*));
void MD5Update __P((MD5_CTX*, unsigned char*, UINT4));
void MD5Final __P((unsigned char[], MD5_CTX*));
__END_DECLS

#define MD5_LEN 16

#define __MD5_INCLUDE__
#endif /* __MD5_INCLUDE__ */
