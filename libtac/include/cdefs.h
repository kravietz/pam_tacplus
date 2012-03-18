/* cdefs.h
 * 
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
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

#ifndef _CDEFS_H
#define _CDEFS_H

#undef __P
#if defined(__STDC__) || defined(__cplusplus)
#define __P(p) p
#else
#define __P(p)
#endif
#define	_PTR      void *
#define	_ANDi     ,
#define	_NOARGS   void
#define	_CONST    const
#define	_VOLATILE volatile
#define	_SIGNED   signed
#define	_DOTS     , ...
#define	_VOID     void
#define	_EXFUN(name, proto) name proto
#define	_DEFUN(name, arglist, args) name(args)
#define	_DEFUN_VOID(name) name(_NOARGS)
#define	_CAST_VOID (void)
#ifndef	_LONG_DOUBLE
#define	_LONG_DOUBLE long double
#endif
#ifndef	_PARAMS
#define	_PARAMS(paramlist)		paramlist
#endif

/* Support gcc's __attribute__ facility.  */

#define _ATTRIBUTE(attrs) __attribute__ ((attrs))

#if defined(__cplusplus)
#define __BEGIN_DECLS extern "C" {
#define __END_DECLS }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif

#endif
