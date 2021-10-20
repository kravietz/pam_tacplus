/* xalloc.c - Failsafe memory allocation functions.
 *            Taken from excellent glibc.info ;)
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "xstrncpy.h"

#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif

/*
 safe string copy that aborts when destination buffer is too small
 */
char *xstrncpy(char *dst, const char *src, size_t dst_size) {
    if (dst == NULL) {
        TACSYSLOG(LOG_ERR, "xstrncpy(): dst == NULL");
#ifdef HAVE_ABORT
        abort();
#else
        exit(EXIT_FAILURE);
#endif
    }
	if (src == NULL) {
        TACSYSLOG(LOG_ERR, "xstrncpy(): src == NULL");
#ifdef HAVE_ABORT
        abort();
#else
        exit(EXIT_FAILURE);
#endif
    }
	if (!dst_size)
		return NULL;

	if (strlen(src) >= dst_size) {
        TACSYSLOG(LOG_ERR, "xstrncpy(): argument too long, aborting");
#ifdef HAVE_ABORT
        abort();
#else
        exit(EXIT_FAILURE);
#endif
    }
#ifdef HAVE_STRLCPY
	if(strlcpy(dst, src, dst_size) > dst_size)
	{
		TACSYSLOG(LOG_ERR, "xstrcpy(): strlcpy refused to copy string longer than destination, aborting");
#ifdef HAVE_ABORT
		abort();
#else
		exit(EXIT_FAILURE);
#endif
	}
	return dst;
#else
	return strncpy(dst, src, dst_size);
#endif
}
