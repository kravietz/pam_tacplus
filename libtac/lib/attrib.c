/* attrib.c - Procedures for handling internal list of attributes
 *               for accounting and authorization functions.
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

#include <stdio.h>
#include <string.h>

#include "gl_array_list.h"
#include "gl_list.h"
#include "gl_xlist.h"

#include "libtac.h"
#include "xalloc.h"

static int _tac_attrib_checks(char *name, char separator, char *value, size_t total_len, int truncate)
{
    if (separator != '=' && separator != '*')
    {
        separator = '=';
        TACSYSLOG(LOG_WARNING,
                  "%s: Separator '%c' not allowed, replaced with '='",
                  __FUNCTION__, separator);
    }

    // https://datatracker.ietf.org/doc/html/rfc8907#section-6.1
    total_len = strlen(name) + sizeof(separator) + strlen(value);
    if (total_len > TAC_PLUS_ATTRIB_MAX_LEN)
    {

        if (truncate)
        {
            TACSYSLOG(LOG_WARNING,
                      "%s: attribute `%s' exceeds max. %d characters, truncating",
                      __FUNCTION__, name, TAC_PLUS_ATTRIB_MAX_LEN - 1);
        }
        else
        {
            TACSYSLOG(LOG_WARNING,
                      "%s: attribute `%s' exceeds max. %d characters, ignoring",
                      __FUNCTION__, name, TAC_PLUS_ATTRIB_MAX_LEN - 1);
            return LIBTAC_STATUS_ATTRIB_TOO_LONG;
        }
    }

    return 0;
}

static int _tac_add_attrib_pair(gl_list_t attr, char *name, char separator, char *value, int truncate)
{
    struct tac_attrib *current;
    size_t total_len;
    int check;
    char *buf = NULL;
    total_len = strlen(name) + sizeof(separator) + strlen(value);
    check = _tac_attrib_checks(name, separator, value, total_len, truncate);
    if (check != 0)
        return check;
    if (total_len > TAC_PLUS_ATTRIB_MAX_LEN)
        total_len = TAC_PLUS_ATTRIB_MAX_LEN;

    buf = xcalloc(1, total_len+1);

    check = snprintf(buf, total_len+1, "%s%c%s", name, separator, value);
    if(check < (int)total_len)
    {
        TACSYSLOG(LOG_ERR,
                  "%s: short snprintf write: wanted %lu bytes, wrote %d",
                  __FUNCTION__, total_len, check);
    }

    if (attr.count + 1 >= TAC_PLUS_ATTRIB_MAX_CNT)
    { /* take new attrib into account */
        TACSYSLOG(LOG_WARNING,
                  "%s: Maximum number of attributes exceeded, skipping",
                  __FUNCTION__);
        return LIBTAC_STATUS_ATTRIB_TOO_MANY;
    }

    gl_list_add_last(attr, buf);

    return 0;
}

int tac_add_attrib(gl_list_t attr, char *name, char *value)
{
    return tac_add_attrib_pair(attr, name, '=', value);
}

int tac_add_attrib_pair(gl_list_t attr, char *name, char sep, char *value)
{
    return _tac_add_attrib_pair(attr, name, sep, value, 0);
}

int tac_add_attrib_truncate(gl_list_t attr, char *name, char *value)
{
    return tac_add_attrib_pair_truncate(attr, name, '=', value);
}

int tac_add_attrib_pair_truncate(gl_list_t attr, char *name, char sep, char *value)
{
    return _tac_add_attrib_pair(attr, name, sep, value, true);
}

void tac_free_attrib(gl_list_t attr)
{
    const void *element;
    gl_list_iterator_t attributes_iterator = gl_list_iterator(attr);
	while(gl_list_iterator_next(&attributes_iterator, &element, NULL)) {
		free(element);
	}
    gl_list_iterator_free(&attributes_iterator);
    gl_list_free(attr);
}
