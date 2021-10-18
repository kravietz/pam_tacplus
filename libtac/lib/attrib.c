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

#include <stdio.h>
#include <string.h>

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
            total_len = TAC_PLUS_ATTRIB_MAX_LEN;
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

static int _tac_add_attrib_pair(struct tac_attrib **head, char *name, char separator, char *value, int truncate)
{
    struct tac_attrib *current;
    unsigned int attr_cnt = 0;
    size_t total_len;
    int check;
    total_len = strlen(name) + sizeof(separator) + strlen(value);
    check = _tac_attrib_checks(name, separator, value, total_len, truncate);
    if (check != 0)
        return check;
    if (total_len > TAC_PLUS_ATTRIB_MAX_LEN)
        total_len = TAC_PLUS_ATTRIB_MAX_LEN;

    if (*head == NULL)
    {
        *head = (struct tac_attrib *)xcalloc(1, sizeof(struct tac_attrib));
        current = *head;
        current->attr_len = total_len;
        current->attr = (char *)xcalloc(1, total_len + 1);
        snprintf(current->attr, total_len + 1, "%s%c%s", name, separator, value);
        current->next = NULL;
        return 0;
    }

    current = *head;

    while (current->next != NULL)
    {
        current = current->next;
        attr_cnt++;
    }

    if (attr_cnt + 1 >= TAC_PLUS_ATTRIB_MAX_CNT)
    { /* take new attrib into account */
        TACSYSLOG(LOG_WARNING,
                  "%s: Maximum number of attributes exceeded, skipping",
                  __FUNCTION__);
        return LIBTAC_STATUS_ATTRIB_TOO_MANY;
    }

    /* allocate buffer for the next tac_attrib chain link */
    current->next = (struct tac_attrib *)xcalloc(1, sizeof(struct tac_attrib));

    /* fill the block */
    current->next->attr_len = total_len;
    /* allocate buffer for the key=value ASCIIZ string */
    current->next->attr = (char *)xcalloc(1, total_len + 1);
    /* write the attribute=value into the buffer */
    if (snprintf(current->next->attr, total_len + 1, "%s%c%s", name, separator, value) < (int)total_len)
    {
        TACSYSLOG(LOG_ERR,
                  "%s: short snprintf write (wanted %lu bytes)",
                  __FUNCTION__, total_len);
    }
    current->next->next = NULL; /* make sure next pointer is null so that it will be allocated on next call */

    return 0;
}

int tac_add_attrib(struct tac_attrib **attr, char *name, char *value)
{
    return tac_add_attrib_pair(attr, name, '=', value);
}

int tac_add_attrib_pair(struct tac_attrib **attr, char *name, char sep, char *value)
{
    return _tac_add_attrib_pair(attr, name, sep, value, 0);
}

int tac_add_attrib_truncate(struct tac_attrib **attr, char *name, char *value)
{
    return tac_add_attrib_pair_truncate(attr, name, '=', value);
}

int tac_add_attrib_pair_truncate(struct tac_attrib **attr, char *name, char sep, char *value)
{
    return _tac_add_attrib_pair(attr, name, sep, value, 1);
}

void tac_free_attrib(struct tac_attrib **attr)
{
    struct tac_attrib *a;
    struct tac_attrib *b;

    if (*attr == NULL)
        return;

    // 'a' is initialized in the loop below
    b = *attr;

    /* find last allocated block */
    do
    {
        a = b;
        b = a->next;
        free(a->attr);
        free(a);
    } while (b != NULL);

    *attr = NULL;
}
