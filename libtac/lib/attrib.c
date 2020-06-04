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

#include "libtac.h"
#include "xalloc.h"

static int _tac_add_attrib_pair(struct tac_attrib **attr, char *name,
                                char sep, char *value, int truncate)
{
    struct tac_attrib *a;
    size_t l1 = strlen(name);
    size_t l2;
    unsigned int attr_cnt = 0;
    size_t total_len;

    if (l1 > TAC_PLUS_ATTRIB_MAX_LEN-1) { /* take sep into account */
        TACSYSLOG(LOG_WARNING,\
            "%s: attribute `%s' exceeds max. %d characters, skipping",\
            __FUNCTION__, name, TAC_PLUS_ATTRIB_MAX_LEN-1);
        return LIBTAC_STATUS_ATTRIB_TOO_LONG;
    }

    total_len = l1 + 1; /* "name" + "sep" */

    if (value == NULL) {
        l2 = 0;
    } else {
        l2 = strlen(value);
    }

    if (l2 > TAC_PLUS_ATTRIB_MAX_LEN-total_len) {
        if (truncate) {
            l2 = TAC_PLUS_ATTRIB_MAX_LEN-total_len;
        }
        else {
            TACSYSLOG(LOG_WARNING,\
                "%s: attribute `%s' total length exceeds %d characters, skipping",\
                __FUNCTION__, name, TAC_PLUS_ATTRIB_MAX_LEN);
            return LIBTAC_STATUS_ATTRIB_TOO_LONG;
        }
    }

    total_len += l2;

    /* initialize the list if application passed us a null pointer */
    if(*attr == NULL) {
        *attr = (struct tac_attrib *) xcalloc(1, sizeof(struct tac_attrib));
        a = *attr;
    } else {
        /* find the last allocated block */
        a = *attr;
        while(a->next != NULL) {
            a = a->next; /* a holds last allocated block */
            attr_cnt++;
        }

        if (attr_cnt+1 >= TAC_PLUS_ATTRIB_MAX_CNT) { /* take new attrib into account */
            TACSYSLOG(LOG_WARNING,\
                "%s: Maximum number of attributes exceeded, skipping",\
                __FUNCTION__);
            return LIBTAC_STATUS_ATTRIB_TOO_MANY;
        }

        a->next = (struct tac_attrib *) xcalloc(1, sizeof(struct tac_attrib));
        a = a->next; /* set current block pointer to the new one */
    }

    if ( sep != '=' && sep != '*' ) {
        sep = '=';
    }

    /* fill the block */
    a->attr_len=total_len;
    a->attr = (char *) xcalloc(1, total_len+1);
    bcopy(name, a->attr, l1);    /* paste name */
    *(a->attr+l1)=sep;           /* insert seperator "[=*]" */
    if (value != NULL) {
        bcopy(value, (a->attr+l1+1), l2); /* paste value */
    }
    *(a->attr+total_len) = '\0';      /* add 0 for safety */
    a->next = NULL; /* make sure it's null */

    return 0;
}

int tac_add_attrib(struct tac_attrib **attr, char *name, char *value) {
    return tac_add_attrib_pair(attr, name, '=', value);
}

int tac_add_attrib_pair(struct tac_attrib **attr, char *name, char sep, char *value) {
    return _tac_add_attrib_pair(attr, name, sep, value, 0);
}

int tac_add_attrib_truncate(struct tac_attrib **attr, char *name, char *value) {
    return tac_add_attrib_pair_truncate(attr, name, '=', value);
}

int tac_add_attrib_pair_truncate(struct tac_attrib **attr, char *name, char sep, char *value) {
    return _tac_add_attrib_pair(attr, name, sep, value, 1);
}

void tac_free_attrib(struct tac_attrib **attr) {
    struct tac_attrib *a;
    struct tac_attrib *b;

    if(*attr == NULL)
            return;

	// 'a' is initialized in the loop below
	b = *attr;

    /* find last allocated block */
    do {
        a = b;
        b = a->next;
        free(a->attr);
        free(a);
    } while (b != NULL);

    *attr = NULL;
}
