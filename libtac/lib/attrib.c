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

void tac_add_attrib(struct tac_attrib **attr, char *name, char *value) {
    tac_add_attrib_pair(attr, name, '=', value);
}

void tac_add_attrib_pair(struct tac_attrib **attr, char *name, char sep, char *value) {
    struct tac_attrib *a;
    u_char l1 = (u_char) strlen(name);
    u_char l2;
    int total_len;
    
    if (value == NULL) {
        l2 = 0;
    } else {
        l2 = (u_char) strlen(value);
    }
    total_len = l1 + l2 + 1; /* "name" + "=" + "value" */

    if (total_len > 255) {
        TACSYSLOG((LOG_WARNING,\
            "%s: attribute `%s' total length exceeds 255 characters, skipping",\
            __FUNCTION__, name))
        return;
    }
    
    /* initialize the list if application passed us a null pointer */
    if(*attr == NULL) {
        *attr = (struct tac_attrib *) xcalloc(1, sizeof(struct tac_attrib));
        a = *attr;
    } else {
        /* find the last allocated block */
        a = *attr;
        while(a->next != NULL)
            a = a->next; /* a holds last allocated block */

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
}

void tac_free_attrib(struct tac_attrib **attr) {
    struct tac_attrib *a;
    struct tac_attrib *b;

    if(*attr == NULL)
            return;

    a  = b = *attr;
    
    /* find last allocated block */
    do {
        a = b;
        b = a->next;
        free(a->attr);
        free(a);
    } while (b != NULL);

    *attr = NULL;
}
