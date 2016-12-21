/* header.c - Create pre-filled header for TACACS+ request.
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

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#include "magic.h"

int tac_debug_enable = 0;
int tac_readtimeout_enable = 0;

/* Returns pre-filled TACACS+ packet header of given type.
 * 1. you MUST fill th->datalength and th->version
 * 2. you MAY fill th->encryption
 * 3. you are responsible for freeing allocated header 
 * By default packet encryption is enabled. The version
 * field depends on the TACACS+ request type and thus it
 * cannot be predefined.
 */
HDR *_tac_req_header(struct tac_session *sess, u_char type, bool cont_session) {
    HDR *th;

    th=(HDR *) xcalloc(1, TAC_PLUS_HDR_SIZE);

    /* preset some packet options in header */
    th->type=type;
    th->seq_no=++sess->seq_no;
    th->encryption=TAC_PLUS_ENCRYPTED_FLAG;
 
    /* make session_id from pseudo-random number */
    if (!cont_session) {
        tac_session_new_session_id(sess);
    }
    th->session_id = htonl(sess->tac_session_id);

    return th;
}
