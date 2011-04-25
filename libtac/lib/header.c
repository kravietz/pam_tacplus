/* header.c - Create pre-filled header for TACACS+ request.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <kravietz@ceti.pl> and
 * Jeroen Nijhof <jeroen@nijhofnet.nl>
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

#include "tacplus.h"
#include "libtac.h"
#include "xalloc.h"
#include "magic.h"

/* Miscellaneous variables that are global, because we need
 * store their values between different functions and connections.
 */
/* Session identifier. */
int session_id;

/* Encryption flag. */
int tac_encryption;

/* Pointer to TACACS+ shared secret string. */
char *tac_secret = "";

/* Pointer to TACACS+ shared login string. */
char *tac_login = "pap";

/* Returns pre-filled TACACS+ packet header of given type.
 * 1. you MUST fill th->datalength and th->version
 * 2. you MAY fill th->encryption
 * 3. you are responsible for freeing allocated header 
 * By default packet encryption is enabled. The version
 * field depends on the TACACS+ request type and thus it
 * cannot be predefined.
 */
HDR *_tac_req_header(u_char type) {
 	HDR *th;

 	th=(HDR *) xcalloc(1, TAC_PLUS_HDR_SIZE);

 	/* preset some packet options in header */
 	th->type=type;
 	th->seq_no=1; /* always 1 for request */
 	th->encryption=TAC_PLUS_ENCRYPTED;
 
 	/* make session_id from pseudo-random number */
 	session_id = magic();
 	th->session_id = htonl(session_id);

 	return(th);
}
