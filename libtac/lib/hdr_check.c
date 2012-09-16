/* hdr_check.c - Perform basic sanity checks on received packet.
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

#include "messages.h"
#include "libtac.h"

/* Checks given reply header for possible inconsistencies:
 *  1. reply type other than expected
 *  2. sequence number other than 2 or 4
 *  3. session_id different from one sent in request
 * Returns pointer to error message
 * or NULL when the header seems to be correct
 */
char *_tac_check_header(HDR *th, int type) {
    if(th->type != type) {
        TACSYSLOG((LOG_ERR,\
            "%s: unrelated reply, type %d, expected %d",\
            __FUNCTION__, th->type, type))
        return protocol_err_msg;
    } else if((th->seq_no != 2) && (th->seq_no != 4)) {
        TACSYSLOG((LOG_ERR, "%s: not a reply - seq_no %d != {2,4}",\
            __FUNCTION__, th->seq_no))
        return protocol_err_msg;
    } /* else if(ntohl(th->session_id) != session_id) {
        TACSYSLOG((LOG_ERR,\
            "%s: unrelated reply, received session_id %d != sent %d",\
            __FUNCTION__, ntohl(th->session_id), session_id))
        return protocol_err_msg;
    } */
    
    return NULL; /* header is ok */    
} /* check header */
