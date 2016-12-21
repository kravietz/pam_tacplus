/* parse.c - Callback for dispatching received packets
 *
 * Copyright (C) 2016, Philip Prindeville <philipp@redfish-solutions.com>
 * Copyright (C) 2016, Brocade Communications Systems, Inc.
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

#include "libtac.h"

void tac_parse_pkt(struct tac_session *sess, struct cb_ctx *ctx, u_char *pkt, unsigned len)
{
    HDR *th = (HDR *)pkt;
    int status = -1;
    struct areply re = { 0 };

    switch (th->type) {
    case TAC_PLUS_AUTHEN:
	TACDEBUG(LOG_DEBUG, "session %p got authen %u bytes", sess, len);
	status = tac_authen_parse(sess, &re, pkt, len);
	break;

    case TAC_PLUS_AUTHOR:
	TACDEBUG(LOG_DEBUG, "session %p got author %u bytes", sess, len);
	status = tac_author_parse(sess, pkt, len, &re);
	break;

    case TAC_PLUS_ACCT:
	TACDEBUG(LOG_DEBUG, "session %p got account %u bytes", sess, len);
	status = tac_acct_parse(sess, pkt, len, &re);
	break;

    default:
	TACDEBUG(LOG_INFO, "session %p got %u byte packet of %02x type; ignoring", \
	    sess, len, th->type);

	break;
    }

    if (sess->response_cb) {
	TACDEBUG(LOG_DEBUG, "session %p user callback", sess);
	sess->response_cb(sess, ctx, status, th->type, &re);
    }

    tac_free_attrib(&re.attr);
    free(re.msg);
    free(re.data);
}

