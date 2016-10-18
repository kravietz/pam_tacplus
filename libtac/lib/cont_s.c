/* cont_s.c - Send continue request to the server.
 * 
 * Copyright (C) 2010, Jeroen Nijhof <jeroen@jeroennijhof.nl>
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
#if defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/md5.h>
#else
# include "md5.h"
#endif

/* allocate and format an continue packet */
void tac_cont_send_pkt(struct tac_session *sess, const char *pass,
   u_char **_pkt, unsigned *_len) {

	HDR *th; /* TACACS+ packet header */
	struct authen_cont *tb; /* continue body */
	unsigned pass_len;
	u_char *pkt = NULL;
	unsigned pkt_total, pkt_len = 0;

	/* get size of submitted data */
	pass_len = strlen(pass);

	assert(pass_len <= UCHAR_MAX);

#define TAC_AUTHEN_CONT_FIXED_TOTAL \
	(TAC_PLUS_HDR_SIZE + TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE)

	/*
	 * precompute the buffer size so we don't need to keep resizing/copying it
	 */
	pkt_total = TAC_AUTHEN_CONT_FIXED_TOTAL + pass_len;

	/* build the packet */
	pkt = xcalloc(1, pkt_total);
	th = (HDR *)pkt;

	/* set some header options */
	th->version = TAC_PLUS_VER_0;
	th->type = TAC_PLUS_AUTHEN;
	th->seq_no = ++sess->seq_no;
	th->encryption =
			sess->tac_encryption ?
					TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;
	th->session_id = htonl(sess->tac_session_id);
	th->datalength = htonl(pkt_total - TAC_PLUS_HDR_SIZE);

	/* fixed part of tacacs body */
	tb = tac_hdr_to_body(th);
	tb->flags = 0;
	tb->user_msg_len = htons(pass_len);
	tb->user_data_len = 0;

	pkt_len = TAC_AUTHEN_CONT_FIXED_TOTAL;	/* reserve room for lengths */

#define PUTATTR(data, len) \
	bcopy(data, pkt + pkt_len, len); \
	pkt_len += len

	PUTATTR(pass, pass_len);

	assert(pkt_len == pkt_total);

	/* encrypt the body */
	_tac_crypt(sess, (u_char *)tb, th);

	*_pkt = pkt;
	*_len = pkt_total;
} /* tac_cont_send */

/* this function sends a continue packet do TACACS+ server, asking
 * for validation of given password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_WRITE_ERR
 *         LIBTAC_STATUS_WRITE_TIMEOUT  (pending impl)
 *         LIBTAC_STATUS_ASSEMBLY_ERR
 */
int tac_cont_send(struct tac_session *sess, int fd, const char *pass) {

	u_char *pkt = NULL;
	unsigned pkt_total = 0;
	int w, ret = 0;

	/* generate the packet */
	tac_cont_send_pkt(sess, pass, &pkt, &pkt_total);

	w = write(fd, pkt, pkt_total);
	if (w < 0 || (unsigned) w < pkt_total) {
		TACSYSLOG(
				LOG_ERR, "%s: short write on packet, wrote %d of %u: %m", __FUNCTION__, w, pkt_total);
		ret = LIBTAC_STATUS_WRITE_ERR;
	}

	free(pkt);

	TACDEBUG(LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret);

	return ret;
} /* tac_cont_send */

