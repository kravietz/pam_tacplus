/* authen_s.c - Send authentication request to the server.
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

#include "libtac.h"
#include "xalloc.h"

#if defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/md5.h>
#else
# include "md5.h"
#endif

/* assume digest points to a buffer MD5_LEN size */
static void
digest_chap(u_char digest[MD5_LBLOCK], uint8_t id,
            const char *pass, unsigned pass_len,
            const char *chal, unsigned chal_len) {

    MD5_CTX mdcontext;

    MD5_Init(&mdcontext);
    /* multiple calls to MD5Update() is still much less overhead
     * than allocating a buffer and marshalling contiguous data
     * for a single call.
     */
    MD5_Update(&mdcontext, &id, sizeof(id));
    MD5_Update(&mdcontext, (const u_char *)pass, pass_len);
    MD5_Update(&mdcontext, (const u_char *)chal, chal_len);
    MD5_Final(digest, &mdcontext);
}

uint8_t tac_get_authen_type(const char *login)
{
	if (login && *login) {
		if (!strcmp(login, "chap")) {
			return TAC_PLUS_AUTHEN_TYPE_CHAP;
		} else if (!strcmp(login, "login")) {
			return TAC_PLUS_AUTHEN_TYPE_ASCII;
		}
	}
	/* default to PAP */
	return TAC_PLUS_AUTHEN_TYPE_PAP;
}

const char *tac_get_authen_string(uint8_t type)
{
	const char *authen_types[5] = {
		"ascii", "pap", "chap", "arap", "mschap"
	};

	if (TAC_PLUS_AUTHEN_TYPE_ASCII <= type
	  && type <= TAC_PLUS_AUTHEN_TYPE_MSCHAP)
		return authen_types[type - TAC_PLUS_AUTHEN_TYPE_ASCII];

	return "???";
}

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT
 *             LIBTAC_STATUS_ASSEMBLY_ERR
 */
/* allocate and format an Authentication Start packet */
void tac_authen_send_pkt(struct tac_session *sess,
    const char *user, const char *pass, const char *tty,
    const char *r_addr, u_char action, u_char **_pkt, unsigned *_len) {

	HDR *th; /* TACACS+ packet header */
	struct authen_start *tb;     /* message body */
	unsigned user_len, pass_len, port_len, chal_len, r_addr_len, token_len;
	const char *chal = "1234123412341234";
	char *token = NULL;
	u_char *pkt = NULL;
	unsigned pkt_total, pkt_len = 0;
	const uint8_t id = 5;

	TACDEBUG(LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s",
					__FUNCTION__, user, tty, r_addr,
					(sess->tac_encryption) ? "yes" : "no");

	/* get size of submitted data */
	user_len = strlen(user);
	chal_len = strlen(chal);
	pass_len = strlen(pass);
	port_len = strlen(tty);
	r_addr_len = strlen(r_addr);

	if (sess->tac_authen_type == TAC_PLUS_AUTHEN_TYPE_CHAP) {
		u_char digest[MD5_LBLOCK];

		digest_chap(digest, id, pass, pass_len, chal, chal_len);

		token_len = sizeof(id) + chal_len + sizeof(digest);
		token = xcalloc(1, token_len);
		token[0] = id;
		memcpy(token + sizeof(id), chal, chal_len);
		memcpy(token + sizeof(id) + chal_len, digest, sizeof(digest));
	} else {
		token = xstrdup(pass);
		token_len = strlen(token);
	}

	assert(user_len <= UCHAR_MAX);
	assert(port_len <= UCHAR_MAX);
	assert(r_addr_len <= UCHAR_MAX);
	assert(token_len <= UCHAR_MAX);

#define TAC_AUTHEN_START_FIXED_TOTAL \
	(TAC_PLUS_HDR_SIZE + TAC_AUTHEN_START_FIXED_FIELDS_SIZE)

	/*
	 * precompute the buffer size so we don't need to keep resizing/copying it
	 */
	pkt_total = TAC_AUTHEN_START_FIXED_TOTAL +
		user_len + port_len + r_addr_len + token_len;

	pkt = xcalloc(1, pkt_total);
	th = (HDR *)pkt;

	/* set some header options */
	if (sess->tac_authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII) {
		th->version = TAC_PLUS_VER_0;
	} else {
		th->version = TAC_PLUS_VER_1;
	}
	th->type = TAC_PLUS_AUTHEN;
	th->seq_no = ++sess->seq_no;
	th->encryption =
			sess->tac_encryption ?
					TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;
	th->session_id = htonl(sess->tac_session_id);
	th->datalength = htonl(pkt_total - TAC_PLUS_HDR_SIZE);

	/* fixed part of tacacs body */
	tb = tac_hdr_to_body(th);
	tb->action = TAC_PLUS_AUTHEN_LOGIN;
	tb->priv_lvl = sess->tac_priv_lvl;
	if (sess->tac_authen_type == TAC_PLUS_AUTHEN_TYPE_PAP) {
		tb->authen_type =
				TAC_PLUS_AUTHEN_CHPASS == action ?
						TAC_PLUS_AUTHEN_TYPE_ASCII : TAC_PLUS_AUTHEN_TYPE_PAP;
	} else {
		tb->authen_type = sess->tac_authen_type;
	}
	tb->service = sess->tac_authen_service;
	tb->user_len = user_len;
	tb->port_len = port_len;
	tb->r_addr_len = r_addr_len; /* may be e.g Caller-ID in future */
	tb->data_len = token_len;

	pkt_len = TAC_AUTHEN_START_FIXED_TOTAL;

#define PUTATTR(data, len) \
	bcopy(data, pkt + pkt_len, len); \
	pkt_len += len

	/* fill user, port, rem_addr, data fields */
	PUTATTR(user, user_len);
	PUTATTR(tty, port_len);
	PUTATTR(r_addr, r_addr_len);
	PUTATTR(token, token_len);

	/* no longer need token */
	free(token);

	/* encrypt packet body */
	_tac_crypt(sess, (u_char *)tb, th);

	*_pkt = pkt;
	*_len = pkt_total;
}    /* tac_authen_send_pkt */

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT
 *             LIBTAC_STATUS_ASSEMBLY_ERR
 */
int tac_authen_send(struct tac_session *sess, int fd,
		const char *user, const char *pass, const char *tty,
		const char *r_addr, u_char action) {

	u_char *pkt = NULL;
	unsigned pkt_total = 0;
	int w, ret = 0;

	/* generate the packet */
	tac_authen_send_pkt(sess, user, pass, tty, r_addr, action, &pkt, &pkt_total);

	/* we can now write the packet */
	w = write(fd, pkt, pkt_total);
	if (w < 0 || (unsigned) w < pkt_total) {
		TACSYSLOG(
				LOG_ERR, "%s: short write on packet, wrote %d of %u: %m", __FUNCTION__, w, pkt_total);
		ret = LIBTAC_STATUS_WRITE_ERR;
	}

	free(pkt);

	TACDEBUG(LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret);

	return ret;
} /* tac_authen_send */

