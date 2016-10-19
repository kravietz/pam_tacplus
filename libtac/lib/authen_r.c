/* authen_r.c - Read authentication reply from server.
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

#include "xalloc.h"
#include "libtac.h"
#include "messages.h"

/*
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_READ_TIMEOUT
 *         LIBTAC_STATUS_SHORT_HDR
 *         LIBTAC_STATUS_SHORT_BODY
 *         LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_authen_parse(struct tac_session *sess, struct areply *re,
	u_char *pkt, unsigned pkt_total) {

	HDR *th = (HDR *)pkt;
	struct authen_reply *tb = NULL;
	size_t len_from_header, len_from_body;
	char *msg = NULL;

	memset(re, 0, sizeof(*re));

	/* check the reply fields in header */
	msg = _tac_check_header(sess, th, TAC_PLUS_AUTHEN);
	if (msg != NULL) {
		re->msg = xstrdup(msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		return re->status;
	}

	len_from_header = ntohl(th->datalength);

	tb = tac_hdr_to_body(th);

	if (pkt_total != TAC_PLUS_HDR_SIZE + len_from_header) {
		TACSYSLOG(
				LOG_ERR, "%s: short packet, got %u expected %zu: %m", __FUNCTION__,
				pkt_total, TAC_PLUS_HDR_SIZE + len_from_header);
		re->msg = xstrdup(authen_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_BODY;
		return re->status;
	}

	/* decrypt the body */
	_tac_crypt(sess, (u_char *) tb, th);

	/* Convert network byte order to host byte order */
	tb->msg_len = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

	/* check the length fields */
	len_from_body = TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE + \
		tb->msg_len + tb->data_len;

	if (len_from_header != len_from_body) {
		TACSYSLOG(
				LOG_ERR, "%s: inconsistent reply body, header len %zu versus parsed len %zu",
				__FUNCTION__, len_from_header, len_from_body);
		re->msg = xstrdup(protocol_err_msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		return re->status;
	}

	/* save status and clean up */
	re->status = tb->status;

	if (0 < tb->msg_len) {
		msg = xcalloc(tb->msg_len + 1, sizeof(char));
		memcpy(msg, tb->msg, tb->msg_len);
		msg[tb->msg_len] = '\0';
		re->msg = msg;
	}

	if (0 < tb->data_len) {
		msg = xcalloc(tb->data_len + 1, sizeof(char));
		/* first byte beyond msg is data */
		memcpy(msg, &tb->msg[tb->msg_len], tb->data_len);
		msg[tb->data_len] = '\0';
		re->data = msg;
	}

	/* server authenticated username and password successfully */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_PASS) {
		TACDEBUG(LOG_DEBUG, "%s: authentication ok", __FUNCTION__);
		return re->status;
	}

	/* server ask for continue packet with password */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
		TACDEBUG(LOG_DEBUG, "%s: continue packet with password needed", __FUNCTION__);
		return re->status;
	}

	/* server wants to prompt user for more data */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_GETDATA) {
		re->flags = tb->flags;

		TACDEBUG(LOG_DEBUG, "%s: continue packet with data request: msg=%.*s",
						__func__, tb->msg_len, tb->msg);
		return re->status;
	}

	TACDEBUG(LOG_DEBUG, "%s: authentication failed, server reply status=%d",
					__FUNCTION__, re->status);

	return re->status;
} /* tac_authen_parse_pkt */

/* reads packet from TACACS+ server; returns:
 *  TAC_PLUS_AUTHEN_STATUS_PASS if the authentication succeded
 *  an other integer if failed. Check tacplus.h for all possible values
 *
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_READ_TIMEOUT
 *         LIBTAC_STATUS_SHORT_HDR
 *         LIBTAC_STATUS_SHORT_BODY
 *         LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_authen_read(struct tac_session *sess, struct areply *re) {
	HDR *th;
	struct authen_reply *tb = NULL;
	size_t len_from_header;
	int r, status, timeleft = 0;

	memset(re, 0, sizeof(*re));

	/* read the reply header */
	if (tac_readtimeout_enable &&
		tac_read_wait(sess->fd, tac_timeout * 1000, TAC_PLUS_HDR_SIZE, &timeleft) < 0 ) {
		TACSYSLOG(LOG_ERR,
			"%s: reply timeout after %d secs", __FUNCTION__, tac_timeout);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		return re->status;
	}

	th = xcalloc(1, TAC_PLUS_HDR_SIZE);

	r = read(sess->fd, th, TAC_PLUS_HDR_SIZE);
	if (r < TAC_PLUS_HDR_SIZE) {
		TACSYSLOG(LOG_ERR,
			"%s: short reply header, read %d of %u: %m", __FUNCTION__,
			((r >= 0) ? r : 0), TAC_PLUS_HDR_SIZE);
		re->status = LIBTAC_STATUS_SHORT_HDR;
		free(th);
		return re->status;
	}

	len_from_header = ntohl(th->datalength);

	if (len_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
		TACSYSLOG(LOG_ERR,
			"%s: excessively long packet, got %zu bytes", __FUNCTION__,
			TAC_PLUS_HDR_SIZE + len_from_header);
		status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(th);
		return status;
	}

	/* now make room for entire contiguous packet */
	th = xrealloc(th, TAC_PLUS_HDR_SIZE + len_from_header);
	tb = tac_hdr_to_body(th);

	/* read reply packet body */
	if (tac_readtimeout_enable &&
		tac_read_wait(sess->fd, timeleft, len_from_header, NULL) < 0 ) {
		TACSYSLOG(LOG_ERR,
			"%s: reply timeout after %d secs", __FUNCTION__, tac_timeout);
		status = LIBTAC_STATUS_READ_TIMEOUT;
	}

	r = read(sess->fd, tb, len_from_header);
	if (r < 0 || (unsigned) r < len_from_header) {
		TACSYSLOG(LOG_ERR,
			"%s: short reply body, read %d of %zu: %m",
			__FUNCTION__,
			((r >= 0) ? r : 0), len_from_header);
		status = LIBTAC_STATUS_SHORT_BODY;
		free(th);
		return status;
	}

	/* now parse remaining packet fields */
	status = tac_authen_parse(sess, re, (u_char *)th, TAC_PLUS_HDR_SIZE + len_from_header);

	/* all useful data has been copied out */
	free(th);

	return status;
} /* tac_authen_read */

