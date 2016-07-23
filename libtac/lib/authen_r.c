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
int tac_authen_read(int fd, struct areply *re) {
	HDR th;
	struct authen_reply *tb = NULL;
	size_t len_from_header, len_from_body;
	ssize_t spacket_read;
	char *msg = NULL;
	int timeleft = 0;

	memset(re, 0, sizeof(struct areply));

	/* read the reply header */
	if (tac_readtimeout_enable
			&& tac_read_wait(fd, tac_timeout * 1000, TAC_PLUS_HDR_SIZE,
					&timeleft) < 0) {
		TACSYSLOG(
				(LOG_ERR, "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout))
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		free(tb);
		return re->status;
	}
	spacket_read = read(fd, &th, TAC_PLUS_HDR_SIZE);
	if (spacket_read < TAC_PLUS_HDR_SIZE) {
		TACSYSLOG(
				(LOG_ERR, "%s: short reply header, read %zd of %d: %m", __FUNCTION__, spacket_read, TAC_PLUS_HDR_SIZE))
		re->status = LIBTAC_STATUS_SHORT_HDR;
		free(tb);
		return re->status;
	}

	/* check the reply fields in header */
	msg = _tac_check_header(&th, TAC_PLUS_AUTHEN);
	if (msg != NULL) {
		re->msg = xstrdup(msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}

	re->seq_no = th.seq_no;

	len_from_header = ntohl(th.datalength);
	if (len_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
		TACSYSLOG(
				(LOG_ERR, "%s: length declared in the packet %zu exceeds max packet size %d", __FUNCTION__, len_from_header, TAC_PLUS_MAX_PACKET_SIZE))
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}
	tb = (struct authen_reply *) xcalloc(1, len_from_header);

	/* read reply packet body */
	if (tac_readtimeout_enable
			&& tac_read_wait(fd, timeleft, len_from_header, NULL) < 0) {
		TACSYSLOG(
				(LOG_ERR, "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout))
		re->msg = xstrdup(authen_syserr_msg);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		free(tb);
		return re->status;
	}
	spacket_read = read(fd, tb, len_from_header);
	if (spacket_read < len_from_header) {
		TACSYSLOG(
				(LOG_ERR, "%s: short reply body, read %zd of %zu: %m", __FUNCTION__, spacket_read, len_from_header))
		re->msg = xstrdup(authen_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_BODY;
		free(tb);
		return re->status;
	}

	/* decrypt the body */
	_tac_crypt((u_char *) tb, &th, len_from_header);

	/* Convert network byte order to host byte order */
	tb->msg_len = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

	/* check the length fields */
	len_from_body = sizeof(tb->status) + sizeof(tb->flags) + sizeof(tb->msg_len)
			+ sizeof(tb->data_len) + tb->msg_len + tb->data_len;

	if (len_from_header != len_from_body) {
		TACSYSLOG(
				(LOG_ERR, "%s: inconsistent reply body, incorrect key?", __FUNCTION__))
		re->msg = xstrdup(protocol_err_msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}

	/* save status and clean up */
	re->status = tb->status;

	if (0 < tb->msg_len) {
		msg = xcalloc(tb->msg_len + 1, sizeof(char));
		memset(msg, 0, (tb->msg_len + 1));
		memcpy(msg, (char*) tb + sizeof(struct authen_reply), tb->msg_len);

		re->msg = msg;
	}

	/* server authenticated username and password successfully */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_PASS) {
		TACDEBUG((LOG_DEBUG, "%s: authentication ok", __FUNCTION__))
		free(tb);
		return re->status;
	}

	/* server ask for continue packet with password */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
		TACDEBUG((LOG_DEBUG, "%s: continue packet with password needed", __FUNCTION__))
		free(tb);
		return re->status;
	}

	/* server wants to prompt user for more data */
	if (re->status == TAC_PLUS_AUTHEN_STATUS_GETDATA) {
		re->flags = tb->flags;

		TACDEBUG((LOG_DEBUG, "%s: continue packet with data request: msg=%.*s",
						__func__, tb->msg_len, (char*)tb + sizeof(struct authen_reply)))
		free(tb);
		return re->status;
	}

	TACDEBUG((LOG_DEBUG, "%s: authentication failed, server reply status=%d",
					__FUNCTION__, r))

	free(tb);
	return re->status;
} /* tac_authen_read */

