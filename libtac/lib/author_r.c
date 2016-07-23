/* author_r.c - Reads authorization reply from the server.
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

/* This function returns structure containing
 1. status (granted/denied)
 2. message for the user
 3. list of attributes returned by server
 The attributes should be applied to service authorization
 is requested for.
 *
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_READ_TIMEOUT
 *         LIBTAC_STATUS_SHORT_HDR
 *         LIBTAC_STATUS_SHORT_BODY
 *         LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHOR_STATUS_...
 */
int tac_author_read(int fd, struct areply *re) {
	HDR th;
	struct author_reply *tb = NULL;
	size_t len_from_header, len_from_body;
	ssize_t packet_read;
	u_char *pktp = NULL;
	char *msg = NULL;
	int timeleft = 0;
	re->msg = NULL;

	bzero(re, sizeof(struct areply));
	if (tac_readtimeout_enable
			&& tac_read_wait(fd, tac_timeout * 1000, TAC_PLUS_HDR_SIZE,
					&timeleft) < 0) {

		TACSYSLOG(
				(LOG_ERR, "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout))
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		free(tb);
		return re->status;
	}

	packet_read = read(fd, &th, TAC_PLUS_HDR_SIZE);
	if (packet_read < TAC_PLUS_HDR_SIZE) {
		TACSYSLOG(
				(LOG_ERR, "%s: short reply header, read %zd of %d: %m", __FUNCTION__, packet_read, TAC_PLUS_HDR_SIZE))
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_HDR;
		free(tb);
		return re->status;
	}

	/* check header consistency */
	msg = _tac_check_header(&th, TAC_PLUS_AUTHOR);
	if (msg != NULL) {
		/* no need to process body if header is broken */
		re->msg = xstrdup(msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}

	len_from_header = ntohl(th.datalength);
	if (len_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
		TACSYSLOG(
				(LOG_ERR, "%s: length declared in the packet %zu exceeds max packet size %d", __FUNCTION__, len_from_header, TAC_PLUS_MAX_PACKET_SIZE))
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}
	tb = (struct author_reply *) xcalloc(1, len_from_header);

	/* read reply packet body */
	if (tac_readtimeout_enable
			&& tac_read_wait(fd, timeleft, len_from_header, NULL) < 0) {

		TACSYSLOG(
				(LOG_ERR, "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout))
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		free(tb);
		return re->status;
	}
	packet_read = read(fd, tb, len_from_header);
	if (packet_read < len_from_header) {
		TACSYSLOG(
				(LOG_ERR, "%s: short reply body, read %zd of %zu", __FUNCTION__, packet_read, len_from_header))
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_BODY;
		free(tb);
		return re->status;
	}

	/* decrypt the body */
	_tac_crypt((u_char *) tb, &th, len_from_header);

	/* Convert network byte order to host byte order */
	tb->msg_len = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

	/* check consistency of the reply body
	 * len_from_header = declared in header
	 * len_from_body = value computed from body fields
	 */
	len_from_body = TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + tb->msg_len
			+ tb->data_len;

	pktp = (u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;

	/* cycle through the arguments supplied in the packet */
	for (unsigned int r = 0; r < tb->arg_cnt && r < TAC_PLUS_MAX_ARGCOUNT;
			r++) {
		if (len_from_body > packet_read
				|| ((void *) pktp - (void *) tb) > packet_read) {
			TACSYSLOG(
					(LOG_ERR, "%s: arguments supplied in packet seem to exceed its size", __FUNCTION__))
			re->msg = xstrdup(protocol_err_msg);
			re->status = LIBTAC_STATUS_PROTOCOL_ERR;
			free(tb);
			return re->status;
		}
		len_from_body += sizeof(u_char); /* add arg length field's size*/
		len_from_body += *pktp; /* add arg length itself */
		pktp++;
	}

	if (len_from_header != len_from_body) {
		TACSYSLOG(
				(LOG_ERR, "%s: inconsistent reply body, incorrect key?", __FUNCTION__))
		re->msg = xstrdup(protocol_err_msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(tb);
		return re->status;
	}

	/* packet seems to be consistent, prepare return messages */
	/* server message for user */
	if (tb->msg_len) {
		char *msg = (char *) xcalloc(1, tb->msg_len + 1);
		bcopy(
				(u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
						+ (tb->arg_cnt) * sizeof(u_char), msg, tb->msg_len);
		msg[(int) tb->msg_len] = '\0';
		re->msg = msg; /* freed by caller */
	}

	/* server message to syslog */
	if (tb->data_len) {
		char *smsg = (char *) xcalloc(1, tb->data_len + 1);
		bcopy(
				(u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
						+ (tb->arg_cnt) * sizeof(u_char) + tb->msg_len, smsg,
				tb->data_len);
		smsg[(int) tb->data_len] = '\0';
		TACSYSLOG((LOG_ERR, "%s: reply message: %s", __FUNCTION__,smsg))
		free(smsg);
	}

	TACDEBUG((LOG_DEBUG, "%s: authorization reply status=%d",
					__FUNCTION__, tb->status));

	/* prepare status */
	switch (tb->status) {
	/* success conditions */
	/* XXX support optional vs mandatory arguments */
	case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
		tac_free_attrib(&re->attr);

	case TAC_PLUS_AUTHOR_STATUS_PASS_ADD: {
		u_char *argp;

		if (!re->msg)
			re->msg = xstrdup(author_ok_msg);
		re->status = tb->status;

		/* add attributes received to attribute list returned to
		 the client */
		pktp = (u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
		argp = pktp + (tb->arg_cnt * sizeof(u_char)) + tb->msg_len
				+ tb->data_len;
		TACSYSLOG((LOG_DEBUG, "Args cnt %d", tb->arg_cnt));
		/* argp points to current argument string
		 pktp points to current argument length */
		for (unsigned int r = 0; r < tb->arg_cnt && r < TAC_PLUS_MAX_ARGCOUNT;
				r++) {
			unsigned char buff[256];
			unsigned char *sep;
			unsigned char *value;
			unsigned char sepchar = '=';

			bcopy(argp, buff, (int) *pktp);
			buff[(int) *pktp] = '\0';
			sep = strchr((const char *) buff, '=');
			if (sep == NULL) {
				sep = strchr((const char *) buff, '*');
			}
			if (sep == NULL) {
				TACSYSLOG(
						(LOG_WARNING, "AUTHOR_STATUS_PASS_ADD/REPL: av pair does not contain a separator: %s", buff))
				/* now buff points to attribute name, make value ""
				 treat as "name=" */
				value = "";
			} else {
				sepchar = *sep;
				*sep = '\0';
				value = ++sep;
				/* now buff points to attribute name,
				 value to the attribute value */
			}
			TACSYSLOG((LOG_DEBUG, "Adding buf/value pair (%s,%s)", buff, value));
			tac_add_attrib_pair(&re->attr, buff, sepchar, value);
			argp += *pktp;
			pktp++;
		}
	}
		free(tb);
		return re->status;
		break;
	}

	switch (tb->status) {
	/* authorization failure conditions */
	/* failing to follow is allowed by RFC, page 23  */
	case TAC_PLUS_AUTHOR_STATUS_FOLLOW:
	case TAC_PLUS_AUTHOR_STATUS_FAIL:
		if (!re->msg)
			re->msg = xstrdup(author_fail_msg);
		re->status = TAC_PLUS_AUTHOR_STATUS_FAIL;
		break;
		/* error conditions */
	case TAC_PLUS_AUTHOR_STATUS_ERROR:
	default:
		if (!re->msg)
			re->msg = xstrdup(author_err_msg);
		re->status = TAC_PLUS_AUTHOR_STATUS_ERROR;
	}

	free(tb);
	return re->status;
}
