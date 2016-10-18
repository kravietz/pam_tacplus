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

/*
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_READ_TIMEOUT
 *         LIBTAC_STATUS_SHORT_HDR
 *         LIBTAC_STATUS_SHORT_BODY
 *         LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHOR_STATUS_...
 */
int tac_author_parse(struct tac_session *sess,
	u_char *pkt, unsigned pkt_total, struct areply *re) {

	HDR *th = (HDR *)pkt;
	struct author_reply *tb = NULL;
	size_t len_from_header, len_from_body;
	char *msg = NULL;
	unsigned int r = 0;

	bzero(re, sizeof(*re));

	/* check header consistency */
	msg = _tac_check_header(sess, th, TAC_PLUS_AUTHOR);
	if (msg != NULL) {
		/* no need to process body if header is broken */
		re->msg = xstrdup(msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		return re->status;
	}

	len_from_header = ntohl(th->datalength);

	tb = tac_hdr_to_body(th);

	if (pkt_total != TAC_PLUS_HDR_SIZE + len_from_header) {
		TACSYSLOG(
				LOG_ERR, "%s: short packet, got %u of %zu", __FUNCTION__, pkt_total, len_from_header);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_BODY;
		return re->status;
	}

	/* decrypt the body */
	_tac_crypt(sess, (u_char *) tb, th);

	/* Convert network byte order to host byte order */
	tb->msg_len = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

	/* check consistency of the reply body
	 * len_from_header = declared in header
	 * len_from_body = value computed from body fields
	 */
	len_from_body = TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE + tb->msg_len
			+ tb->data_len;

	/* cycle through the arguments supplied in the packet */
	for (r = 0; ; r++) {
		if (len_from_body > pkt_total) {
			TACSYSLOG(
					LOG_ERR, "%s: arguments supplied in packet seem to exceed its size", __FUNCTION__);
			re->msg = xstrdup(protocol_err_msg);
			re->status = LIBTAC_STATUS_PROTOCOL_ERR;
			return re->status;
		}

		if (r == tb->arg_cnt)
			break;

		len_from_body += sizeof(tb->arg_len[0]) + tb->arg_len[r];
	}

	if (len_from_header != len_from_body) {
		TACSYSLOG(
				LOG_ERR, "%s: inconsistent reply body, header len %zu versus parsed len %zu", __FUNCTION__, len_from_header, len_from_body);
		re->msg = xstrdup(protocol_err_msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		return re->status;
	}

	/* packet seems to be consistent, prepare return messages */

	/* server message for user */
	if (tb->msg_len) {
		char *msg = xcalloc(1, tb->msg_len + 1);
		bcopy(
				(u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
						+ (tb->arg_cnt) * sizeof(tb->arg_len[0]), msg, tb->msg_len);
		msg[tb->msg_len] = '\0';
		re->msg = msg; /* freed by caller */
	}

	/* server message to syslog */
	if (tb->data_len) {
		char *smsg = xcalloc(1, tb->data_len + 1);
		bcopy(
				(u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
						+ (tb->arg_cnt) * sizeof(tb->arg_len[0]) + tb->msg_len, smsg,
				tb->data_len);
		smsg[tb->data_len] = '\0';
		re->data = smsg;     /* Freed by caller */
		TACSYSLOG(LOG_ERR, "%s: reply message: %s", __FUNCTION__, smsg);
	}

	TACDEBUG(LOG_DEBUG, "%s: authorization reply status=%d",
					__FUNCTION__, tb->status);

	/* prepare status */
	switch (tb->status) {
	/* success conditions */
	/* XXX support optional vs mandatory arguments */
	case TAC_PLUS_AUTHOR_STATUS_PASS_REPL:
		/* @@@ we bzero'd the pointer at the top of this function,
		 * so there's nothing left to free here!
		 */
		tac_free_attrib(&re->attr);

	case TAC_PLUS_AUTHOR_STATUS_PASS_ADD: {
		u_char *argp;

		if (!re->msg)
			re->msg = xstrdup(author_ok_msg);
		re->status = tb->status;

		/* add attributes received to attribute list returned to
		 the client */
		argp = (u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE +
		       (tb->arg_cnt * sizeof(tb->arg_len[0])) + tb->msg_len +
			tb->data_len;
		TACSYSLOG(LOG_DEBUG, "Args cnt %d", tb->arg_cnt);

		/* argp points to current argument string
		 pktp points to current argument length */
		for (r = 0; r < tb->arg_cnt && r < TAC_PLUS_MAX_ARGCOUNT;
				r++) {
			char buff[256];
			char *sep;
			char *value;
			char sepchar = '=';

			bcopy(argp, buff, tb->arg_len[r]);
			buff[tb->arg_len[r]] = '\0';

			sep = strchr(buff, sepchar);

			if (sep == NULL) {
				sep = strchr(buff, '*');
			}

			if (sep == NULL) {
				TACSYSLOG(
						LOG_WARNING, "AUTHOR_STATUS_PASS_ADD/REPL: av pair does not contain a separator: %s", buff);
				/* now buff points to attribute name, make value ""
				 treat as "name=" */
				value = "";
			} else {
				sepchar = *sep;
				*sep = '\0';
				value = ++sep;
				/* now buff points to attribute name,
				 value to the attribute value (only
				 buff needs to be freed). */
			}
			TACSYSLOG(LOG_DEBUG, "Adding buf/value pair (%s,%s)", buff, value);
			tac_add_attrib_pair(&re->attr, buff, sepchar, value);
			argp += tb->arg_len[r];
		}

		break;
	}

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
		break;
	}

	return re->status;
}

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
int tac_author_read(struct tac_session *sess, int fd, struct areply *re) {
	HDR *th;
	struct author_reply *tb = NULL;
	size_t len_from_header;
	ssize_t packet_read;
	int timeleft = 0;

	bzero(re, sizeof(*re));

	if (tac_readtimeout_enable
			&& tac_read_wait(fd, tac_timeout * 1000, TAC_PLUS_HDR_SIZE,
					&timeleft) < 0) {

		TACSYSLOG(
				LOG_ERR, "%s: reply timeout after %d secs", __FUNCTION__, tac_timeout);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		return re->status;
	}

	th = xcalloc(1, TAC_PLUS_HDR_SIZE);

	packet_read = read(fd, th, TAC_PLUS_HDR_SIZE);
	if (packet_read < TAC_PLUS_HDR_SIZE) {
		TACSYSLOG(
				LOG_ERR, "%s: short reply header, read %zd of %u: %m", __FUNCTION__,
				((packet_read >= 0) ? packet_read : 0), TAC_PLUS_HDR_SIZE);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_HDR;
		free(th);
		return re->status;
	}

	len_from_header = ntohl(th->datalength);
	if (len_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
		TACSYSLOG(
				LOG_ERR, "%s: length declared in the packet %zu exceeds max packet size %d", __FUNCTION__, len_from_header, TAC_PLUS_MAX_PACKET_SIZE);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_PROTOCOL_ERR;
		free(th);
		return re->status;
	}

	/* now make room for entire contiguous packet */
	th = xrealloc(th, TAC_PLUS_HDR_SIZE + len_from_header);
	tb = tac_hdr_to_body(th);

	/* read reply packet body */
	if (tac_readtimeout_enable
			&& tac_read_wait(fd, timeleft, len_from_header, NULL) < 0) {
		TACSYSLOG(
				LOG_ERR, "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_READ_TIMEOUT;
		free(th);
		return re->status;
	}
	packet_read = read(fd, tb, len_from_header);
	if (packet_read < 0 || (size_t) packet_read < len_from_header) {
		TACSYSLOG(
				LOG_ERR, "%s: short reply body, read %zd of %zu: %m", __FUNCTION__, ((packet_read >= 0) ? packet_read : 0), len_from_header);
		re->msg = xstrdup(author_syserr_msg);
		re->status = LIBTAC_STATUS_SHORT_BODY;
		free(th);
		return re->status;
	}

	/* now parse remaining packet fields */
	(void) tac_author_parse(sess, (u_char *)th, TAC_PLUS_HDR_SIZE + len_from_header,
				 re);

	/* all useful data has been copied out */
	free(th);

	return re->status;
}	/* tac_author_read */

