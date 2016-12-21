/* acct_r.c - Read accounting reply from server.
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
 *             LIBTAC_STATUS_READ_TIMEOUT
 *             LIBTAC_STATUS_SHORT_HDR
 *             LIBTAC_STATUS_SHORT_BODY
 *             LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_acct_parse(u_char *pkt, unsigned pkt_total, struct areply *re) {
    HDR *th = (HDR *)pkt;
    struct acct_reply *tb = NULL;
    size_t ulen_from_header, len_from_body;
    char *msg = NULL;

    re->attr = NULL; /* unused */
    re->msg = re->data = NULL;

    /* check the reply fields in header */
    msg = _tac_check_header(th, TAC_PLUS_ACCT);
    if(msg != NULL) {
        re->msg = xstrdup(msg);
        re->status = LIBTAC_STATUS_PROTOCOL_ERR;
        TACDEBUG(LOG_DEBUG, "%s: exit status=%d, status message \"%s\"",\
            __FUNCTION__, re->status, re->msg != NULL ? re->msg : "");
        return re->status;
    }

    ulen_from_header = ntohl(th->datalength);

    tb = (struct acct_reply *)(pkt + TAC_PLUS_HDR_SIZE);

    if (pkt_total != ulen_from_header) {
        TACSYSLOG(LOG_ERR,\
            "%s: short packet, got %u expected %zu: %m",\
            __FUNCTION__,\
	    pkt_total, TAC_PLUS_HDR_SIZE + ulen_from_header);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_SHORT_BODY;
        return re->status;
    }

    /* decrypt the body */
    _tac_crypt((u_char *) tb, th);

    /* Convert network byte order to host byte order */
    tb->msg_len  = ntohs(tb->msg_len);
    tb->data_len = ntohs(tb->data_len);

    /* check the length fields */
    len_from_body = TAC_ACCT_REPLY_FIXED_FIELDS_SIZE + \
        tb->msg_len + tb->data_len;

    if(ulen_from_header != len_from_body) {
        TACSYSLOG(LOG_ERR,\
            "%s: inconsistent reply body, header len %zu versus parsed len %zu",\
            __FUNCTION__, ulen_from_header, len_from_body);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_PROTOCOL_ERR;
        return re->status;
    }

    /* save status and clean up */
    if(tb->msg_len) {
        msg=(char *) xcalloc(1, tb->msg_len+1);
        bcopy((u_char *) tb+TAC_ACCT_REPLY_FIXED_FIELDS_SIZE, msg, tb->msg_len);
        msg[tb->msg_len] = '\0';
        re->msg = msg;      /* Freed by caller */
    }

    if(tb->data_len) {
        msg=(char *) xcalloc(1, tb->data_len+1);
        bcopy((u_char *) tb+TAC_ACCT_REPLY_FIXED_FIELDS_SIZE+tb->data_len,
            msg, tb->data_len);
        msg[tb->data_len] = '\0';
        re->data = msg;     /* Freed by caller */
    }

    /* server logged our request successfully */
    if (tb->status == TAC_PLUS_ACCT_STATUS_SUCCESS) {
        TACDEBUG(LOG_DEBUG, "%s: accounted ok", __FUNCTION__);
        if (!re->msg) re->msg = xstrdup(acct_ok_msg);
        re->status = tb->status;
        return re->status;
    }

    TACDEBUG(LOG_DEBUG, "%s: accounting failed, server reply status=%d",\
        __FUNCTION__, tb->status);
    switch(tb->status) {
        case TAC_PLUS_ACCT_STATUS_FOLLOW:
            re->status = tb->status;
            if (!re->msg) re->msg=xstrdup(acct_fail_msg);
            break;

        case TAC_PLUS_ACCT_STATUS_ERROR:
        default:
            re->status = tb->status;
            if (!re->msg) re->msg=xstrdup(acct_err_msg);
            break;
    }

    return re->status;
}    /* tac_acct_parse */

/*
 * return value:
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_READ_TIMEOUT
 *             LIBTAC_STATUS_SHORT_HDR
 *             LIBTAC_STATUS_SHORT_BODY
 *             LIBTAC_STATUS_PROTOCOL_ERR
 *   >= 0 : server response, see TAC_PLUS_AUTHEN_STATUS_...
 */
int tac_acct_read(int fd, struct areply *re) {
    HDR *th;
    struct acct_reply *tb = NULL;
    size_t ulen_from_header;
    ssize_t spacket_read;
    int status, timeleft = 0;

    re->attr = NULL; /* unused */
    re->msg = re->data = NULL;

    if (tac_readtimeout_enable &&
        tac_read_wait(fd, tac_timeout * 1000, TAC_PLUS_HDR_SIZE, &timeleft) < 0 ) {
        TACSYSLOG(LOG_ERR,\
            "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_READ_TIMEOUT;
        return re->status;
    }

    th = (HDR *)xcalloc(1, TAC_PLUS_HDR_SIZE);

    spacket_read = read(fd, (char *)th, TAC_PLUS_HDR_SIZE);
    if(spacket_read < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG(LOG_ERR,\
            "%s: short reply header, read %zd of %u expected: %m", __FUNCTION__,\
            ((spacket_read >= 0) ? spacket_read : 0), TAC_PLUS_HDR_SIZE);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_SHORT_HDR;
        free(th);
        return re->status;
    }

    ulen_from_header = ntohl(th->datalength);
    if (ulen_from_header > TAC_PLUS_MAX_PACKET_SIZE) {
        TACSYSLOG(LOG_ERR,\
            "%s: length declared in the packet %zu exceeds max allowed packet size %u", __FUNCTION__,\
            ulen_from_header, TAC_PLUS_MAX_PACKET_SIZE);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_PROTOCOL_ERR;
        free(th);
        return re->status;
    }

    /* now make room for entire contiguous packet */
    th = (HDR *)xrealloc(th, TAC_PLUS_HDR_SIZE + ulen_from_header);
    tb = (struct acct_reply *)((u_char *)th + TAC_PLUS_HDR_SIZE);

    /* read reply packet body */
    if (tac_readtimeout_enable &&
        tac_read_wait(fd, timeleft, ulen_from_header, NULL) < 0 ) {
        TACSYSLOG(LOG_ERR,\
            "%s: reply timeout after %u secs", __FUNCTION__, tac_timeout);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_READ_TIMEOUT;
        free(th);
        return re->status;
    }

    spacket_read = read(fd, (char *)tb, ulen_from_header);
    if(spacket_read < 0 || (size_t) spacket_read < ulen_from_header) {
        TACSYSLOG(LOG_ERR,\
            "%s: short reply body, read %zd of %zu: %m",\
            __FUNCTION__,\
            ((spacket_read >= 0) ? spacket_read : 0), ulen_from_header);
        re->msg = xstrdup(acct_syserr_msg);
        re->status = LIBTAC_STATUS_SHORT_BODY;
        free(th);
        return re->status;
    }

    /* now parse remaining packet fields */
    status = tac_acct_parse((u_char *)th, TAC_PLUS_HDR_SIZE + ulen_from_header, re);

    /* all useful data has been copied out */
    free(th);

    return status;
}    /* tac_acct_read */

