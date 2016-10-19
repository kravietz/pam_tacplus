/* acct_s.c - Send accounting event information to server.
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

#include "libtac.h"
#include "xalloc.h"

char *tac_acct_flag2str(u_char flag) {
    switch(flag) {
        case TAC_PLUS_ACCT_FLAG_MORE:
            return "more";
        case TAC_PLUS_ACCT_FLAG_START:
            return "start";
        case TAC_PLUS_ACCT_FLAG_STOP:
            return "stop";
        case TAC_PLUS_ACCT_FLAG_WATCHDOG:
            return "update";
        default:
            return "unknown";
    }
}

/* allocate and format an Accounting Start packet */
void tac_acct_send_pkt(struct tac_session *sess, u_char type,
    const char *user, const char *tty, const char *r_addr,
    struct tac_attrib *attr, u_char **_pkt, unsigned *_len) {

    HDR *th;
    struct acct *tb;
    unsigned user_len, port_len, r_addr_len;
    struct tac_attrib *a;
    unsigned i;  /* arg count */
    u_char *pkt=NULL;
    unsigned pkt_total, pkt_len = 0;

    TACDEBUG(LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s, type: %s", \
        __FUNCTION__, user, tty, r_addr, \
        (sess->tac_encryption) ? "yes" : "no", \
        tac_acct_flag2str(type));

    /*
     * precompute the buffer size so we don't need to keep resizing/copying it
     */
    user_len = strlen(user);
    port_len = strlen(tty);
    r_addr_len = strlen(r_addr);

    assert(user_len <= UCHAR_MAX);
    assert(port_len <= UCHAR_MAX);
    assert(r_addr_len <= UCHAR_MAX);

#define TAC_ACCT_REQ_FIXED_TOTAL \
            (TAC_PLUS_HDR_SIZE + TAC_ACCT_REQ_FIXED_FIELDS_SIZE)

    pkt_total = TAC_ACCT_REQ_FIXED_TOTAL + user_len + port_len + r_addr_len;

    /* ... add in attributes */
    for (i = 0, a = attr; a; a = a->next, ++i) {
        pkt_total += a->attr_len + 1;          /* count length byte too */
    }

    pkt = (u_char *)xcalloc(1, pkt_total);
    th = (HDR *)pkt;

    /* tacacs header */
    th->version = TAC_PLUS_VER_0;
    th->type = TAC_PLUS_ACCT;
    th->seq_no = ++sess->seq_no;
    th->encryption = sess->tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;
    th->session_id = htonl(sess->tac_session_id);
    th->datalength = htonl(pkt_total - TAC_PLUS_HDR_SIZE);

    /* fixed part of tacacs body */
    tb = (struct acct *)(pkt + TAC_PLUS_HDR_SIZE);
    tb->flags = type;
    tb->authen_method = sess->tac_authen_method;
    tb->priv_lvl = sess->tac_priv_lvl;
    tb->authen_type = sess->tac_authen_type;
    tb->authen_service = sess->tac_authen_service;
    tb->user_len = user_len;
    tb->port_len = port_len;
    tb->r_addr_len = r_addr_len;

    /* fill the arg count field and add the fixed fields to packet */
    tb->arg_cnt = i;

    pkt_len = TAC_ACCT_REQ_FIXED_TOTAL + i;    /* reserve room for lengths */

#define PUTATTR(data, len) \
    bcopy(data, pkt + pkt_len, len); \
    pkt_len += len

    /* fill user and port fields */
    PUTATTR(user, user_len);
    PUTATTR(tty, port_len);
    PUTATTR(r_addr, r_addr_len);

    /* fill attributes */
    for (i = 0, a = attr; a; a = a->next, ++i) {
        tb->arg_len[i] = a->attr_len;
        PUTATTR(a->attr, a->attr_len);
    }

    assert(pkt_len == pkt_total);

    /* encrypt packet body  */
    _tac_crypt(sess, (u_char *)tb, th);

    *_pkt = pkt;
    *_len = pkt_total;
}    /* tac_acct_send_pkt */

/*
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT  (pending impl)
 *             LIBTAC_STATUS_ASSEMBLY_ERR   (pending impl)
 */
int tac_acct_send(struct tac_session *sess,
    u_char type, const char *user,
    const char *tty, const char *r_addr, struct tac_attrib *attr) {

    u_char *pkt = NULL;
    unsigned pkt_total = 0;
    int w, ret = 0;

    /* generate the packet */
    tac_acct_send_pkt(sess, type, user, tty, r_addr, attr, &pkt, &pkt_total);

    /* write packet */
    w = write(sess->fd, pkt, pkt_total);

    if(w < 0 || (unsigned) w < pkt_total) {
        TACSYSLOG(LOG_ERR, "%s: short write of packet, wrote %d of %d: %m",\
            __FUNCTION__, w, pkt_total);
        ret = LIBTAC_STATUS_WRITE_ERR;
    }

    free(pkt);
    TACDEBUG(LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret);
    return ret;
}    /* tac_acct_send */

