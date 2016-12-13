/* wrappers.c - Add libevent2 wrappers
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
#include "xalloc.h"
#include "../../config.h"

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

void *
tac_event_loop_initialize()
{
    struct event_base *ev_base = NULL;

    struct event_config *cfg = event_config_new();

    TACDEBUG(LOG_DEBUG, "constructing event base");

    /* can tailor methods later */
    ev_base = event_base_new_with_config(cfg);

    /* event_base_priority_init(ev_base, ev_priorities); */

    /* no longer needed */
    event_config_free(cfg);

    TACDEBUG(LOG_DEBUG, "return event_base %p", ev_base);

    return ev_base;
}

/*
 * Loops until there are no more events.
 * @return: 0 on normal exit, 1 if no more events are queued and -1 on error.
 */
int
tac_event_loop(void *tac_event)
{
    struct event_base *ev_base = (struct event_base *) tac_event;
    int ret;

    TACDEBUG(LOG_DEBUG, "running event_base loop %p", ev_base);

    /* run until an event handler tells us to shut down via tac_end_loop() */
    /* EVLOOP_NO_EXIT_ON_EMPTY is not supported in older libevent versions. */
    ret = event_base_loop(ev_base, 0);

    TACDEBUG(LOG_DEBUG, "event_base loop returns %d", ret);

    return ret;
}

void
tac_event_loop_end(void *tac_event)
{
    struct event_base *ev_base = (struct event_base *) tac_event;

    TACDEBUG(LOG_DEBUG, "ending event_base %p", ev_base);

    (void)event_base_loopexit(ev_base, NULL);
}

void
tac_event_loop_free(void *tac_event)
{
    struct event_base *ev_base = (struct event_base *) tac_event;

    TACDEBUG(LOG_DEBUG, "destroying event_base %p", ev_base);

    event_base_free(ev_base);
}

void
tac_event_loop_global_shutdown(void)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    libevent_global_shutdown();
#endif
}

void tac_session_reset_timeouts(struct tac_session *sess, bool on)
{
    struct timeval tv = { sess->tac_timeout, 0 };

    TACDEBUG(LOG_DEBUG, "session %p reset_timeouts %u %s", sess, sess->tac_timeout, (on ? "on" : "off"));

    if (!sess->bufev)
        return;

    /* nothing will be enabled if we haven't yet connected... */
    if (bufferevent_get_enabled(sess->bufev) == 0)
        return;

    if (on)
        bufferevent_set_timeouts(sess->bufev, &tv, &tv);
    else
        bufferevent_set_timeouts(sess->bufev, NULL, NULL);
}

static void eventcb(struct bufferevent *bev, short events, void *ptr)
{
    struct cb_ctx *ctx = (struct cb_ctx *)ptr;
    struct tac_session *sess = ctx->sess;

#if 0
    fprintf(stderr, "eventcb: bev=%p, events=%#x, ptr=%p\n", bev, (unsigned)events, ptr);
    fputs("  flags =", stderr);
    if (events & BEV_EVENT_READING)
        fputs(" reading", stderr);
    if (events & BEV_EVENT_WRITING)
        fputs(" writing", stderr);
    if (events & BEV_EVENT_EOF)
        fputs(" eof", stderr);
    if (events & BEV_EVENT_ERROR)
        fputs(" error", stderr);
    if (events & BEV_EVENT_TIMEOUT)
        fputs(" timeout", stderr);
    if (events & BEV_EVENT_CONNECTED)
        fputs(" connected", stderr);
    fputc('\n', stderr);
#endif

    if (sess->oob_cb) {
        if (events & BEV_EVENT_CONNECTED) {
                TACDEBUG(LOG_DEBUG, "session %p connected", sess);
		/*
		 * if we had enqueued a request before the connect
		 * completed, then the idle flag would be false
		 * and we would want to reset the timer; if we didn't
		 * have a request on-the-wire, then the timeout gets
		 * cleared once we're connected.
		 */
		tac_session_reset_timeouts(sess, !sess->tac_idle);
		(sess->oob_cb)(sess, &sess->context, CONNECTED);
        }
        if (events & BEV_EVENT_ERROR) {
                TACDEBUG(LOG_DEBUG, "session %p errored", sess);
                (sess->oob_cb)(sess, &sess->context, ERROR);
        }
        if (events & BEV_EVENT_TIMEOUT) {
                TACDEBUG(LOG_DEBUG, "session %p timeout", sess);
                (sess->oob_cb)(sess, &sess->context, TIMEOUT);
        }
        if (events & BEV_EVENT_EOF) {
                TACDEBUG(LOG_DEBUG, "session %p closing", sess);
                (sess->oob_cb)(sess, &sess->context, CLOSED);
        }
    }

#if 0
    /* we don't close on a timeout because it will keep trying; if you
     * want to call tac_session_free() on the first TIMEOUT, you can
     * or you can wait for the eventual ERROR.  We might want to let
     * the user do all the cleanup via tac_session_free()...
     */
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        sess->bufev = NULL;
    }
#endif

    /* now notify us of inbound data, etc */
    if (events & BEV_EVENT_CONNECTED) {
	TACDEBUG(LOG_DEBUG, "session %p enabling r/w callbacks", sess);
        bufferevent_enable(bev, EV_READ|EV_WRITE);
    }
}

static void writecb(struct bufferevent *bev, void *ptr)
{
    struct cb_ctx *ctx = (struct cb_ctx *)ptr;
    struct tac_session *sess = ctx->sess;
    struct evbuffer *evbuf = bufferevent_get_output(bev);
    size_t n = evbuffer_get_length(evbuf);

    sess = sess;		/* unused */
    n = n;

    TACDEBUG(LOG_DEBUG, "session %p write cb %ld bytes", sess, n);
}

static void readcb(struct bufferevent *bev, void *ptr)
{
    struct cb_ctx *ctx = (struct cb_ctx *)ptr;
    struct tac_session *sess = ctx->sess;
    unsigned length;
    struct evbuffer *evbuf = bufferevent_get_input(bev);
    size_t n = evbuffer_get_length(evbuf);
    u_char *start;
    HDR *th;
    int i;

    sess = sess;		/* unused */

    TACDEBUG(LOG_DEBUG, "session %p read cb %ld bytes", sess, n);

    /* evbuffer_pullup() returns NULL if there aren't enough bytes in
     * the buffer yet to pull-up as many as are requested.
     */
    start = evbuffer_pullup(evbuf, TAC_PLUS_HDR_SIZE);
    if (! start) {
        TACDEBUG(LOG_DEBUG, "session %p not enough data to pullup", sess);
        return;
    }

    th = (HDR *)start;

    length = ntohl(th->datalength) + TAC_PLUS_HDR_SIZE;

    TACDEBUG(LOG_DEBUG, "session %p header shows %u bytes", sess, length);

    /* if we're short, we'll get called again when more data arrives */
    if (n < length) {
         TACDEBUG(LOG_DEBUG, "session %p want %u bytes but have %ld", sess, length, n);
         return;
    }

    u_char *pkt = xcalloc(1, length);

    /* copy out... */
    i = evbuffer_remove(evbuf, pkt, length);

    if (i < 0 || (unsigned) i != length)
        TACDEBUG(LOG_DEBUG, "%s: evbuffer_remove want %u got %d", __FUNCTION__, length, i);

    /* turn off timeouts */
    tac_session_reset_timeouts(sess, false);

    /* received response, so connection is idle again */
    sess->tac_idle = true;

    tac_parse_pkt(sess, ctx, pkt, ((i > 0) ? i : 0));

    free(pkt);
}

bool
tac_connect_single_ev(struct tac_session *sess, void *tac_event,
    struct addrinfo *server, struct addrinfo *srcaddr, unsigned timeout)
{
    struct event_base *ev_base = (struct event_base *)tac_event;
    struct bufferevent *bev;

    TACDEBUG(LOG_DEBUG, "sess %p starting connect", sess);

    bev = bufferevent_socket_new(ev_base, -1, BEV_OPT_CLOSE_ON_FREE);

    /* bind if source address got explicitly defined */
    if (srcaddr != NULL) {
        if (bind(bufferevent_getfd(bev), srcaddr->ai_addr, srcaddr->ai_addrlen) < 0) {
	    TACDEBUG(LOG_DEBUG, "couldn't bind src address: %m");
        }
    }

    if (timeout != 0) {
        struct timeval tv = { timeout, 0 };

        TACDEBUG(LOG_DEBUG, "session %p timeout %ld.%06ld", sess, tv.tv_sec, tv.tv_usec);
        bufferevent_set_timeouts(bev, &tv, &tv);
    }

    bufferevent_setwatermark(bev, EV_READ, TAC_PLUS_HDR_SIZE, 0);
    bufferevent_setcb(bev, readcb, writecb, eventcb, &sess->context);

    if (bufferevent_socket_connect(bev, server->ai_addr, server->ai_addrlen) < 0) {
        TACDEBUG(LOG_DEBUG, "session %p bufferevent connect fails: %m", sess);
        bufferevent_free(bev);
        return false;
    }

    /* don't bind bufferevent to session until connect initiated */
    sess->bufev = bev;

    return true;
}

static void cleanup_malloc(const void *data, size_t len, void *ptr)
{
    len = len;
    ptr = ptr;			/* unused */

    free((void *)data);
}

/*
 * return value:
 *	true/false success
 */
bool
tac_authen_send_ev(struct tac_session *sess,
    const char *user, const char *pass, const char *tty,
    const char *r_addr, u_char action) {

    u_char *pkt = NULL;
    unsigned pkt_total = 0;
    struct evbuffer *evbuf = evbuffer_new();
    int ret;

    TACDEBUG(LOG_DEBUG, "session %p authen %s/%s/%s", sess, user, tty, r_addr);

    sess->context.login = user;
    sess->context.pass = pass;

    /* generate the packet */
    tac_authen_send_pkt(sess, user, pass, tty, r_addr, action, &pkt, &pkt_total);

    /* if reusing connection, reset timeouts */
    tac_session_reset_timeouts(sess, true);

    /*
     * make evbuffer wrap around our packet, and call cleanup (free)
     * when done
     */
    evbuffer_add_reference(evbuf, pkt, pkt_total, cleanup_malloc, NULL);

    ret = bufferevent_write_buffer(sess->bufev, evbuf);
    evbuffer_free(evbuf);

    /* we have a request on-the-wire */
    sess->tac_idle = false;

    TACDEBUG(LOG_DEBUG, "session %p: write status=%d", sess, ret);

    return (ret == 0);
}

/*
 * return value:
 *	true/false
 */
bool
tac_author_send_ev(struct tac_session *sess,
    const char *user, const char *tty, const char *r_addr,
    struct tac_attrib *attr) {

    u_char *pkt = NULL;
    unsigned pkt_total = 0;
    struct evbuffer *evbuf = evbuffer_new();
    int ret;

    TACDEBUG(LOG_DEBUG, "session %p author %s/%s/%s", sess, user, tty, r_addr);

    sess->context.login = user;
    sess->context.pass = NULL;

    /* generate the packet */
    tac_author_send_pkt(sess, user, tty, r_addr, attr, &pkt, &pkt_total);

    /* if reusing connection, reset timeouts */
    tac_session_reset_timeouts(sess, true);

    /*
     * make evbuffer wrap around our packet, and call cleanup (free)
     * when done
     */
    evbuffer_add_reference(evbuf, pkt, pkt_total, cleanup_malloc, NULL);

    ret = bufferevent_write_buffer(sess->bufev, evbuf);
    evbuffer_free(evbuf);

    /* we have a request on-the-wire */
    sess->tac_idle = false;

    TACDEBUG(LOG_DEBUG, "session %p write status=%d", sess, ret);

    return (ret == 0);
}

/*
 * return value:
 *      true/false
 */
bool
tac_acct_send_ev(struct tac_session *sess,
    u_char type, const char *user, const char *tty,
    const char *r_addr, struct tac_attrib *attr) {

    u_char *pkt = NULL;
    unsigned pkt_total = 0;
    struct evbuffer *evbuf = evbuffer_new();
    int ret;

    TACDEBUG(LOG_DEBUG, "session %p account %s/%s/%s", sess, user, tty, r_addr);

    sess->context.login = user;
    sess->context.pass = NULL;

    /* generate the packet */
    tac_acct_send_pkt(sess, type, user, tty, r_addr, attr, &pkt, &pkt_total);

    /* if reusing connection, reset timeouts */
    tac_session_reset_timeouts(sess, true);

    /*
     * make evbuffer wrap around our packet, and call cleanup (free)
     * when done
     */
    evbuffer_add_reference(evbuf, pkt, pkt_total, cleanup_malloc, NULL);

    ret = bufferevent_write_buffer(sess->bufev, evbuf);
    evbuffer_free(evbuf);

    /* we have a request on-the-wire */
    sess->tac_idle = false;

    TACDEBUG(LOG_DEBUG, "session %p write status=%d", sess, ret);

    return (ret == 0);
}

/*
 * return value:
 *      true/false
 */
bool
tac_cont_send_ev(struct tac_session *sess, const char *pass) {

    u_char *pkt = NULL;
    unsigned pkt_total = 0;
    struct evbuffer *evbuf = evbuffer_new();
    int ret;

    TACDEBUG(LOG_DEBUG, "session %p authen-cont %s", sess, "********");

    sess->context.pass = pass;

    /* generate the packet */
    tac_cont_send_pkt(sess, pass, &pkt, &pkt_total);

    /* if reusing connection, reset timeouts */
    tac_session_reset_timeouts(sess, true);

    /*
     * make evbuffer wrap around our packet, and call cleanup (free)
     * when done
     */
    evbuffer_add_reference(evbuf, pkt, pkt_total, cleanup_malloc, NULL);

    ret = bufferevent_write_buffer(sess->bufev, evbuf);
    evbuffer_free(evbuf);

    /* we have a request on-the-wire */
    sess->tac_idle = false;

    TACDEBUG(LOG_DEBUG, "session %p write status=%d", sess, ret);

    return (ret == 0);
}

