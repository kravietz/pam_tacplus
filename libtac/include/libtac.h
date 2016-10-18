/* libtac.h
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

#ifndef _LIB_TAC_H
#define _LIB_TAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef __linux__
#include <sys/cdefs.h>
#else
#include "cdefs.h"
#endif
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include "tacplus.h"

#if defined(DEBUGTAC) && !defined(TACDEBUG)
# ifdef __GNUC__
#define TACDEBUG(level, fmt, ...) syslog(level, fmt, ## __VA_ARGS__)
# else
#define TACDEBUG(level, fmt, ...) syslog(level, fmt, __VA_ARGS__)
# endif
#else
#define TACDEBUG(level, fmt, ...) (void)0
#endif

#ifdef __GNUC__
#define TACSYSLOG(level, fmt, ...) syslog(level, fmt, ## __VA_ARGS__)
#else
#define TACSYSLOG(level, fmt, ...) syslog(level, fmt, __VA_ARGS__)
#endif

#if defined(TACDEBUG_AT_RUNTIME)
#undef TACDEBUG
#undef TACSYSLOG
# ifdef __GNUC__
#define TACDEBUG(level, fmt, ...) do { if (tac_debug_enable) logmsg(level, fmt, ## __VA_ARGS__); } while (0)
#define TACSYSLOG(level, fmt, ...) logmsg(level, fmt, ## __VA_ARGS__)
# else
#define TACDEBUG(level, fmt, ...) do { if (tac_debug_enable) logmsg(level, fmt, __VA_ARGS__); } while (0)
#define TACSYSLOG(level, fmt, ...) logmsg(level, fmt, __VA_ARGS__)
# endif
extern void logmsg __P((int, const char*, ...));
#endif

/* u_int32_t support for sun */
#ifdef sun
typedef unsigned int u_int32_t;
#endif

struct tac_attrib {
	char *attr;
	u_char attr_len;
	struct tac_attrib *next;
};

struct areply {
	struct tac_attrib *attr;
	char *msg;
	char *data;
	int status :8;
	int flags :8;
	int seq_no :8;
};

#ifndef TAC_PLUS_MAXSERVERS		
#define TAC_PLUS_MAXSERVERS 8
#endif

#ifndef TAC_PLUS_MAX_PACKET_SIZE
#define TAC_PLUS_MAX_PACKET_SIZE 128000 /* bytes */
#endif

#ifndef TAC_PLUS_MAX_ARGCOUNT
#define TAC_PLUS_MAX_ARGCOUNT 100 /* maximum number of arguments passed in packet */
#endif

#ifndef TAC_PLUS_PORT
#define	TAC_PLUS_PORT 49
#endif

#define TAC_PLUS_READ_TIMEOUT  180    /* seconds */
#define TAC_PLUS_WRITE_TIMEOUT 180    /* seconds */

/* Internal status codes 
 *   all negative, tacplus status codes are >= 0
 */

#define LIBTAC_STATUS_ASSEMBLY_ERR  -1
#define LIBTAC_STATUS_PROTOCOL_ERR  -2
#define LIBTAC_STATUS_READ_TIMEOUT  -3
#define LIBTAC_STATUS_WRITE_TIMEOUT -4
#define LIBTAC_STATUS_WRITE_ERR     -5
#define LIBTAC_STATUS_SHORT_HDR     -6
#define LIBTAC_STATUS_SHORT_BODY    -7
#define LIBTAC_STATUS_CONN_TIMEOUT  -8
#define LIBTAC_STATUS_CONN_ERR      -9

/* Runtime flags */

/* version.c */
extern int tac_ver_major;
extern int tac_ver_minor;
extern int tac_ver_patch;

/* session.c */
struct tac_session {
    unsigned tac_timeout;
    const char *tac_secret;
    uint32_t tac_session_id;
    bool tac_encryption;
    uint8_t tac_priv_lvl;
    uint8_t tac_authen_method;
    uint8_t tac_authen_service;
    uint8_t tac_authen_type;
    uint8_t seq_no;

    /* user defined stuff */
    uint8_t user_data[0];
};

struct tac_session *tac_session_alloc(void);
struct tac_session *tac_session_alloc_extra(unsigned);
void tac_session_set_authen_type(struct tac_session *, uint8_t);
void tac_session_set_secret(struct tac_session *, const char *);
void tac_session_set_timeout(struct tac_session *, unsigned);
void tac_session_new_session_id(struct tac_session *);
void tac_session_reset_seq(struct tac_session *);
void *tac_session_get_user_data(struct tac_session *);
void tac_session_free(struct tac_session *);

/* header.c */
extern int tac_debug_enable;
extern int tac_readtimeout_enable;

HDR *_tac_req_header(struct tac_session *, u_char, bool);

/* connect.c */
extern int tac_timeout;

int tac_connect(struct addrinfo **, unsigned);
int tac_connect_single(const struct addrinfo *, struct addrinfo *, int);
char *tac_ntop(const struct sockaddr *);

/* authen_s.c */
u_char tac_get_authen_type(const char *);
const char *tag_get_authen_string(uint8_t);

void tac_authen_send_pkt(struct tac_session *,
    const char *, const char *, const char *, const char *, u_char,
    u_char **, unsigned *);
int tac_authen_send(struct tac_session *, int,
    const char *, const char *, const char *, const char *, u_char);

/* authen_r.c */
int tac_authen_parse(struct tac_session *, struct areply *, u_char *, unsigned);
int tac_authen_read(struct tac_session *, int, struct areply *);

/* cont_s.c */
void tac_cont_send_pkt(struct tac_session *, const char *,
   u_char **, unsigned *);
int tac_cont_send(struct tac_session *, int, const char *);

/* crypt.c */
void _tac_crypt(const struct tac_session *, u_char *, const HDR *);

/* author_r.c */
int tac_author_parse(struct tac_session *, u_char *, unsigned, struct areply *);
int tac_author_read(struct tac_session *, int, struct areply *);

/* author_s.c */
void tac_author_send_pkt(struct tac_session *, const char *, const char *,
    const char *, struct tac_attrib *, u_char **, unsigned *);
int tac_author_send(struct tac_session *, int, const char *, const char *,
    const char *, struct tac_attrib *);

/* attrib.c */
void tac_add_attrib(struct tac_attrib **, char *, char *);
void tac_add_attrib_pair(struct tac_attrib **, char *, char, char *);
void tac_free_attrib(struct tac_attrib **);

/* acct_s.c */
char *tac_acct_flag2str(u_char);
void tac_acct_send_pkt(struct tac_session *, u_char, const char *,
    const char *, const char *, struct tac_attrib *, u_char **, unsigned *);
int tac_acct_send(struct tac_session *, int, u_char, const char *,
    const char *, const char *, struct tac_attrib *);

/* acct_r.c */
int tac_acct_parse(struct tac_session *, u_char *, unsigned,
    struct areply *);
int tac_acct_read(struct tac_session *, int, struct areply *);

/* xalloc.c */
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
char *xstrcpy(char *, const char *, size_t);

/* hdr_check.c */
char *_tac_check_header(struct tac_session *, HDR *, uint8_t);

/* magic.c */
u_int32_t magic(void);

/* read_wait.c */
int tac_read_wait(int, int, int, int *);

#ifdef __cplusplus
}
#endif

#endif
