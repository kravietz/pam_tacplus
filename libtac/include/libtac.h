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

/* header.c */
extern int session_id;
extern int tac_encryption;
extern const char *tac_secret;
extern char tac_login[64];
extern int tac_priv_lvl;
extern int tac_authen_method;
extern int tac_authen_service;

extern int tac_debug_enable;
extern int tac_readtimeout_enable;

/* we return a void * because there are different types of bodies */
static inline void *tac_hdr_to_body(HDR *th)
{
    return (void *)((u_char *)th + TAC_PLUS_HDR_SIZE);
}

HDR *_tac_req_header(u_char, int);

/* connect.c */
extern int tac_timeout;

int tac_connect(struct addrinfo **, char **, int);
int tac_connect_single(const struct addrinfo *, const char *, struct addrinfo *,
		int);
char *tac_ntop(const struct sockaddr *);

/* authen_s.c */
u_char tac_get_authen_type(const char *);
void tac_authen_send_pkt(const char *, const char *, const char *,
    const char *, u_char, u_char **, unsigned *);
int tac_authen_send(int, const char *, const char *, const char *,
    const char *, u_char);

/* authen_r.c */
int tac_authen_parse(struct areply *, u_char *, unsigned);
int tac_authen_read(int, struct areply *);

/* cont_s.c */
void tac_cont_send_pkt(const char *, uint8_t, u_char **, unsigned *);
int tac_cont_send_seq(int, const char *, uint8_t);
#define tac_cont_send(fd, pass) tac_cont_send_seq((fd), (pass), 3)

/* crypt.c */
void _tac_crypt(u_char *, const HDR *);

/* author_r.c */
int tac_author_parse(u_char *, unsigned, struct areply *);
int tac_author_read(int, struct areply *);

/* author_s.c */
void tac_author_send_pkt(const char *, const char *, const char *,
    struct tac_attrib *, u_char **, unsigned *);
int tac_author_send(int, const char *, const char *, const char *,
    struct tac_attrib *);

/* attrib.c */
void tac_add_attrib(struct tac_attrib **, char *, char *);
void tac_add_attrib_pair(struct tac_attrib **, char *, char, char *);
void tac_free_attrib(struct tac_attrib **);

/* acct_s.c */
char *tac_acct_flag2str(u_char);
void tac_acct_send_pkt(u_char, const char *, const char *, const char *,
    struct tac_attrib *, u_char **, unsigned *);
int tac_acct_send(int, u_char, const char *, const char *, const char *,
    struct tac_attrib *);

/* acct_r.c */
int tac_acct_parse(u_char *, unsigned, struct areply *);
int tac_acct_read(int, struct areply *);

/* xalloc.c */
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
char *xstrcpy(char *, const char *, size_t);

/* hdr_check.c */
char *_tac_check_header(HDR *, uint8_t);

/* magic.c */
u_int32_t magic(void);

/* read_wait.c */
int tac_read_wait(int, int, int, int *);

#ifdef __cplusplus
}
#endif

#endif
