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
#include "tacplus.h"

#if defined(DEBUGTAC) && !defined(TACDEBUG)
#define TACDEBUG(x) syslog x;
#else
//#define TACDEBUG(x) syslog x;
#define TACDEBUG(x)
#endif

#define TACSYSLOG(x) syslog x;

#if defined(TACDEBUG_AT_RUNTIME)
#undef TACDEBUG
#undef TACSYSLOG
#define TACDEBUG(x) if (tac_debug_enable) (void)logmsg x;
#define TACSYSLOG(x) (void)logmsg x;
extern int logmsg __P((int, const char*, ...));
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
    int status;
};

#ifndef TAC_PLUS_MAXSERVERS		
#define TAC_PLUS_MAXSERVERS 8
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

/* connect.c */
extern int tac_timeout;

int tac_connect(struct addrinfo **, char **, int);
int tac_connect_single(struct addrinfo *, const char *, struct addrinfo *, int);
char *tac_ntop(const struct sockaddr *);

int tac_authen_send(int, const char *, char *, char *,
    char *);
int tac_authen_read(int);
int tac_cont_send(int, char *);
HDR *_tac_req_header(u_char, int);
void _tac_crypt(u_char *, HDR *, int);
u_char *_tac_md5_pad(int, HDR *);
void tac_add_attrib(struct tac_attrib **, char *, char *);
void tac_free_attrib(struct tac_attrib **);
char *tac_acct_flag2str(int);
int tac_acct_send(int, int, const char *, char *, char *,
    struct tac_attrib *);
int tac_acct_read(int, struct areply *);
void *xcalloc(size_t, size_t);
void *xrealloc(void *, size_t);
char *xstrcpy(char *, const char *, size_t);
char *_tac_check_header(HDR *, int);
int tac_author_send(int, const char *, char *, char *,
    struct tac_attrib *);
int tac_author_read(int, struct areply *);
void tac_add_attrib_pair(struct tac_attrib **, char *, char,
    char *);
int tac_read_wait(int, int, int, int *);

/* magic.c */
u_int32_t magic(void);

#ifdef __cplusplus
}
#endif

#endif
