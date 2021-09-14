/* support.h - support functions for pam_tacplus.c
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

#ifndef PAM_TACPLUS_SUPPORT_H
#define PAM_TACPLUS_SUPPORT_H

#include "libtac.h"

#include <security/pam_modules.h>

#define TAC_SECRET_MAX_LEN   64

typedef struct {
    struct addrinfo *addr;
    const char *key;
    unsigned int timeout;
    struct addrinfo *source_addr;
} tacplus_server_t;

extern tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
extern unsigned int tac_srv_no;

extern char tac_service[64];
extern char tac_protocol[64];
extern char tac_prompt[64];

void tac_copy_addr_info(struct addrinfo *p_dst, const struct addrinfo *p_src);

int _pam_parse(int, const char **);

unsigned long _resolve_name(char *);

unsigned long _getserveraddr(char *serv);

int tacacs_get_password(pam_handle_t *, int, int, char **);

int converse(pam_handle_t *, int, const struct pam_message *, struct pam_response **);

void _pam_log(int, const char *, ...);

void *_xcalloc(size_t);

char *_pam_get_user(pam_handle_t *);

char *_pam_get_terminal(pam_handle_t *);

char *_pam_get_rhost(pam_handle_t *);

/* Used to mute gcc/clang "unused parameter" warnings */
#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

#ifdef __GNUC__
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#  define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

#endif  /* PAM_TACPLUS_SUPPORT_H */

