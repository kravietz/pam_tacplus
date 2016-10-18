/* session.c - Parameters for concurrent Tacacs+ sessions
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

#include "libtac.h"
#include "xalloc.h"

/*
 * like tac_session_alloc() but with n extra bytes of room at the bottom
 */

struct tac_session *
tac_session_alloc_extra(unsigned n)
{
    struct tac_session *sess = (struct tac_session *)xcalloc(1, sizeof(*sess) + n);

    sess->tac_timeout = 5;
    sess->tac_secret = NULL;
    sess->tac_session_id = magic();
    sess->tac_encryption = false;
    sess->tac_priv_lvl = TAC_PLUS_PRIV_LVL_MIN;
    sess->tac_authen_service = TAC_PLUS_AUTHEN_SVC_PPP;
    sess->tac_authen_method = TAC_PLUS_AUTHEN_METH_TACACSPLUS;
    sess->tac_authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
    sess->seq_no = 0;

    return sess;
}

struct tac_session *
tac_session_alloc(void)
{
    return tac_session_alloc_extra(0);
}

void
tac_session_set_secret(struct tac_session *sess, const char *secret)
{
    if (secret == NULL || !*secret) {
        sess->tac_encryption = false;
        sess->tac_secret = NULL;
    } else {
        sess->tac_encryption = true;
        sess->tac_secret = secret;
    }
}

void
tac_session_set_authen_type(struct tac_session *sess, uint8_t type)
{
    sess->tac_authen_type = type;
}

void
tac_session_set_timeout(struct tac_session *sess, unsigned timeout)
{
    sess->tac_timeout = timeout;
}

void
tac_session_new_session_id(struct tac_session *sess)
{
    sess->tac_session_id = magic();
}

void
tac_session_reset_seq(struct tac_session *sess)
{
    sess->seq_no = 0;
}

void *
tac_session_get_user_data(struct tac_session *sess)
{
    return &sess->user_data;
}

void
tac_session_free(struct tac_session *sess)
{
    free(sess);
}

