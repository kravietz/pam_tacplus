/* authen_s.c - Send authentication request to the server.
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
#include "md5.h"

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT
 *             LIBTAC_STATUS_ASSEMBLY_ERR
 */
int tac_authen_send(int fd, const char *user, char *pass, char *tty,
    char *r_addr) {

    HDR *th;    /* TACACS+ packet header */
    struct authen_start tb;     /* message body */
    int user_len, port_len, chal_len, mdp_len, token_len, bodylength, w;
    int r_addr_len;
    int pkt_len = 0;
    int ret = 0;
    char *chal = "1234123412341234";
    char digest[MD5_LEN];
    char *token = NULL;
    u_char *pkt = NULL, *mdp = NULL;
    MD5_CTX mdcontext;

    th=_tac_req_header(TAC_PLUS_AUTHEN, 0);

    /* set some header options */
    if (!strcmp(tac_login,"login")) {
        th->version = TAC_PLUS_VER_0;
    } else {
        th->version = TAC_PLUS_VER_1;
    }
    th->encryption = tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;

    TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s", \
        __FUNCTION__, user, tty, r_addr, \
        (tac_encryption) ? "yes" : "no"))        
        
    if (!strcmp(tac_login,"chap")) {
        chal_len = strlen(chal);
        mdp_len = sizeof(u_char) + strlen(pass) + chal_len;
        mdp = (u_char *) xcalloc(1, mdp_len);
        mdp[0] = 5;
        memcpy(&mdp[1], pass, strlen(pass));
        memcpy(mdp + strlen(pass) + 1, chal, chal_len);
        MD5Init(&mdcontext);
        MD5Update(&mdcontext, mdp, mdp_len);
        MD5Final((u_char *) digest, &mdcontext);
        free(mdp);
        token = (char*) xcalloc(1, sizeof(u_char) + 1 + chal_len + MD5_LEN);
        token[0] = 5;
        memcpy(&token[1], chal, chal_len);
        memcpy(token + chal_len + 1, digest, MD5_LEN);
    } else {
        token = xstrdup(pass);
    }

    /* get size of submitted data */
    user_len = strlen(user);
    port_len = strlen(tty);
    r_addr_len = strlen(r_addr);
    token_len = strlen(token);

    /* fill the body of message */
    tb.action = TAC_PLUS_AUTHEN_LOGIN;
    tb.priv_lvl = tac_priv_lvl;
    if (!*tac_login) {
        /* default to PAP */
        tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
    } else {
        if (!strcmp(tac_login,"chap")) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
        } else if (!strcmp(tac_login,"login")) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
        } else {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
        }
    }
    tb.service = tac_authen_service;
    tb.user_len = user_len;
    tb.port_len = port_len;
    tb.r_addr_len = r_addr_len;    /* may be e.g Caller-ID in future */
    tb.data_len = token_len;

    /* fill body length in header */
    bodylength = sizeof(tb) + user_len
        + port_len + r_addr_len + token_len;

    th->datalength = htonl(bodylength);

    /* we can now write the header */
    w = write(fd, th, TAC_PLUS_HDR_SIZE);
    if (w < 0 || w < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: short write on header, wrote %d of %d: %m",\
            __FUNCTION__, w, TAC_PLUS_HDR_SIZE))
        free(token);
        free(pkt);
        free(th);
        return LIBTAC_STATUS_WRITE_ERR;
    }

    /* build the packet */
    pkt = (u_char *) xcalloc(1, bodylength+10);

    bcopy(&tb, pkt+pkt_len, sizeof(tb)); /* packet body beginning */
    pkt_len += sizeof(tb);
    bcopy(user, pkt+pkt_len, user_len);  /* user */
    pkt_len += user_len;
    bcopy(tty, pkt+pkt_len, port_len);   /* tty */
    pkt_len += port_len;
    bcopy(r_addr, pkt+pkt_len, r_addr_len);   /* rem addr */
    pkt_len += r_addr_len;

    bcopy(token, pkt+pkt_len, token_len);  /* password */
    pkt_len += token_len;

    /* pkt_len == bodylength ? */
    if (pkt_len != bodylength) {
        TACSYSLOG((LOG_ERR, "%s: bodylength %d != pkt_len %d",\
            __FUNCTION__, bodylength, pkt_len))
        free(token);
        free(pkt);
        free(th);
        return LIBTAC_STATUS_ASSEMBLY_ERR;
    } 
        
    /* encrypt the body */
    _tac_crypt(pkt, th, bodylength);

    w = write(fd, pkt, pkt_len);
    if (w < 0 || w < pkt_len) {
        TACSYSLOG((LOG_ERR,\
            "%s: short write on body, wrote %d of %d: %m",\
            __FUNCTION__, w, pkt_len))
        ret = LIBTAC_STATUS_WRITE_ERR;
    }

    free(token);
    free(pkt);
    free(th);
    TACDEBUG((LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret))
    return ret;
}    /* tac_authen_send */
