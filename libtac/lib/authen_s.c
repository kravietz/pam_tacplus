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

#ifdef HAVE_CONFIG_H

#include "config.h"

#endif

#include <fcntl.h>


#include "libtac.h"


/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT
 *             LIBTAC_STATUS_ASSEMBLY_ERR
 * 5.1.  The Authentication START Packet Body

    1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
   +----------------+----------------+----------------+----------------+
   |    action      |    priv_lvl    |  authen_type   | authen_service |
   +----------------+----------------+----------------+----------------+
   |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
   +----------------+----------------+----------------+----------------+
   |    user ...
   +----------------+----------------+----------------+----------------+
   |    port ...
   +----------------+----------------+----------------+----------------+
   |    rem_addr ...
   +----------------+----------------+----------------+----------------+
   |    data...
   +----------------+----------------+----------------+----------------+
 */
int tac_authen_send(int fd, const char *user, const char *pass, const char *tty,
                    const char *r_addr, unsigned char action) {

    HDR *th;                /* TACACS+ packet header */
    struct authen_start tb; /* message body */
    uint8_t user_len;
    uint8_t port_len;
    uint8_t r_addr_len;
    uint8_t pass_len;
    uint32_t bodylength;
    ssize_t w;
    size_t pkt_len = 0;
    int ret = 0;
    uint8_t *pkt = NULL;

    // authentication token, which will be plaintext password for PAP or challenge for CHAP
    char *token = NULL;
    uint8_t token_len;


    // get pre-filled header template
    th = _tac_req_header(TAC_PLUS_AUTHEN, false);

    /* amend header options */
    if (strcmp(tac_login, "login") == 0) {
        th->version = TAC_PLUS_VER_0;
    } else {
        th->version = TAC_PLUS_VER_1;
    }
    th->encryption =
            tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;
    /* header now waits for data_length which will be calculated after body is built */

    TACDEBUG(LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s",
             __FUNCTION__, user, tty, r_addr,
             (tac_encryption) ? "yes" : "no");

    /* get sizes of submitted data */
    user_len = (unsigned char) strlen(user);
    pass_len = (unsigned char) strlen(pass);
    port_len = (unsigned char) strlen(tty);
    r_addr_len = (unsigned char) strlen(r_addr);

    if (strcmp(tac_login, "chap") == 0) {
        const uint8_t id = TACPLUS_ALGORITHM_CHAP_MD5;
        unsigned char challenge[MD5_DIGEST_SIZE];
        unsigned char digest[sizeof(challenge)];

        token_len = sizeof(id) + sizeof(challenge) + sizeof(digest);
        token = xcalloc(1, token_len);

        digest_chap(digest, id, pass, pass_len, challenge, sizeof(challenge));

        // build the CHAP challenge packet
        memcpy(token, &id, sizeof(id));
        memcpy(token + sizeof(id), challenge, sizeof(challenge));
        memcpy(token + sizeof(id) + sizeof(challenge), digest, sizeof(digest));

    } else {
        // for PAP, just copy passed credentials
        token = xstrdup(pass);
        token_len = strlen(pass);
    }

    /* fill the body of message */
    tb.action = action;
    tb.priv_lvl = tac_priv_lvl;
    if (!*tac_login) {
        /* default to PAP */
        tb.authen_type =
                action == TAC_PLUS_AUTHEN_CHPASS ? TAC_PLUS_AUTHEN_TYPE_ASCII : TAC_PLUS_AUTHEN_TYPE_PAP;
    } else {
        if (!strcmp(tac_login, "chap")) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
        } else if (!strcmp(tac_login, "login")) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
        } else {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
        }
    }

    /* data field is not used in ASCII login */
    if (tb.authen_type == TAC_PLUS_AUTHEN_TYPE_ASCII) {
        token_len = 0;
    }

    tb.service = tac_authen_service;
    tb.user_len = user_len;
    tb.port_len = port_len;
    tb.r_addr_len = r_addr_len; /* may be e.g Caller-ID in future */
    tb.data_len = token_len;

    /* body length can be now extrapolated and copied into the header */
    bodylength = sizeof(tb) + user_len + port_len + r_addr_len + token_len;
    th->datalength = htonl(bodylength);

    /* we can now write the header */
    w = write(fd, th, TAC_PLUS_HDR_SIZE);
    if (w < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG(
                LOG_ERR, "%s: short write on header, wrote %zd of %d: %m", __FUNCTION__, w, TAC_PLUS_HDR_SIZE);
        free(token);
        free(pkt);
        free(th);
        return LIBTAC_STATUS_WRITE_ERR;
    }

    /* build the packet */
    pkt = (unsigned char *) xcalloc(1, bodylength);

    memcpy(pkt + pkt_len, &tb, sizeof(tb)); /* packet body beginning */
    pkt_len += sizeof(tb);
    memcpy(pkt + pkt_len, user, user_len); /* user */
    pkt_len += user_len;
    memcpy(pkt + pkt_len, tty, port_len); /* tty */
    pkt_len += port_len;
    memcpy(pkt + pkt_len, r_addr, r_addr_len); /* rem addr */
    pkt_len += r_addr_len;

    memcpy(pkt + pkt_len, token, token_len); /* password */
    free(token);
    pkt_len += token_len;

    /* encrypt the body */
    _tac_obfuscate(pkt, th);
    free(th);

    w = write(fd, pkt, pkt_len);
    free(pkt);
    if (w < (ssize_t) pkt_len) {
        TACSYSLOG(
                LOG_ERR, "%s: short write on body, wrote %zd of %zu: %m", __FUNCTION__, w, pkt_len);
        ret = LIBTAC_STATUS_WRITE_ERR;
    }

    TACDEBUG(LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret);
    return ret;
} /* tac_authen_send */
