/* author_s.c - Send authorization request to the server.
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

/* Send authorization request to the server, along with attributes
   specified in attribute list prepared with tac_add_attrib.
 *
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *         LIBTAC_STATUS_WRITE_ERR
 *         LIBTAC_STATUS_WRITE_TIMEOUT (pending impl)
 *         LIBTAC_STATUS_ASSEMBLY_ERR  (pending impl)
 */
int tac_author_send(int fd, const char *user, char *tty, char *r_addr,
    struct tac_attrib *attr) {

    HDR *th;
    struct author tb;
    u_char user_len, port_len, r_addr_len;
    struct tac_attrib *a;
    int i = 0;              /* attributes count */
    int pkt_len = 0;    /* current packet length */
    int pktl = 0;       /* temporary storage for previous pkt_len values */
    int w;              /* write() return value */
    u_char *pkt = NULL;         /* packet building pointer */
    /* u_char *pktp; */         /* obsolete */
    int ret = 0;

    th=_tac_req_header(TAC_PLUS_AUTHOR, 0);

    /* set header options */
    th->version=TAC_PLUS_VER_0;
    th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;

    TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s", \
        __FUNCTION__, user, \
        tty, r_addr, tac_encryption ? "yes" : "no"))
    
    user_len = (u_char) strlen(user);
    port_len = (u_char) strlen(tty);
    r_addr_len = (u_char) strlen(r_addr);

    tb.authen_method = tac_authen_method;
    tb.priv_lvl = tac_priv_lvl;
    if (!*tac_login) {
        /* default to PAP */
        tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
    } else {
        if (strcmp(tac_login,"chap") == 0) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
        } else if (strcmp(tac_login,"login") == 0) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
        } else {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
        }
    }
    tb.service = tac_authen_service;
    tb.user_len = user_len;
    tb.port_len = port_len;
    tb.r_addr_len = r_addr_len;

    /* allocate packet */
    pkt = (u_char *) xcalloc(1, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);
    pkt_len = sizeof(tb);

    /* fill attribute length fields */
    a = attr;
    while (a) {
        pktl = pkt_len;
        pkt_len += sizeof(a->attr_len);
        pkt = (u_char*) xrealloc(pkt, pkt_len);

        /* bad method: realloc() is allowed to return different pointer
           with each call
        pktp=pkt + pkt_len; 
        pkt_len += sizeof(a->attr_len);
        pkt = xrealloc(pkt, pkt_len);   
        */
                
        bcopy(&a->attr_len, pkt + pktl, sizeof(a->attr_len));
        i++;

        a = a->next;
    }

    /* fill the arg count field and add the fixed fields to packet */
    tb.arg_cnt = i;
    bcopy(&tb, pkt, TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE);
/*
#define PUTATTR(data, len) \
    pktp = pkt + pkt_len; \
    pkt_len += len; \
    pkt = xrealloc(pkt, pkt_len); \
    bcopy(data, pktp, len);
*/

#define PUTATTR(data, len) \
    pktl = pkt_len; \
    pkt_len += len; \
    pkt = (u_char*) xrealloc(pkt, pkt_len); \
    bcopy(data, pkt + pktl, len);

    /* fill user and port fields */
    PUTATTR(user, user_len)
    PUTATTR(tty, port_len)
    PUTATTR(r_addr, r_addr_len)

    /* fill attributes */
    a = attr;
    while (a) {
        PUTATTR(a->attr, a->attr_len)

        a = a->next;
    }

    /* finished building packet, fill len_from_header in header */
    th->datalength = htonl(pkt_len);

    /* write header */
    w = write(fd, th, TAC_PLUS_HDR_SIZE);

    if (w < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG((LOG_ERR,\
            "%s: short write on header, wrote %d of %d: %m",\
            __FUNCTION__, w, TAC_PLUS_HDR_SIZE))
        free(pkt);
        free(th);
        return LIBTAC_STATUS_WRITE_ERR;
    }
    
    /* encrypt packet body  */
    _tac_crypt(pkt, th, pkt_len);

    /* write body */
    w = write(fd, pkt, pkt_len);
    if (w < pkt_len) {
        TACSYSLOG((LOG_ERR,\
            "%s: short write on body, wrote %d of %d: %m",\
            __FUNCTION__, w, pkt_len))
        ret = LIBTAC_STATUS_WRITE_ERR;
    }

    free(pkt);
    free(th);
    TACDEBUG((LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret))
    return ret;
}
