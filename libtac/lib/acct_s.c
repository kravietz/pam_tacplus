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
#ifdef HAVE_CONFIG_H

#include "config.h"

#endif

#include <fcntl.h>

#include "libtac.h"

char *tac_acct_flag2str(int flag) {
    switch (flag) {
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

/*
 * return value:
 *      0 : success
 *   <  0 : error status code, see LIBTAC_STATUS_...
 *             LIBTAC_STATUS_WRITE_ERR
 *             LIBTAC_STATUS_WRITE_TIMEOUT  (pending impl)
 *             LIBTAC_STATUS_ASSEMBLY_ERR   (pending impl)
 7.1.  The Account REQUEST Packet Body

    1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
   +----------------+----------------+----------------+----------------+
   |      flags     |  authen_method |    priv_lvl    |  authen_type   |
   +----------------+----------------+----------------+----------------+
   | authen_service |    user_len    |    port_len    |  rem_addr_len  |
   +----------------+----------------+----------------+----------------+
   |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
   +----------------+----------------+----------------+----------------+
   |   arg_N_len    |    user ...
   +----------------+----------------+----------------+----------------+
   |   port ...
   +----------------+----------------+----------------+----------------+
   |   rem_addr ...
   +----------------+----------------+----------------+----------------+
   |   arg_1 ...
   +----------------+----------------+----------------+----------------+
   |   arg_2 ...
   +----------------+----------------+----------------+----------------+
   |   ...
   +----------------+----------------+----------------+----------------+
   |   arg_N ...
   +----------------+----------------+----------------+----------------+

 */
int tac_acct_send(int fd, int type, const char *user, char *tty,
                  char *r_addr, gl_list_t attr)
{

    HDR *th;
    struct acct tb;
    int attribute_counter;
    int total_attributes_size;
    unsigned char user_len;
    unsigned char port_len;
    unsigned char r_addr_len;
    int i;
    size_t pkt_len = 0;
    ssize_t w;
    uint8_t *pkt = NULL;
    int ret = 0;
    size_t total_packet_length;
    char *current_attribute;
    gl_list_iterator_t attributes_iterator;
    // all received attributes are cached locally which simplifies operations
    // and is feasible as there's only max 255 of them
    char *attribute_cache[TAC_PLUS_ATTRIB_MAX_CNT];
    // attribute lengths are max 255 bytes and they occupy one byte
    uint8_t attribute_len_cache[TAC_PLUS_ATTRIB_MAX_CNT];

    memset(&attribute_len_cache, 0, sizeof(attribute_len_cache));
    memset(&attribute_cache, 0, sizeof(attribute_cache));

    // get pre-filled header template
    th = _tac_req_header(TAC_PLUS_AUTHOR, false);

    /* amend header options */
    th->version = TAC_PLUS_VER_0;
    th->encryption =
            tac_encryption ? TAC_PLUS_ENCRYPTED_FLAG : TAC_PLUS_UNENCRYPTED_FLAG;
    /* header now waits for data_length which will be calculated after body is built */

    TACDEBUG(LOG_DEBUG, "%s: user '%s', tty '%s', rem_addr '%s', encrypt: %s",
             __FUNCTION__, user,
             tty, r_addr, tac_encryption ? "yes" : "no");

    user_len = (unsigned char) strlen(user);
    port_len = (unsigned char) strlen(tty);
    r_addr_len = (unsigned char) strlen(r_addr);

    // unique to accounting packet
    tb.flags = (unsigned char) type;

    // fill-in body template
    tb.authen_method = tac_authen_method;
    tb.priv_lvl = tac_priv_lvl;
    if (!*tac_login) {
        /* default to PAP */
        tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
    } else {
        if (strcmp(tac_login, "chap") == 0) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_CHAP;
        } else if (strcmp(tac_login, "login") == 0) {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_ASCII;
        } else {
            tb.authen_type = TAC_PLUS_AUTHEN_TYPE_PAP;
        }
    }
    tb.authen_service = tac_authen_service;
    tb.user_len = user_len;
    tb.port_len = port_len;
    tb.r_addr_len = r_addr_len;
    // tb.arg_cnt not yet available, filled in later down

    /* allocate packet */
    pkt = (unsigned char *) xcalloc(1, TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
    pkt_len = sizeof(tb);

    // iterate through the received list of attributes and build a local cache
    // of attribute pointers and their lengths
    attribute_counter = 0;
    total_attributes_size = 0;
    attributes_iterator = gl_list_iterator(attr);
    while (gl_list_iterator_next(&attributes_iterator, (const void **) &current_attribute, NULL)) {
        attribute_cache[attribute_counter] = xstrdup(current_attribute);
        attribute_len_cache[attribute_counter] = (size_t) strlen(current_attribute);
        total_attributes_size += attribute_len_cache[attribute_counter];
        attribute_counter++;
    }
    gl_list_iterator_free(&attributes_iterator);

    tb.arg_cnt = attribute_counter;

    // we can now calculate total packet size, extrapolating length of attributes
    total_packet_length = (size_t) (sizeof(tb) + user_len + port_len + r_addr_len +
                                    (attribute_counter * sizeof(uint8_t)) + total_attributes_size);
    pkt = (unsigned char *) xcalloc(1, total_packet_length);

    // copy the fixed fields
    memcpy(pkt, &tb, sizeof(tb));
    pkt_len = sizeof(tb);

    // copy attribute length fields to the packet buffer
    for (i = 0; i < attribute_counter; i++) {
        memcpy(pkt + pkt_len, &attribute_len_cache[i], sizeof(unsigned char));
        pkt_len += sizeof(unsigned char);
    }
    // copy fixed fields to the packet buffer
    memcpy(pkt + pkt_len, user, user_len);
    pkt_len += user_len;
    memcpy(pkt + pkt_len, tty, port_len);
    pkt_len += port_len;
    memcpy(pkt + pkt_len, r_addr, r_addr_len);
    pkt_len += r_addr_len;

    // copy attributes into the packet buffer
    for (i = 0; i < attribute_counter; i++) {
        memcpy(pkt + pkt_len, attribute_cache[i], attribute_len_cache[i]);
        free(attribute_cache[i]);
        pkt_len += attribute_len_cache[i];
    }

    // finished building packet, fill len_from_header in header
    th->datalength = htonl(pkt_len);

    // send header to the server
    w = write(fd, th, TAC_PLUS_HDR_SIZE);

    if (w < TAC_PLUS_HDR_SIZE) {
        TACSYSLOG(
                LOG_ERR, "%s: short write on header, wrote %ld of %d: %m", __FUNCTION__, w, TAC_PLUS_HDR_SIZE);
        free(pkt);
        free(th);
        return LIBTAC_STATUS_WRITE_ERR;
    }

    // obfuscate packet body
    _tac_obfuscate(pkt, th);

    // send body to the server
    w = write(fd, pkt, pkt_len);
    if (w < (ssize_t) pkt_len) {
        TACSYSLOG(
                LOG_ERR, "%s: short write on body, wrote %ld of %lu: %m", __FUNCTION__, w, pkt_len);
        ret = LIBTAC_STATUS_WRITE_ERR;
    }

    free(pkt);
    free(th);
    TACDEBUG(LOG_DEBUG, "%s: exit status=%d", __FUNCTION__, ret);
    return ret;
}
