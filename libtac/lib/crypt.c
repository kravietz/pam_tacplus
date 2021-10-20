/* crypt.c - TACACS+ encryption related functions
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

#include "libtac.h"
#include "xalloc.h"

#include "md5.h"

/* CHAP digest per https://datatracker.ietf.org/doc/html/rfc1994
The target `digest` buffer must be at least MD5_DIGEST_SIZE long.
*/
void digest_chap(unsigned char *digest, unsigned char id,
                 const char *pass, unsigned pass_len,
                 const char *chal, unsigned chal_len)
{

    struct md5_ctx mdcontext;

    md5_init_ctx(&mdcontext);
    md5_process_bytes(&id, sizeof(id), &mdcontext);
    md5_process_bytes((const unsigned char *)pass, pass_len, &mdcontext);
    md5_process_bytes((const unsigned char *)chal, chal_len, &mdcontext);
    md5_finish_ctx(&mdcontext, digest);
}

/* Produce MD5 pseudo-random pad for TACACS+ encryption.
   Use data from packet header and secret, which
   should be a global variable */
static void _tac_md5_pad(const HDR *hdr,
                         unsigned char *new_digest, unsigned char *old_digest)
{
    unsigned tac_secret_len = strlen(tac_secret);
    struct md5_ctx mdcontext;

    /* MD5_1 = MD5{session_id, secret, version, seq_no}
       MD5_2 = MD5{session_id, secret, version, seq_no, MD5_1} */

    /* place session_id, key, version and seq_no in buffer */
    md5_init_ctx(&mdcontext);
    md5_process_bytes((const unsigned char *)&hdr->session_id, sizeof(hdr->session_id), &mdcontext);
    md5_process_bytes((const unsigned char *)tac_secret, tac_secret_len, &mdcontext);
    md5_process_bytes(&hdr->version, sizeof(hdr->version), &mdcontext);
    md5_process_bytes(&hdr->seq_no, sizeof(hdr->seq_no), &mdcontext);

    /* append previous pad if this is not the first run */
    if (old_digest)
    {
        md5_process_bytes(old_digest, MD5_DIGEST_SIZE, &mdcontext);
    }

    md5_finish_ctx(&mdcontext, new_digest);

} /* _tac_md5_pad */

/*
 * The body of packets may be obfuscated.  The following sections
   describe the obfuscation method that is supported in the protocol.
   In "The Draft", this process was actually referred to as Encryption,
   but the algorithm would not meet modern standards and so will not be
   termed as encryption in this document.
 * https://datatracker.ietf.org/doc/html/rfc8907#section-4.5
 */
void _tac_obfuscate(unsigned char *buf, const HDR *th)
{
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int length = ntohl(th->datalength);
    unsigned char digest[MD5_DIGEST_SIZE];

    if ((tac_secret == NULL) || (th->encryption & TAC_PLUS_UNENCRYPTED_FLAG) == TAC_PLUS_UNENCRYPTED_FLAG)
    {
        TACSYSLOG(LOG_WARNING, "%s: no-op, using no TACACS+ obfuscation", __FUNCTION__);
        return;
    }

    for (i = 0; i < length; i++)
    {
        j = i % MD5_DIGEST_SIZE;

        /* At the beginning of every block (16 bytes, i.e. the size
             * of an MD5 digest), generate a new pad to XOR against.
             * For the 2nd and all successive blocks, we prime it with
             * the previous digest.
             */
        if (j == 0)
            _tac_md5_pad(th, digest, ((i > 0) ? digest : NULL));

        buf[i] ^= digest[j];
    }

} /* _tac_obfuscate */
