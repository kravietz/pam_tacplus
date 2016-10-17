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

#include "libtac.h"
#include "xalloc.h"

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#if defined(HAVE_OPENSSL_MD5_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/md5.h>
#else
# include "md5.h"
#endif

/* Produce MD5 pseudo-random pad for TACACS+ encryption.
   Use data from packet header and secret, which
   should be a global variable */
static void _tac_md5_pad(const HDR *hdr,
        u_char *new_digest, u_char *old_digest)  {
    unsigned tac_secret_len = strlen(tac_secret);
    MD5_CTX mdcontext;

    /* MD5_1 = MD5{session_id, secret, version, seq_no}
       MD5_2 = MD5{session_id, secret, version, seq_no, MD5_1} */

    /* place session_id, key, version and seq_no in buffer */
    MD5_Init(&mdcontext);
    MD5_Update(&mdcontext, (const u_char *) &hdr->session_id, sizeof(hdr->session_id));
    MD5_Update(&mdcontext, (const u_char *) tac_secret, tac_secret_len);
    MD5_Update(&mdcontext, &hdr->version, sizeof(hdr->version));
    MD5_Update(&mdcontext, &hdr->seq_no, sizeof(hdr->seq_no));

    /* append previous pad if this is not the first run */
    if (old_digest) {
        MD5_Update(&mdcontext, old_digest, MD5_LBLOCK);
    }

    MD5_Final(new_digest, &mdcontext);
 
}    /* _tac_md5_pad */

/* Perform encryption/decryption on buffer. This means simply XORing
   each byte from buffer with according byte from pseudo-random
   pad. */
void _tac_crypt(u_char *buf, const HDR *th) {
    unsigned i, j, length = ntohl(th->datalength);
 
    /* null operation if no encryption requested */
    if((tac_secret != NULL) && (th->encryption & TAC_PLUS_UNENCRYPTED_FLAG) != TAC_PLUS_UNENCRYPTED_FLAG) {
        u_char digest[MD5_LBLOCK];
 
        for (i=0; i<length; i++) {
            j = i % MD5_LBLOCK;

            /* At the beginning of every block (16 bytes, i.e. the size
             * of an MD5 digest), generate a new pad to XOR against.
             * For the 2nd and all successive blocks, we prime it with
             * the previous digest.
             */
            if (j == 0)
                _tac_md5_pad(th, digest, ((i > 0) ? digest : NULL));

            buf[i] ^= digest[j];
        }
    } else {
        TACSYSLOG(LOG_WARNING, "%s: using no TACACS+ encryption", __FUNCTION__);
    }
}    /* _tac_crypt */
