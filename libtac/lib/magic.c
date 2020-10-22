/* magic.c - PPP Magic Number routines.
 * 
 * Copyright (C) 1989 Carnegie Mellon University.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "magic.h"

#ifdef _MSC_VER
# pragma section(".CRT$XCU",read)
# define INITIALIZER2_(f,p) \
	static void f(void); \
	__declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
	__pragma(comment(linker,"/include:" p #f "_")) \
	static void f(void)
# ifdef _WIN64
#  define INITIALIZER(f) INITIALIZER2_(f,"")
# else
#  define INITIALIZER(f) INITIALIZER2_(f,"_")
# endif
#else /* __GNUC__ */
# define INITIALIZER(f) \
	static void f(void) __attribute__((constructor)); \
	static void f(void)
#endif

#if defined(HAVE_GETRANDOM)

# if defined(HAVE_SYS_RANDOM_H)
#  include <sys/random.h>
# else
#  error no header containing getrandom(2) declaration
# endif

/* getrandom(2) is the most convenient and secure options from our point of view so it's on the first order of preference */

u_int32_t
magic()
{
    u_int32_t num;
    ssize_t ret;

    ret = getrandom(&num, sizeof(num), GRND_NONBLOCK);
    if(ret < 0) {
    	TACSYSLOG(LOG_CRIT,"%s: getrandom failed to provide random bytes: %s", __FUNCTION__, strerror(errno));
    	exit(1);
    }
    if(ret < (ssize_t) sizeof(num)) {
    	TACSYSLOG(LOG_CRIT,"%s: getrandom less bytes than expected: %zd vs %zu", __FUNCTION__, ret, sizeof(num));
    	exit(1);
    }
    return num;
}

#elif defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)

#include <openssl/err.h>
#include <openssl/rand.h>

/* RAND_bytes is OpenSSL's classic function to obtain cryptographic strength pseudo-random bytes
   however, we can use RAND_pseudo_bytes() which doesn't deplete the system's entropy pool, so long
   as it returns a "cryptographically strong" result - since session_id is an input to the TACACS+
   "encryption" ("obfuscation" by modern standards - RFC 8907) algorithm.
   */

u_int32_t
magic()
{
    u_int32_t num;
    int ret;

#ifdef HAVE_RAND_BYTES
    ret = RAND_bytes((unsigned char *)&num, sizeof(num));
#elif HAVE_RAND_PSEUDO_BYTES
    ret = RAND_pseudo_bytes((unsigned char *)&num, sizeof(num));
#else
	#error Neither  RAND_bytes nor RAND_pseudo_bytes seems to be available
#endif

    /* RAND_bytes success / RAND_pseudo_bytes "cryptographically strong" result */
    if (ret == 1)
        return num;

    TACSYSLOG(LOG_CRIT,"%s: "
#ifdef HAVE_RAND_BYTES
                       "RAND_bytes "
#else
                       "RAND_pseudo_bytes "
#endif
                       "failed; ret: %d err: %ld", __FUNCTION__, ret, ERR_get_error());

    exit(1);
}

#else

/* Finally, if nothing else works, use the legacy function that will use random(3) seeded from /dev/urandom,
 * or just use a weak PRNG initialisation using time. But since magic() is used for session identifier and not crypto
 * keys generation it can be used as a last resort.
 */
INITIALIZER(magic_init)
{
    struct stat statbuf;
    long seed = 0;
    struct timeval t;

    // try to initialise seed from urandom
    if (!lstat("/dev/urandom", &statbuf) && S_ISCHR(statbuf.st_mode)) {
        int rfd = open("/dev/urandom", O_RDONLY);
        if(rfd >= 0) {
            (void) read(rfd, &seed, sizeof(seed));
            close(rfd);
        }
    }

    // Fallback to ancient time-based PRNG seeding; if urandom worked, this doesn't "break" the entropy already collected
    gettimeofday(&t, NULL);
    seed ^= gethostid() ^ t.tv_sec ^ t.tv_usec ^ getpid();

    // finally seed the PRNG
    srandom(seed);
}

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic()
{
    return (u_int32_t)random();
}

#endif

