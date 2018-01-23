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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

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

/* if OpenSSL library is available this legacy code will not be compiled in */
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)

#include <openssl/rand.h>

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic()
{
    u_int32_t num;

#ifdef HAVE_RAND_BYTES
    RAND_bytes((unsigned char *)&num, sizeof(num));
#else
    RAND_pseudo_bytes((unsigned char *)&num, sizeof(num));
#endif

    return num;
}

#elif defined(HAVE_GETRANDOM)

# if defined(HAVE_SYS_RANDOM_H)
#  include <sys/random.h>
# else
#  error no header containing getrandom(2) declaration
# endif

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic()
{
    u_int32_t num;

    getrandom(&num, sizeof(num), GRND_NONBLOCK);
    return num;
}

#else

/*
 * magic_init - Initialize the magic number generator.
 *
 * Attempts to compute a random number seed which will not repeat.
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

    // fallback
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

