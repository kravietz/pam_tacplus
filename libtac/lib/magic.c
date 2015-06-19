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

#include "magic.h"

static int magic_initialised = 0;

/*
 * magic_init - Initialize the magic number generator.
 *
 * Attempts to compute a random number seed which will not repeat.
 */
void
magic_init()
{
    struct stat statbuf;
    long seed = 0;
    struct timeval t;

    if (magic_initialised)
        return;

    // try to initialise seed from urandom
    if (!lstat("/dev/urandom", &statbuf) && S_ISCHR(statbuf.st_mode)) {
        int rfd = open("/dev/urandom", O_RDONLY);
        if(rfd >= 0) {
            int nb_read = read(rfd, &seed, sizeof(seed));
            close(rfd);
        }
    }

    // fallback
    gettimeofday(&t, NULL);
    seed ^= gethostid() ^ t.tv_sec ^ t.tv_usec ^ getpid();

    // finally seed the PRNG
    srandom(seed);
    magic_initialised = 1;
}

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic()
{
    if(!magic_initialised)
        magic_init();

    return (u_int32_t)random();
}

