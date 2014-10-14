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

static int rfd = -1;	/* fd for /dev/urandom */
static int magic_inited = 0;

/*
 * magic_init - Initialize the magic number generator.
 *
 * Attempts to compute a random number seed which will not repeat.
 * The current method uses the current hostid, current process ID
 * and current time, currently.
 */
void
magic_init()
{
    struct stat statbuf;
    long seed;
    struct timeval t;

    if (magic_inited)
        return;

    magic_inited = 1;

    /*
        try using /dev/urandom
        also check that it's a character device
        If it doesn't exist, fallback to other method
    */

    if (!lstat("/dev/urandom", &statbuf) && S_ISCHR(statbuf.st_mode)) {
        rfd = open("/dev/urandom", O_RDONLY);
        if (rfd >= 0)
            return;
    } 

    gettimeofday(&t, NULL);
    seed = gethostid() ^ t.tv_sec ^ t.tv_usec ^ getpid();
    srandom(seed);
}

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic()
{
    magic_init();

    if(rfd > -1) {
        u_int32_t ret;
        int nb_read = read(rfd, &ret, sizeof(ret));
        close(rfd);

        if (nb_read < sizeof(ret)) {
            /* on read() error fallback to other method */
            return (u_int32_t)random();
        }
        return ret;
    }
    return (u_int32_t)random();
}

