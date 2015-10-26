/* connect.c - Open connection to server.
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

#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _AIX
#include <sys/socket.h>
#endif

#include "libtac.h"

/* Pointer to TACACS+ connection timeout */
int tac_timeout = 5;

/* Returns file descriptor of open connection
   to the first available server from list passed
   in server table.

 * return value:
 *   >= 0 : valid fd
 *   <  0 : error status code, see LIBTAC_STATUS_...
 */
int tac_connect(struct addrinfo **server, char **key, int servers) {
    int tries;
    int fd=-1;

    if(servers == 0 || server == NULL) {
        TACSYSLOG((LOG_ERR, "%s: no TACACS+ servers defined", __FUNCTION__))
    } else {
        for ( tries = 0; tries < servers; tries++ ) {   
            if((fd=tac_connect_single(server[tries], key[tries], NULL, tac_timeout)) >= 0 ) {
                /* tac_secret was set in tac_connect_single on success */
                break;
            }
        }
    }

    /* all attempts failed if fd is still < 0 */
    TACDEBUG((LOG_DEBUG, "%s: exit status=%d",__FUNCTION__, fd))
    return fd;
} /* tac_connect */


/* return value:
 *   >= 0 : valid fd
 *   <  0 : error status code, see LIBTAC_STATUS_...
 */
int tac_connect_single(struct addrinfo *server, const char *key, struct addrinfo *srcaddr, int timeout) {
    int retval = LIBTAC_STATUS_CONN_ERR; /* default retval */
    int fd = -1;
    int flags, rc;
    fd_set readfds, writefds;
    struct timeval tv;
    socklen_t len;
    struct sockaddr_storage addr;
    char *ip;

    if(server == NULL) {
        TACSYSLOG((LOG_ERR, "%s: no TACACS+ server defined", __FUNCTION__))
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* format server address into a string  for use in messages */
    ip = tac_ntop(server->ai_addr);

    if((fd=socket(server->ai_family, server->ai_socktype, server->ai_protocol)) < 0) {
        TACSYSLOG((LOG_ERR,"%s: socket creation error: %s", __FUNCTION__,
            strerror(errno)))
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* get flags for restoration later */
    flags = fcntl(fd, F_GETFL, 0);

    /* put socket in non blocking mode for timeout support */
    if( fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1 ) {
        TACSYSLOG((LOG_ERR, "%s: cannot set socket non blocking",\
            __FUNCTION__))
        close(fd);
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* bind if source address got explicity defined */
    if (srcaddr) {
        if (bind(fd, srcaddr->ai_addr, srcaddr->ai_addrlen) < 0) {
            TACSYSLOG((LOG_ERR, "%s: Failed to bind source address: %s",
                __FUNCTION__, strerror(errno)))
            close(fd);
            return LIBTAC_STATUS_CONN_ERR;
        }
    }

    rc = connect(fd, server->ai_addr, server->ai_addrlen);
    /* FIX this..for some reason errno = 0 on AIX... */
    if((rc == -1) && (errno != EINPROGRESS) && (errno != 0)) {
        TACSYSLOG((LOG_ERR,\
            "%s: connection to %s failed: %m", __FUNCTION__, ip))
        close(fd);
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* set fds for select */
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_SET(fd, &readfds);
    FD_SET(fd, &writefds);

    /* set timeout seconds */
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    /* check if socket is ready for read and write */
    rc = select(fd+1, &readfds, &writefds, NULL, &tv);

    /* timeout */
    if ( rc == 0 ) {
        close(fd);
        return LIBTAC_STATUS_CONN_TIMEOUT;
    }

    /* some other error or interrupt before timeout */
    if ( rc < 0 ) {
        TACSYSLOG((LOG_ERR,\
            "%s: connection failed with %s: %m", __FUNCTION__, ip))
        close(fd);
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* check with getpeername if we have a valid connection */
    len = sizeof addr;
    if(getpeername(fd, (struct sockaddr*)&addr, &len) == -1) {
        TACSYSLOG((LOG_ERR,\
            "%s: connection failed with %s: %m", __FUNCTION__, ip))
        close(fd);
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* restore flags on socket - flags was set only when fd >= 0 */
    if(fcntl(fd, F_SETFL, flags) == -1) {
        TACSYSLOG((LOG_ERR, "%s: cannot restore socket flags: %m",\
             __FUNCTION__)) 
        close(fd);
        return LIBTAC_STATUS_CONN_ERR;
    }

    /* connected ok */
    TACDEBUG((LOG_DEBUG, "%s: connected to %s", __FUNCTION__, ip))
    retval = fd;

    /* set current tac_secret */
    tac_encryption = 0;
    if (key != NULL && *key) {
        tac_encryption = 1;
        tac_secret = key;
    }

    /* if valid fd, but error experienced after open, close fd */
    if ( fd >= 0 && retval < 0 ) {
        close(fd);
    }

    TACDEBUG((LOG_DEBUG, "%s: exit status=%d (fd=%d)",\
        __FUNCTION__, retval < 0 ? retval:0, fd))
    return retval;
} /* tac_connect_single */


/* return value:
 *   ptr to char* with format IP address
 *   warning: returns a static buffer
 *   (which some ppl don't like, but it's robust and at last no more memory leaks)
 */
char *tac_ntop(const struct sockaddr *sa) {
    static char server_address[INET6_ADDRSTRLEN+16];

    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                server_address, INET_ADDRSTRLEN);

            snprintf(server_address + strlen(server_address), 14, ":%hu", 
                htons(((struct sockaddr_in *)sa)->sin_port));
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                server_address, INET6_ADDRSTRLEN);

            snprintf(server_address + strlen(server_address), 14, ":%hu",
                htons(((struct sockaddr_in6 *)sa)->sin6_port));
            break;

        default:
            strcpy(server_address, "Unknown AF");
    }
    return server_address;
} /* tac_ntop */

