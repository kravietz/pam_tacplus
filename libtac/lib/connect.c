/* connect.c - Open connection to server.
 * 
 * Copyright (C) 2010, Pawel Krawczyk <kravietz@ceti.pl> and
 * Jeroen Nijhof <jeroen@nijhofnet.nl>
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

#include "tacplus.h"
#include "libtac.h"

/* Pointer to TACACS+ connection timeout */
int tac_timeout = 5;

/* Returns file descriptor of open connection
   to the first available server from list passed
   in server table.
*/
int tac_connect(struct addrinfo **server, char **key, int servers) {
	int tries = 0;
	int fd, flags, retval;
	fd_set readfds, writefds;
	struct timeval tv;
	socklen_t len;
	struct sockaddr_storage addr;

	if(!servers) {
		syslog(LOG_ERR, "%s: no TACACS+ servers defined", __FUNCTION__);
		return(-1);
	}

	while(tries < servers) {	
		if((fd=socket(server[tries]->ai_family, server[tries]->ai_socktype, server[tries]->ai_protocol)) == -1) {
       	   		syslog(LOG_WARNING, 
				"%s: socket creation error", __FUNCTION__);
			tries++;
			continue;
		}

		/* put socket in non blocking mode for timeout support */
		flags = fcntl(fd, F_GETFL, 0);
		if(fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
     	  		syslog(LOG_WARNING, "%s: cannot set socket non blocking",
				 __FUNCTION__); 
			tries++;
			continue;
		}

		retval = connect(fd, server[tries]->ai_addr, server[tries]->ai_addrlen);
		if((retval == -1) && (errno != EINPROGRESS)) {
     	  		syslog(LOG_WARNING, 
				"%s: connection to %s failed: %m", __FUNCTION__,
						tac_ntop(server[tries]->ai_addr, server[tries]->ai_addrlen));
			if(fcntl(fd, F_SETFL, flags)) {
     	  			syslog(LOG_WARNING, "%s: cannot restore socket flags",
					 __FUNCTION__); 
			}
			tries++;
			continue;
    		}

		/* set fds for select */
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		writefds = readfds;

		/* set timeout seconds */
		tv.tv_sec = tac_timeout;
		tv.tv_usec = 0;

		/* check if socket is ready for read and write */
		if(select(fd+1, &readfds, &writefds, NULL, &tv) < 1) {
     	  		syslog(LOG_WARNING, 
				"%s: connection failed with %s : %m", __FUNCTION__,
						tac_ntop(server[tries]->ai_addr, server[tries]->ai_addrlen));
			if(fcntl(fd, F_SETFL, flags)) {
     	  			syslog(LOG_WARNING, "%s: cannot restore socket flags",
					__FUNCTION__); 
			}
			tries++;
			continue;
		} else {
			/* check with getpeername if we have a valid connection */
			len = sizeof addr;
			if(getpeername(fd, (struct sockaddr*)&addr, &len) == -1) {
     	  			syslog(LOG_WARNING, 
					"%s: connection failed with %s : %m", __FUNCTION__,
							tac_ntop(server[tries]->ai_addr, server[tries]->ai_addrlen));
				if(fcntl(fd, F_SETFL, flags)) {
     	  				syslog(LOG_WARNING, "%s: cannot restore socket flags",
						 __FUNCTION__); 
				}
				tries++;
				continue;
			}
		}

		/* connected ok */
		if(fcntl(fd, F_SETFL, flags)) {
     	  		syslog(LOG_WARNING, "%s: cannot restore socket flags",
				 __FUNCTION__); 
		}
		TACDEBUG((LOG_DEBUG, "%s: connected to %s", __FUNCTION__, \
			       	tac_ntop(server[tries]->ai_addr, server[tries]->ai_addrlen)));

		/* set current tac_secret */
		tac_secret = key[tries];
		return(fd);
	}

	/* all attempts failed */
	return(-1);
} /* tac_connect */


int tac_connect_single(struct addrinfo *server, char *key) {
	struct addrinfo *tmpaddr[1];
	tmpaddr[0] = server;
	char *tmpkey[1];
	tmpkey[0] = key;
	return(tac_connect(tmpaddr, tmpkey, 1));
} /* tac_connect_single */


char *tac_ntop(const struct sockaddr *sa, size_t ai_addrlen) {
	char *str = (char *) xcalloc(1, ai_addrlen);
	switch(sa->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
				str, ai_addrlen);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
				str, ai_addrlen);
			break;
		default:
			strncpy(str, "Unknown AF", ai_addrlen);
	}
	return str;
} /* tac_ntop */
