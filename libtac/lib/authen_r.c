/* authen_r.c - Read authentication reply from server.
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

#include "tacplus.h"
#include "libtac.h"
#include "messages.h"

/* reads packet from TACACS+ server; returns:
 *  TAC_PLUS_AUTHEN_STATUS_PASS if the authentication succeded
 *  an other integer if failed. Check tacplus.h for all possible values
 */
int tac_authen_read(int fd) {
 	HDR th;
 	struct authen_reply *tb;
 	int len_from_header, r, len_from_body;
	char *msg = NULL;

 	/* read the reply header */
 	r=read(fd, &th, TAC_PLUS_HDR_SIZE);
 	if(r < TAC_PLUS_HDR_SIZE) {
  		syslog(LOG_ERR,
 			"%s: error reading authen header, read %d of %d: %m",
			__FUNCTION__,
		 	r, TAC_PLUS_HDR_SIZE);
  		return(TAC_PLUS_AUTHEN_STATUS_FAIL);
 	}

 	/* check the reply fields in header */
	msg = _tac_check_header(&th, TAC_PLUS_AUTHEN);
	if(msg != NULL)
		return(TAC_PLUS_AUTHEN_STATUS_FAIL);
 
 	len_from_header=ntohl(th.datalength);
 	tb=(struct authen_reply *) xcalloc(1, len_from_header);

 	/* read reply packet body */
 	r=read(fd, tb, len_from_header);
 	if(r < len_from_header) {
  		syslog(LOG_ERR,
			"%s: incomplete message body, %d bytes, expected %d: %m",
			__FUNCTION__,
			r, len_from_header);
  		return(TAC_PLUS_AUTHEN_STATUS_FAIL);
 	}

 	/* decrypt the body */
 	_tac_crypt((u_char *) tb, &th, len_from_header);

	/* Convert network byte order to host byte order */
	tb->msg_len  = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

 	/* check the length fields */
 	len_from_body=sizeof(tb->status) + sizeof(tb->flags) +
            sizeof(tb->msg_len) + sizeof(tb->data_len) +
            tb->msg_len + tb->data_len;

 	if(len_from_header != len_from_body) {
  		syslog(LOG_ERR,
			"%s: invalid reply content, incorrect key?",
			__FUNCTION__);
  		return(TAC_PLUS_AUTHEN_STATUS_FAIL);
 	}

 	/* save status and clean up */
 	r=tb->status;
 	free(tb);

 	/* server authenticated username and password successfully */
 	if(r == TAC_PLUS_AUTHEN_STATUS_PASS) {
		TACDEBUG((LOG_DEBUG, "%s: authentication ok", __FUNCTION__))
		return(r);
	}
		
 	/* server ask for continue packet with password */
 	if(r == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
		TACDEBUG((LOG_DEBUG, "%s: continue packet with password needed", __FUNCTION__))
		return(r);
	}

	/* return pointer to server message */
	syslog(LOG_DEBUG, "%s: authentication failed, server reply was %d", 
					__FUNCTION__, r);
 	return(r);

} /* tac_authen_read */
