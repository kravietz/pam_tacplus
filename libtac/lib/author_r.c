/* author_r.c - Reads authorization reply from the server.
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
#include "xalloc.h"
#include "libtac.h"
#include "messages.h"

/* This function returns structure containing 
    1. status (granted/denied)
    2. message for the user
    3. list of attributes returned by server
   The attributes should be applied to service authorization
   is requested for, but actually the aren't. Attributes are
   discarded. 
*/
void tac_author_read(int fd, struct areply *re) {
	HDR th;
	struct author_reply *tb = NULL;
	int len_from_header, r, len_from_body;
	char *pktp;
	char *msg = NULL;

	bzero(re, sizeof(struct areply));
	
	r=read(fd, &th, TAC_PLUS_HDR_SIZE);
	if(r < TAC_PLUS_HDR_SIZE) {
  		syslog(LOG_ERR,
 			"%s: short author header, %d of %d: %m", __FUNCTION__,
		 	r, TAC_PLUS_HDR_SIZE);
		re->msg = system_err_msg;
		re->status = AUTHOR_STATUS_ERROR;
		goto AuthorExit;
 	}

	/* check header consistency */
	msg = _tac_check_header(&th, TAC_PLUS_AUTHOR);
	if(msg != NULL) {
		/* no need to process body if header is broken */
		re->msg = msg;
		re->status = AUTHOR_STATUS_ERROR;
		goto AuthorExit;
	}

 	len_from_header=ntohl(th.datalength);
 	tb=(struct author_reply *) xcalloc(1, len_from_header);

 	/* read reply packet body */
 	r=read(fd, tb, len_from_header);
 	if(r < len_from_header) {
  		syslog(LOG_ERR,
			"%s: short author body, %d of %d: %m", __FUNCTION__,
			r, len_from_header);
		re->msg = system_err_msg;
		re->status = AUTHOR_STATUS_ERROR;
		goto AuthorExit;
 	}

 	/* decrypt the body */
 	_tac_crypt((u_char *) tb, &th, len_from_header);

	/* Convert network byte order to host byte order */
	tb->msg_len  = ntohs(tb->msg_len);
	tb->data_len = ntohs(tb->data_len);

 	/* check consistency of the reply body
	 * len_from_header = declared in header
	 * len_from_body = value computed from body fields
	 */
 	len_from_body = TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE +
	    		tb->msg_len + tb->data_len;
	    
	pktp = (char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
	
	for(r = 0; r < tb->arg_cnt; r++) {
	    len_from_body += sizeof(u_char); /* add arg length field's size*/
	    len_from_body += *pktp; /* add arg length itself */
		pktp++;
	}
	
 	if(len_from_header != len_from_body) {
  		syslog(LOG_ERR,
			"%s: inconsistent author reply body, incorrect key?",
			__FUNCTION__);
		re->msg = system_err_msg;
		re->status = AUTHOR_STATUS_ERROR;
		goto AuthorExit;
 	}

	/* packet seems to be consistent, prepare return messages */
	/* server message for user */
	if(tb->msg_len) {
		char *msg = (char *) xcalloc(1, tb->msg_len+1);
		bcopy((u_char *) tb+TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
				+ (tb->arg_cnt)*sizeof(u_char),
				msg, tb->msg_len);
		re->msg = msg;
	}

	/* server message to syslog */
	if(tb->data_len) {
		char *smsg=(char *) xcalloc(1, tb->data_len+1);
		bcopy((u_char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE
				+ (tb->arg_cnt)*sizeof(u_char)
				+ tb->msg_len, smsg, 
				tb->data_len);
		syslog(LOG_ERR, "%s: author failed: %s", __FUNCTION__,smsg);
		free(smsg);
	}

	/* prepare status */
	switch(tb->status) {
		/* success conditions */
		/* XXX support optional vs mandatory arguments */
		case AUTHOR_STATUS_PASS_ADD:
		case AUTHOR_STATUS_PASS_REPL:
			{
				char *argp; 

				if(!re->msg) re->msg=author_ok_msg;
				re->status=tb->status;
			
				/* add attributes received to attribute list returned to
				   the client */
				pktp = (char *) tb + TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE;
				argp = pktp + (tb->arg_cnt * sizeof(u_char)) + tb->msg_len +
						tb->data_len;
				/* argp points to current argument string
				   pktp holds current argument length */
				for(r=0; r < tb->arg_cnt; r++) {
					char buff[256];
					char *sep;
					char *value;
					
					bcopy(argp, buff, *pktp);
					buff[(int)*pktp] = '\0';
					sep=index(buff, '=');
					if(sep == NULL)
						sep=index(buff, '*');
					if(sep == NULL)
						syslog(LOG_WARNING, "AUTHOR_STATUS_PASS_REPL: attribute contains no separator: %s", buff);
					*sep = '\0';
					value = ++sep;
					/* now buff points to attribute name,
					   value to the attribute value */
					tac_add_attrib(&re->attr, buff, value);
					
					argp += *pktp;
					pktp++; 
				}
			}
			
			break;

		/* authorization failure conditions */
		/* failing to follow is allowed by RFC, page 23  */
		case AUTHOR_STATUS_FOLLOW: 
		case AUTHOR_STATUS_FAIL:
			if(!re->msg) re->msg=author_fail_msg;
			re->status=AUTHOR_STATUS_FAIL;
			break;

		/* error conditions */	
		case AUTHOR_STATUS_ERROR:
		default:
			if(!re->msg) re->msg=author_err_msg;
			re->status=AUTHOR_STATUS_ERROR;
	}

AuthorExit:

	free(tb);	
	TACDEBUG((LOG_DEBUG, "%s: server replied '%s'", __FUNCTION__, \
			re->msg))
	
}
