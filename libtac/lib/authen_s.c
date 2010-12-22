/* authen_s.c - Send authentication request to the server.
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
#include "md5.h"

/* this function sends a packet do TACACS+ server, asking
 * for validation of given username and password
 */
int tac_authen_send(int fd, const char *user, char *pass, char *tty)
{
 	HDR *th; 		 /* TACACS+ packet header */
 	struct authen_start tb; /* message body */
 	int user_len, port_len, chal_len, mdp_len, token_len, bodylength, w;
 	int pkt_len=0;
	int ret=0;
	char *chal = "1234123412341234";
	char digest[MD5_LEN];
	char *token;
 	u_char *pkt, *mdp;
	MD5_CTX mdcontext;

 	th=_tac_req_header(TAC_PLUS_AUTHEN);

 	/* set some header options */
	if(strcmp(tac_login,"login") == 0) {
 		th->version=TAC_PLUS_VER_0;
	} else {
 		th->version=TAC_PLUS_VER_1;
	}
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', encrypt: %s", \
		 __FUNCTION__, user, tty, \
	 	(tac_encryption) ? "yes" : "no"))	 
	
	if(strcmp(tac_login,"chap") == 0) {
		chal_len = strlen(chal);
		mdp_len = sizeof(u_char) + strlen(pass) + chal_len;
		mdp = (u_char *) xcalloc(1, mdp_len);
		mdp[0] = 5;
		memcpy(&mdp[1], pass, strlen(pass));
		memcpy(mdp + strlen(pass) + 1, chal, chal_len);
		MD5Init(&mdcontext);
		MD5Update(&mdcontext, mdp, mdp_len);
		MD5Final((u_char *) digest, &mdcontext);
		free(mdp);
		token = xcalloc(1, sizeof(u_char) + 1 + chal_len + MD5_LEN);
		token[0] = 5;
		memcpy(&token[1], chal, chal_len);
		memcpy(token + chal_len + 1, digest, MD5_LEN);
	} else {
		token = pass;
	}

 	/* get size of submitted data */
 	user_len=strlen(user);
 	port_len=strlen(tty);
 	token_len=strlen(token);

 	/* fill the body of message */
 	tb.action=TAC_PLUS_AUTHEN_LOGIN;
 	tb.priv_lvl=TAC_PLUS_PRIV_LVL_MIN;
	if(strcmp(tac_login,"chap") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP;
	} else if(strcmp(tac_login,"login") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII;
	} else {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
	}
 	tb.service=TAC_PLUS_AUTHEN_SVC_PPP;
 	tb.user_len=user_len;
 	tb.port_len=port_len;
 	tb.rem_addr_len=0;          /* may be e.g Caller-ID in future */
 	tb.data_len=token_len;

 	/* fill body length in header */
 	bodylength=sizeof(tb) + user_len
		+ port_len + token_len; /* + rem_addr_len */

 	th->datalength= htonl(bodylength);

 	/* we can now write the header */
 	w=write(fd, th, TAC_PLUS_HDR_SIZE);
	if(w < 0 || w < TAC_PLUS_HDR_SIZE) {
		syslog(LOG_ERR, "%s: short write on header: wrote %d of %d: %m", 
						__FUNCTION__, w, TAC_PLUS_HDR_SIZE);
		ret=-1;
	}

 	/* build the packet */
 	pkt=(u_char *) xcalloc(1, bodylength+10);

 	bcopy(&tb, pkt+pkt_len, sizeof(tb)); /* packet body beginning */
 	pkt_len+=sizeof(tb);
 	bcopy(user, pkt+pkt_len, user_len);  /* user */
 	pkt_len+=user_len;
 	bcopy(tty, pkt+pkt_len, port_len);   /* tty */
 	pkt_len+=port_len;
 	bcopy(token, pkt+pkt_len, token_len);  /* password */
 	pkt_len+=token_len;

 	/* pkt_len == bodylength ? */
	if(pkt_len != bodylength) {
		syslog(LOG_ERR, "%s: bodylength %d != pkt_len %d",
					__FUNCTION__, bodylength, pkt_len);
		ret=-1;
	} 
 	
	/* encrypt the body */
 	_tac_crypt(pkt, th, bodylength);

 	w=write(fd, pkt, pkt_len);
	if(w < 0 || w < pkt_len) {
		syslog(LOG_ERR, "%s: short write on body: wrote %d of %d: %m",
					   __FUNCTION__, w, pkt_len);
		ret=-1;
	}

 	free(pkt);
 	free(th);

 	return(ret);
} /* tac_authen_send */
