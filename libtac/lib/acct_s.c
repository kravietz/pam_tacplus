/* acct_s.c - Send accounting event information to server.
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
#include "xalloc.h"

int tac_account_send(int fd, int type, const char *user, char *tty,
	 struct tac_attrib *attr) {
	HDR *th;
	struct acct tb;
	u_char user_len, port_len;
	struct tac_attrib *a;
	int i = 0; 	/* arg count */
	int pkt_len = 0;
	int pktl = 0;
	int w; /* write count */
	u_char *pkt;
	/* u_char *pktp; */ 		/* obsolute */
	int ret = 0;

	th=_tac_req_header(TAC_PLUS_ACCT);

	/* set header options */
 	th->version=TAC_PLUS_VER_0;
 	th->encryption=tac_encryption ? TAC_PLUS_ENCRYPTED : TAC_PLUS_CLEAR;

	TACDEBUG((LOG_DEBUG, "%s: user '%s', tty '%s', encrypt: %s, type: %s", \
			__FUNCTION__, user, tty, \
			(tac_encryption) ? "yes" : "no", \
			(type == TAC_PLUS_ACCT_FLAG_START) ? "START" : "STOP"))
	
	user_len=(u_char) strlen(user);
	port_len=(u_char) strlen(tty);

	tb.flags=(u_char) type;
	tb.authen_method=AUTHEN_METH_TACACSPLUS;
	tb.priv_lvl=TAC_PLUS_PRIV_LVL_MIN;
	if(strcmp(tac_login,"chap") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_CHAP;
	} else if(strcmp(tac_login,"login") == 0) {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII;
	} else {
		tb.authen_type=TAC_PLUS_AUTHEN_TYPE_PAP;
	}
	tb.authen_service=TAC_PLUS_AUTHEN_SVC_PPP;
	tb.user_len=user_len;
	tb.port_len=port_len;
	tb.rem_addr_len=0;

	/* allocate packet */
	pkt=(u_char *) xcalloc(1, TAC_ACCT_REQ_FIXED_FIELDS_SIZE);
	pkt_len=sizeof(tb);

	/* fill attribute length fields */
	a = attr;
	while(a) {
		
		pktl = pkt_len;
		pkt_len += sizeof(a->attr_len);
	    pkt = xrealloc(pkt, pkt_len);

		/* see comments in author_s.c
		pktp=pkt + pkt_len;
		pkt_len += sizeof(a->attr_len);
		pkt = xrealloc(pkt, pkt_len);	
		*/

		bcopy(&a->attr_len, pkt + pktl, sizeof(a->attr_len));
		i++;

		a = a->next;
	}

	/* fill the arg count field and add the fixed fields to packet */
	tb.arg_cnt = i;
	bcopy(&tb, pkt, TAC_ACCT_REQ_FIXED_FIELDS_SIZE);

	/*
#define PUTATTR(data, len) \
	pktp = pkt + pkt_len; \
	pkt_len += len; \
	pkt = xrealloc(pkt, pkt_len); \
	bcopy(data, pktp, len);
*/
#define PUTATTR(data, len) \
	pktl = pkt_len; \
	pkt_len += len; \
	pkt = xrealloc(pkt, pkt_len); \
	bcopy(data, pkt + pktl, len);

	/* fill user and port fields */
	PUTATTR(user, user_len)
	PUTATTR(tty, port_len)

	/* fill attributes */
	a = attr;
	while(a) {
		PUTATTR(a->attr, a->attr_len)

		a = a->next;
	}

	/* finished building packet, fill len_from_header in header */
	th->datalength = htonl(pkt_len);

	/* write header */
 	w=write(fd, th, TAC_PLUS_HDR_SIZE);

	if(w < TAC_PLUS_HDR_SIZE) {
		syslog(LOG_ERR, "%s: acct hdr send failed: wrote %d of %d",
				__FUNCTION__, w,
				TAC_PLUS_HDR_SIZE);
		ret = -1;
	}
	
	/* encrypt packet body  */
 	_tac_crypt(pkt, th, pkt_len);

	/* write body */
	w=write(fd, pkt, pkt_len);
	if(w < pkt_len) {
		syslog(LOG_ERR, "%s: acct body send failed: wrote %d of %d", 
				__FUNCTION__, w,
				pkt_len);
		ret = -1;
	}

	free(pkt);
	free(th);

	return(ret);
}
