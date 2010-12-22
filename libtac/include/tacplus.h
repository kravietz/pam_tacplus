/* tacplus.h
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

#ifndef _TACPLUS_H
#define _TACPLUS_H

#include <sys/types.h>
#ifdef sun
  #include "cdefs.h"
#else
  #include <sys/cdefs.h>
#endif

struct tac_attrib {
	char *attr;
	u_char attr_len;
	struct tac_attrib *next;
};

struct areply {
	struct tac_attrib *attr;
	char *msg;
	int status;
};

#ifndef TAC_PLUS_MAXSERVERS		
#define TAC_PLUS_MAXSERVERS		4
#endif

#ifndef TAC_PLUS_PORT
#define	TAC_PLUS_PORT			49
#endif

#define TAC_PLUS_READ_TIMEOUT		180	/* seconds */
#define TAC_PLUS_WRITE_TIMEOUT		180	/* seconds */

/* All tacacs+ packets have the same header format */

struct tac_plus_pak_hdr {
    u_char version;

#define TAC_PLUS_MAJOR_VER_MASK 0xf0
#define TAC_PLUS_MAJOR_VER      0xc0

#define TAC_PLUS_MINOR_VER_0    0x0
#define TAC_PLUS_VER_0  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_0)

#define TAC_PLUS_MINOR_VER_1    0x01
#define TAC_PLUS_VER_1  (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_1)

    u_char type;

#define TAC_PLUS_AUTHEN			1
#define TAC_PLUS_AUTHOR			2
#define TAC_PLUS_ACCT			3

    u_char seq_no;		/* packet sequence number */
    u_char encryption;		/* packet is encrypted or cleartext */

#define TAC_PLUS_ENCRYPTED 0x0		/* packet is encrypted */
#define TAC_PLUS_CLEAR     0x1		/* packet is not encrypted */

    int session_id;		/* session identifier FIXME: Is this needed? */
    int datalength;		/* length of encrypted data following this
				 * header */
    /* datalength bytes of encrypted data */
};

#define TAC_PLUS_HDR_SIZE 12

typedef struct tac_plus_pak_hdr HDR;

/* Authentication packet NAS sends to us */ 

struct authen_start {
    u_char action;

#define TAC_PLUS_AUTHEN_LOGIN    0x1
#define TAC_PLUS_AUTHEN_CHPASS   0x2
#define TAC_PLUS_AUTHEN_SENDPASS 0x3 /* deprecated */
#define TAC_PLUS_AUTHEN_SENDAUTH 0x4

    u_char priv_lvl;

#define TAC_PLUS_PRIV_LVL_MIN 0x0
#define TAC_PLUS_PRIV_LVL_MAX 0xf

    u_char authen_type;

#define TAC_PLUS_AUTHEN_TYPE_ASCII  1
#define TAC_PLUS_AUTHEN_TYPE_PAP    2
#define TAC_PLUS_AUTHEN_TYPE_CHAP   3
#define TAC_PLUS_AUTHEN_TYPE_ARAP   4

    u_char service;

#define TAC_PLUS_AUTHEN_SVC_LOGIN  1
#define TAC_PLUS_AUTHEN_SVC_ENABLE 2
#define TAC_PLUS_AUTHEN_SVC_PPP    3
#define TAC_PLUS_AUTHEN_SVC_ARAP   4
#define TAC_PLUS_AUTHEN_SVC_PT     5
#define TAC_PLUS_AUTHEN_SVC_RCMD   6
#define TAC_PLUS_AUTHEN_SVC_X25    7
#define TAC_PLUS_AUTHEN_SVC_NASI   8

    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char data_len;
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* <data_len bytes of u_char data> */
};

#define TAC_AUTHEN_START_FIXED_FIELDS_SIZE 8

/* Authentication continue packet NAS sends to us */ 
struct authen_cont {
    u_short user_msg_len;
    u_short user_data_len;
    u_char flags;

#define TAC_PLUS_CONTINUE_FLAG_ABORT 0x1

    /* <user_msg_len bytes of u_char data> */
    /* <user_data_len bytes of u_char data> */
};

#define TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE 5

/* Authentication reply packet we send to NAS */ 
struct authen_reply {
    u_char status;

#define TAC_PLUS_AUTHEN_STATUS_PASS     1
#define TAC_PLUS_AUTHEN_STATUS_FAIL     2
#define TAC_PLUS_AUTHEN_STATUS_GETDATA  3
#define TAC_PLUS_AUTHEN_STATUS_GETUSER  4
#define TAC_PLUS_AUTHEN_STATUS_GETPASS  5
#define TAC_PLUS_AUTHEN_STATUS_RESTART  6
#define TAC_PLUS_AUTHEN_STATUS_ERROR    7 
#define TAC_PLUS_AUTHEN_STATUS_FOLLOW   0x21

    u_char flags;

#define TAC_PLUS_AUTHEN_FLAG_NOECHO     0x1

    u_short msg_len;
    u_short data_len;

    /* <msg_len bytes of char data> */
    /* <data_len bytes of u_char data> */
};

#define TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE 6

#define AUTHEN_METH_NONE             0x01
#define AUTHEN_METH_KRB5             0x02
#define AUTHEN_METH_LINE             0x03
#define AUTHEN_METH_ENABLE           0x04
#define AUTHEN_METH_LOCAL            0x05
#define AUTHEN_METH_TACACSPLUS       0x06
#define AUTHEN_METH_RCMD             0x20

struct acct {
    u_char flags;

#define TAC_PLUS_ACCT_FLAG_MORE     0x1
#define TAC_PLUS_ACCT_FLAG_START    0x2
#define TAC_PLUS_ACCT_FLAG_STOP     0x4
#define TAC_PLUS_ACCT_FLAG_WATCHDOG 0x8
	    
    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char authen_service;
    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char arg_cnt; /* the number of cmd args */
    /* one u_char containing size for each arg */
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* char data for args 1 ... n */
};

#define TAC_ACCT_REQ_FIXED_FIELDS_SIZE 9

struct acct_reply {
    u_short msg_len;
    u_short data_len;
    u_char status;

#define TAC_PLUS_ACCT_STATUS_SUCCESS 0x1
#define TAC_PLUS_ACCT_STATUS_ERROR   0x2
#define TAC_PLUS_ACCT_STATUS_FOLLOW  0x21

};

#define TAC_ACCT_REPLY_FIXED_FIELDS_SIZE 5

/* An authorization request packet */
struct author {
    u_char authen_method;
    u_char priv_lvl;
    u_char authen_type;
    u_char service;

    u_char user_len;
    u_char port_len;
    u_char rem_addr_len;
    u_char arg_cnt;		/* the number of args */

    /* <arg_cnt u_chars containing the lengths of args 1 to arg n> */
    /* <user_len bytes of char data> */
    /* <port_len bytes of char data> */
    /* <rem_addr_len bytes of u_char data> */
    /* <char data for each arg> */
};

#define TAC_AUTHOR_REQ_FIXED_FIELDS_SIZE 8

/* An authorization reply packet */
struct author_reply {
    u_char status;
    u_char arg_cnt;
    u_short msg_len;
    u_short data_len;

#define AUTHOR_STATUS_PASS_ADD       0x01
#define AUTHOR_STATUS_PASS_REPL      0x02
#define AUTHOR_STATUS_FAIL           0x10
#define AUTHOR_STATUS_ERROR          0x11
#define AUTHOR_STATUS_FOLLOW	     0x21

    /* <arg_cnt u_chars containing the lengths of arg 1 to arg n> */
    /* <msg_len bytes of char data> */
    /* <data_len bytes of char data> */
    /* <char data for each arg> */
};

#define TAC_AUTHOR_REPLY_FIXED_FIELDS_SIZE 6


#endif
