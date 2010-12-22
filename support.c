/* support.c - support functions for pam_tacplus.c
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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#ifndef __linux__
	#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_tacplus.h"
#include "tacplus.h"
#include "libtac.h"

struct addrinfo *tac_srv[TAC_MAX_SERVERS];
int tac_srv_no = 0;
char *tac_service = NULL;
char *tac_protocol = NULL;
char *tac_prompt = NULL;

/* libtac */
extern char *tac_secret;
extern char *tac_login;
extern int tac_encryption;
extern int tac_timeout;

#ifndef xcalloc
void *_xcalloc (size_t size) {
	register void *val = calloc (1, size);
	if (val == 0) {
		syslog (LOG_ERR, "xcalloc: calloc(1,%u) failed", (unsigned) size);
		exit (1);
 	}
	return val;
}
#else
#define _xcalloc xcalloc
#endif

char *_pam_get_terminal(pam_handle_t *pamh) {
	int retval;
	char *tty;

	retval = pam_get_item (pamh, PAM_TTY, (void *)&tty);
	if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
		tty = ttyname(STDIN_FILENO);
		if(tty == NULL || *tty == '\0')
			tty = "unknown";
	}
	return(tty);
}

void _pam_log(int err, const char *format,...) {
	char msg[256];
	va_list args;

	va_start(args, format);
	vsnprintf(msg, sizeof(msg), format, args);
	openlog("PAM-tacplus", LOG_PID, LOG_AUTH);
	syslog(err, "%s", msg);
	va_end(args);
	closelog();
}


/* stolen from pam_stress */
int converse(pam_handle_t * pamh, int nargs
		,struct pam_message **message
		,struct pam_response **response) {
	int retval;
	struct pam_conv *conv;

	if ((retval = pam_get_item (pamh, PAM_CONV, (void *)&conv)) == PAM_SUCCESS) {
#if (defined(__linux__) || defined(__NetBSD__))
		retval = conv->conv (nargs, (const struct pam_message **) message
#else
		retval = conv->conv (nargs, (struct pam_message **) message
#endif
				,response, conv->appdata_ptr);
		if (retval != PAM_SUCCESS) {
			_pam_log(LOG_ERR, "(pam_tacplus) converse returned %d", retval);
			_pam_log(LOG_ERR, "that is: %s", pam_strerror (pamh, retval));
		}
	} else {
		_pam_log (LOG_ERR, "(pam_tacplus) converse failed to get pam_conv");
	}

	return retval;
}

/* stolen from pam_stress */
int tacacs_get_password (pam_handle_t * pamh, int flags
			,int ctrl, char **password) {
	char *pass = NULL;

	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;
	int retval;

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

	/* set up conversation call */
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;

	if (!tac_prompt) {
		msg[0].msg = "Password: ";
	} else {
		msg[0].msg = tac_prompt;
	}
	resp = NULL;

	if ((retval = converse (pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
		return retval;

	if (resp) {
		if ((resp[0].resp == NULL) && (ctrl & PAM_TAC_DEBUG))
			_pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");
		pass = resp[0].resp;	/* remember this! */
		resp[0].resp = NULL;
	} else if (ctrl & PAM_TAC_DEBUG) {
		_pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
		_pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
		return PAM_CONV_ERR;
	}

	free(resp);
	resp = NULL;

	*password = pass;	/* this *MUST* be free()'d by this module */

  if(ctrl & PAM_TAC_DEBUG)
	syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

  return PAM_SUCCESS;
}

int _pam_parse (int argc, const char **argv) {
	int ctrl = 0;

	/* otherwise the list will grow with each call */
	tac_srv_no = 0;

	for (ctrl = 0; argc-- > 0; ++argv) {
		if (!strcmp (*argv, "debug")) { /* all */
			ctrl |= PAM_TAC_DEBUG;
		} else if (!strcmp (*argv, "encrypt")) {
			ctrl |= PAM_TAC_ENCRYPT;
			tac_encryption = 1;
		} else if (!strcmp (*argv, "first_hit")) { /* authentication */
			ctrl |= PAM_TAC_FIRSTHIT;
		} else if (!strncmp (*argv, "service=", 8)) { /* author & acct */
			tac_service = (char *) _xcalloc (strlen (*argv + 8) + 1);
			strcpy (tac_service, *argv + 8);
		} else if (!strncmp (*argv, "protocol=", 9)) { /* author & acct */
			tac_protocol = (char *) _xcalloc (strlen (*argv + 9) + 1);
			strcpy (tac_protocol, *argv + 9);
		} else if (!strncmp (*argv, "prompt=", 7)) { /* authentication */
			tac_prompt = (char *) _xcalloc (strlen (*argv + 7) + 1);
			strcpy (tac_prompt, *argv + 7);
			// Replace _ with space
			int chr;
			for (chr = 0; chr < strlen(tac_prompt); chr++) {
				if (tac_prompt[chr] == '_') {
					tac_prompt[chr] = ' ';
				}
			}
		} else if (!strcmp (*argv, "acct_all")) {
			ctrl |= PAM_TAC_ACCT;
		} else if (!strncmp (*argv, "server=", 7)) { /* authen & acct */
			if(tac_srv_no < TAC_MAX_SERVERS) { 
				struct addrinfo hints, *servers, *server;
				int rv;

				memset(&hints, 0, sizeof hints);
				hints.ai_family = AF_UNSPEC;  // use IPv4 or IPv6, whichever
				hints.ai_socktype = SOCK_STREAM;
				if ((rv = getaddrinfo(*argv + 7, "49", &hints, &servers)) == 0) {
					for(server = servers; server != NULL; server = server->ai_next) {
						tac_srv[tac_srv_no] = server;
						tac_srv_no++;
					}
				} else {
					_pam_log (LOG_ERR,
						"skip invalid server: %s (getaddrinfo: %s)",
						*argv + 7, gai_strerror(rv));
				}
			} else {
				_pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
					TAC_MAX_SERVERS);
			}
		} else if (!strncmp (*argv, "secret=", 7)) {
			tac_secret = (char *) _xcalloc (strlen (*argv + 7) + 1);
			strcpy (tac_secret, *argv + 7);
		} else if (!strncmp (*argv, "timeout=", 8)) {
			tac_timeout = atoi(*argv + 8);
		} else if (!strncmp (*argv, "login=", 6)) {
			tac_login = (char *) _xcalloc (strlen (*argv + 6) + 1);
			strcpy (tac_login, *argv + 6);
		} else {
			_pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
		}
	}

	return ctrl;
}	/* _pam_parse */

