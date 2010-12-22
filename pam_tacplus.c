/* pam_tacplus.c - PAM interface for TACACS+ protocol.
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

#include <stdlib.h>	/* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>	/* gethostbyname */
#include <sys/socket.h>	/* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>	/* va_ */
#include <signal.h>
#include <string.h>	/* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>

#ifndef __linux__
	#include <strings.h>
#endif

#include "tacplus.h"
#include "libtac.h"
#include "pam_tacplus.h"
#include "support.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#ifndef __linux__
	#include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

/* support.c */
extern struct addrinfo *tac_srv[TAC_MAX_SERVERS];
extern int tac_srv_no;
extern char *tac_service;
extern char *tac_protocol;
extern int _pam_parse (int argc, const char **argv);
extern unsigned long _getserveraddr (char *serv);
extern int tacacs_get_password (pam_handle_t * pamh, int flags
				,int ctrl, char **password);
extern int converse (pam_handle_t * pamh, int nargs
			,struct pam_message **message
			,struct pam_response **response);
extern void _pam_log (int err, const char *format,...);
extern void *_xcalloc (size_t size);

/* magic.c */
extern u_int32_t magic();

/* libtac */
extern char *tac_secret;
extern int tac_encryption;

/* address of server discovered by pam_sm_authenticate */
static struct addrinfo *active_server;
/* accounting task identifier */
static short int task_id = 0;


/* Helper functions */
int _pam_send_account(int tac_fd, int type, const char *user, char *tty) {
	char buf[40];
	struct tac_attrib *attr;
	int retval, status = -1;
	

	attr=(struct tac_attrib *)_xcalloc(sizeof(struct tac_attrib));
	
#ifdef _AIX
	sprintf(buf, "%d", time(0));
#else
	sprintf(buf, "%lu", (long unsigned int)time(0));
#endif

	tac_add_attrib(&attr, 
		(type == TAC_PLUS_ACCT_FLAG_START) ? "start_time" : "stop_time"
			, buf);
	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);
	tac_add_attrib(&attr, "service", tac_service);
	tac_add_attrib(&attr, "protocol", tac_protocol);

	retval = tac_account_send(tac_fd, type, user, tty, attr);

	/* this is no longer needed */
	tac_free_attrib(&attr);
	
	if(retval < 0) {
		_pam_log (LOG_WARNING, "%s: send %s accounting failed (task %hu)",
			__FUNCTION__, 
			(type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop",
			task_id);
		status = -1;
		goto ErrExit;
	}
	
	if(tac_account_read(tac_fd) != NULL) {
		_pam_log (LOG_WARNING, "%s: accounting %s failed (task %hu)",
			__FUNCTION__, 
			(type == TAC_PLUS_ACCT_FLAG_START) ? "start" : "stop",
			task_id);
		status = -1;
		goto ErrExit;
	}

	status = 0;

ErrExit:
	close(tac_fd);
	return status;
}

int _pam_account(pam_handle_t *pamh, int argc, const char **argv,  int type) {
	int retval;
	static int ctrl;
#if (defined(__linux__) || defined(__NetBSD__))
	char *user = NULL;
#else
	const char *user = NULL;
#endif
	char *tty = NULL;
	char *typemsg;
	int status = PAM_SESSION_ERR;
  
	typemsg = (type == TAC_PLUS_ACCT_FLAG_START) ? "START" : "STOP";
  	ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: [%s] called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tac_srv_no=%d", __FUNCTION__, tac_srv_no);
  
#if (defined(__linux__) || defined(__NetBSD__))
	retval = pam_get_item(pamh, PAM_USER, (const void **) (const void*) &user);
#else
	retval = pam_get_item(pamh, PAM_USER, (void **) (void*) &user);
#endif
	if(retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log(LOG_ERR, "%s: unable to obtain username", __FUNCTION__);
		return PAM_SESSION_ERR;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username [%s] obtained", __FUNCTION__, user);
  
	tty = _pam_get_terminal(pamh);
  
	if(!strncmp(tty, "/dev/", 5)) 
		tty += 5;
  
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	/* checks for specific data required by TACACS+, which should
	   be supplied in command line  */
	if(tac_service == NULL || *tac_service == '\0') {
		_pam_log (LOG_ERR, "TACACS+ service type not configured");
		return PAM_AUTH_ERR;
	}
	if(tac_protocol == NULL || *tac_protocol == '\0') {
		_pam_log (LOG_ERR, "TACACS+ protocol type not configured");
		return PAM_AUTH_ERR;
	}

	/* when this module is called from within pppd or other
	   application dealing with serial lines, it is likely
	   that we will get hit with signal caused by modem hangup;
	   this is important only for STOP packets, it's relatively
	   rare that modem hangs up on accounting start */
	if(type == TAC_PLUS_ACCT_FLAG_STOP) {
		signal(SIGALRM, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}

	if(!(ctrl & PAM_TAC_ACCT)) {
	/* normal mode, send packet to the first available server */
		int tac_fd;

		status = PAM_SUCCESS;
		  
		tac_fd = tac_connect(tac_srv, tac_srv_no);
		if(tac_fd < 0) {
			_pam_log(LOG_ERR, "%s: error sending %s - no servers",
				__FUNCTION__, typemsg);
			status = PAM_SESSION_ERR;
		}
		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: connected with fd=%d", __FUNCTION__, tac_fd);

		retval = _pam_send_account(tac_fd, type, user, tty);
		if(retval < 0) {
			_pam_log(LOG_ERR, "%s: error sending %s", 
				__FUNCTION__, typemsg);
			status = PAM_SESSION_ERR;
		}
		  
		close(tac_fd);
  		  
		if (ctrl & PAM_TAC_DEBUG) {
			syslog(LOG_DEBUG, "%s: [%s] for [%s] sent",
				__FUNCTION__, typemsg,user);
		}
	} else {
	/* send packet to all servers specified */
		int srv_i;
		  
		status = PAM_SESSION_ERR;
		  
		for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
			int tac_fd;
				  
			tac_fd = tac_connect_single(tac_srv[srv_i]);
			if(tac_fd < 0) {
				_pam_log(LOG_WARNING, "%s: error sending %s (fd)",
					__FUNCTION__, typemsg);
				continue;
			}

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: connected with fd=%d (srv %d)", __FUNCTION__, tac_fd, srv_i);

			retval = _pam_send_account(tac_fd, type, user, tty);
			/* return code from function in this mode is
			   status of the last server we tried to send
			   packet to */
			if(retval < 0) {
				_pam_log(LOG_WARNING, "%s: error sending %s (acct)",
					__FUNCTION__, typemsg);
			} else {
				status = PAM_SUCCESS;
				if (ctrl & PAM_TAC_DEBUG) 
					syslog(LOG_DEBUG, "%s: [%s] for [%s] sent",
						__FUNCTION__, typemsg,user);
			}
			close(tac_fd);
		}
	}  /* acct mode */

	if(type == TAC_PLUS_ACCT_FLAG_STOP) {
		signal(SIGALRM, SIG_DFL);
		signal(SIGCHLD, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
	}
			  
	return status;
}				


/* Main PAM functions */

/* authenticates user on remote TACACS+ server
 * returns PAM_SUCCESS if the supplied username and password
 * pair is valid 
 */
PAM_EXTERN 
int pam_sm_authenticate (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	int ctrl, retval;
#if (defined(__linux__) || defined(__NetBSD__))
	const char *user;
#else
	char *user;
#endif
	char *pass;
	char *tty;
	int srv_i;
	int tac_fd;
	int status = PAM_AUTH_ERR;

	user = pass = tty = NULL;

	ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	retval = pam_get_user (pamh, &user, "Username: ");
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log (LOG_ERR, "unable to obtain username");
		return PAM_USER_UNKNOWN;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: user [%s] obtained", __FUNCTION__, user);
  
	/* uwzgledniac PAM_DISALLOW_NULL_AUTHTOK */

	retval = tacacs_get_password (pamh, flags, ctrl, &pass);
	if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0') {
		_pam_log (LOG_ERR, "unable to obtain password");
		return PAM_CRED_INSUFFICIENT;
	}

	retval = pam_set_item (pamh, PAM_AUTHTOK, pass);
	if (retval != PAM_SUCCESS) {
		_pam_log (LOG_ERR, "unable to set password");
		return PAM_CRED_INSUFFICIENT;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: password obtained", __FUNCTION__);

	tty = _pam_get_terminal(pamh);

	if (!strncmp (tty, "/dev/", 5))
		tty += 5;

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
		int msg = TAC_PLUS_AUTHEN_STATUS_FAIL;
		if (ctrl & PAM_TAC_DEBUG)
			syslog (LOG_DEBUG, "%s: trying srv %d", __FUNCTION__, srv_i );

		tac_fd = tac_connect_single(tac_srv[srv_i]);
		if (tac_fd < 0) {
			_pam_log (LOG_ERR, "connection failed srv %d: %m", srv_i);
			if (srv_i == tac_srv_no-1) {
				_pam_log (LOG_ERR, "no more servers to connect");
				return PAM_AUTHINFO_UNAVAIL;
			}
		}
		if (tac_authen_send (tac_fd, user, pass, tty) < 0) {
			_pam_log (LOG_ERR, "error sending auth req to TACACS+ server");
			status = PAM_AUTHINFO_UNAVAIL;
		} else {
			msg = tac_authen_read (tac_fd);
			if (msg == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
				if (ctrl & PAM_TAC_DEBUG)
					syslog (LOG_DEBUG, "%s: tac_cont_send called", __FUNCTION__);
				if (tac_cont_send (tac_fd, pass) < 0) {
					_pam_log (LOG_ERR, "error sending continue req to TACACS+ server");
					status = PAM_AUTHINFO_UNAVAIL;
				} else {
					msg = tac_authen_read (tac_fd);
					if (msg != TAC_PLUS_AUTHEN_STATUS_PASS) {
						_pam_log (LOG_ERR, "auth failed: %d", msg);
						status = PAM_AUTH_ERR;
					} else {
						/* OK, we got authenticated; save the server that
						   accepted us for pam_sm_acct_mgmt and exit the loop */
						status = PAM_SUCCESS;
						active_server = tac_srv[srv_i];
						close(tac_fd);
						break;
					}
				}
			} else if (msg != TAC_PLUS_AUTHEN_STATUS_PASS) {
				_pam_log (LOG_ERR, "auth failed: %d", msg);
				status = PAM_AUTH_ERR;
			} else {
				/* OK, we got authenticated; save the server that
				   accepted us for pam_sm_acct_mgmt and exit the loop */
				status = PAM_SUCCESS;
				active_server = tac_srv[srv_i];
				close(tac_fd);
				break;
			}
		}
		close(tac_fd);
		/* if we are here, this means that authentication failed
		   on current server; break if we are not allowed to probe
		   another one, continue otherwise */
		if (!(ctrl & PAM_TAC_FIRSTHIT))
			break;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: exit with pam status: %i", __FUNCTION__, status);

	bzero (pass, strlen (pass));
	free(pass);
	pass = NULL;

	return status;
}	/* pam_sm_authenticate */

/* no-op function to satisfy PAM authentication module */ 
PAM_EXTERN 
int pam_sm_setcred (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	int ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	return PAM_SUCCESS;
}	/* pam_sm_setcred */

/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */
PAM_EXTERN 
int pam_sm_acct_mgmt (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	int retval, ctrl, status=PAM_AUTH_ERR;
#if (defined(__linux__) || defined(__NetBSD__))
	const char *user;
#else
	char *user;
#endif
	char *tty;
	struct areply arep;
	struct tac_attrib *attr = NULL;
	int tac_fd;

	user = tty = NULL;
  
	/* this also obtains service name for authorization
	   this should be normally performed by pam_get_item(PAM_SERVICE)
	   but since PAM service names are incompatible TACACS+
	   we have to pass it via command line argument until a better
	   solution is found ;) */
	ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG) {
		syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);
		syslog (LOG_DEBUG, "%s: active server is [%s]", __FUNCTION__,
			tac_ntop(active_server->ai_addr, active_server->ai_addrlen));
	}
  
#if (defined(__linux__) || defined(__NetBSD__))
	retval = pam_get_item(pamh, PAM_USER, (const void **) (const void*) &user);
#else
	retval = pam_get_item(pamh, PAM_USER, (void **) (void*) &user);
#endif
	if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
		_pam_log (LOG_ERR, "unable to obtain username");
		return PAM_USER_UNKNOWN;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username obtained [%s]", __FUNCTION__, user);
  
	tty = _pam_get_terminal(pamh);

	if(!strncmp(tty, "/dev/", 5)) 
		tty += 5;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty obtained [%s]", __FUNCTION__, tty);
  
	/* checks if user has been successfully authenticated
	   by TACACS+; we cannot solely authorize user if it hasn't
	   been authenticated or has been authenticated by method other
	   than TACACS+ */
	if(!active_server) {
		_pam_log (LOG_ERR, "user not authenticated by TACACS+");
		return PAM_AUTH_ERR;
	}

	/* checks for specific data required by TACACS+, which should
	   be supplied in command line  */
	if(tac_service == NULL || *tac_service == '\0') {
		_pam_log (LOG_ERR, "TACACS+ service type not configured");
		return PAM_AUTH_ERR;
	}
	if(tac_protocol == NULL || *tac_protocol == '\0') {
		_pam_log (LOG_ERR, "TACACS+ protocol type not configured");
		return PAM_AUTH_ERR;
	}

	tac_add_attrib(&attr, "service", tac_service);
	tac_add_attrib(&attr, "protocol", tac_protocol);

	tac_fd = tac_connect_single(active_server);
	if(tac_fd < 0) {
		_pam_log (LOG_ERR, "TACACS+ server unavailable");
		status = PAM_AUTH_ERR;
		goto ErrExit;
	}

	retval = tac_author_send(tac_fd, user, tty, attr);
  
	tac_free_attrib(&attr);
  
	if(retval < 0) {
		_pam_log (LOG_ERR, "error getting authorization");
		status = PAM_AUTH_ERR;
		goto ErrExit;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: sent authorization request", __FUNCTION__);
  
	tac_author_read(tac_fd, &arep);

	if(arep.status != AUTHOR_STATUS_PASS_ADD &&
			arep.status != AUTHOR_STATUS_PASS_REPL) {
		_pam_log (LOG_ERR, "TACACS+ authorisation failed for [%s]", user);
		status = PAM_PERM_DENIED;
		goto ErrExit;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] successfully authorized", __FUNCTION__, user);
  
	status = PAM_SUCCESS;
  
	attr = arep.attr;
	while (attr != NULL)  {
		char attribute[attr->attr_len];
		char value[attr->attr_len];
		char *sep;

		sep = index(attr->attr, '=');
		if(sep == NULL)
			sep = index(attr->attr, '*');
		if(sep != NULL) {
			bcopy(attr->attr, attribute, attr->attr_len-strlen(sep));
			attribute[attr->attr_len-strlen(sep)] = '\0';
			bcopy(sep, value, strlen(sep));
			value[strlen(sep)] = '\0';

			size_t i;
			for (i = 0; attribute[i] != '\0'; i++) {
				attribute[i] = toupper(attribute[i]);
				if (attribute[i] == '-')
					attribute[i] = '_';
			}

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: returned attribute `%s%s' from server", __FUNCTION__, attribute, value);

			/* set PAM_RHOST if 'addr' attribute was returned from server */
			if(!strncmp(attribute, "addr", 4) && isdigit((int)*value)) {
				retval = pam_set_item(pamh, PAM_RHOST, value);
				if (retval != PAM_SUCCESS)
					syslog(LOG_WARNING, "%s: unable to set remote address for PAM", __FUNCTION__);
				else if(ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: set remote addr to `%s'", __FUNCTION__, value);
			}

			/* make returned attributes available for other PAM modules via PAM environment */
			if (pam_putenv(pamh, strncat(attribute, value, strlen(value))) != PAM_SUCCESS)
				syslog(LOG_WARNING, "%s: unable to set PAM environment", __FUNCTION__);

		} else {
			syslog(LOG_WARNING, "%s: invalid attribute `%s', no separator", __FUNCTION__, attr->attr);
		}
		attr = attr->next;
	}

	/* free returned attributes */
	if(arep.attr != NULL) tac_free_attrib(&arep.attr);

ErrExit:
	close(tac_fd);
	return status;
}	/* pam_sm_acct_mgmt */

/* sends START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
/* accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * it may be also directed to all specified servers
 */  
PAM_EXTERN 
int pam_sm_open_session (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	task_id=(short int) magic();

	return(_pam_account(pamh, argc, argv,TAC_PLUS_ACCT_FLAG_START)); 
}	/* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
PAM_EXTERN 
int pam_sm_close_session (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	return(_pam_account(pamh, argc, argv,TAC_PLUS_ACCT_FLAG_STOP)); 
}	/* pam_sm_close_session */


#ifdef PAM_SM_PASSWORD
/* no-op function for future use */ 
PAM_EXTERN 
int pam_sm_chauthtok (pam_handle_t * pamh, int flags,
			int argc, const char **argv) {
	int ctrl = _pam_parse (argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog (LOG_DEBUG, "%s: called (pam_tacplus v%hu.%hu.%hu)"
			, __FUNCTION__, PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	return PAM_SUCCESS;
}	/* pam_sm_chauthtok */
#endif


#ifdef PAM_STATIC
struct pam_module _pam_tacplus_modstruct
{
	"pam_tacplus",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
#ifdef PAM_SM_PASSWORD
	pam_sm_chauthtok
#else
	NULL
#endif
};
#endif

