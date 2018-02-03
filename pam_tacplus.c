/* pam_tacplus.c - PAM interface for TACACS+ protocol.
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

#include "pam_tacplus.h"
#include "support.h"

#include <stdlib.h>     /* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>      /* gethostbyname */
#include <sys/socket.h> /* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>     /* va_ */
#include <signal.h>
#include <string.h>     /* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
# include <openssl/rand.h>
#else
# include "magic.h"
#endif

/* address of server discovered by pam_sm_authenticate */
static tacplus_server_t active_server;
struct addrinfo active_addrinfo;
struct sockaddr active_sockaddr;
char active_key[TAC_SECRET_MAX_LEN+1];

/* accounting task identifier */
static short int task_id = 0;

/* copy a server's information into active_server */
static void set_active_server (const tacplus_server_t *tac_svr)
{
	active_addrinfo.ai_addr = &active_sockaddr;
	tac_copy_addr_info (&active_addrinfo, tac_svr->addr);
	strncpy (active_key, tac_svr->key ? tac_svr->key : "", TAC_SECRET_MAX_LEN-1);
	active_server.addr = &active_addrinfo;
	active_server.key = active_key;
}

/* Helper functions */
int _pam_send_account(int tac_fd, int type, const char *user, char *tty,
		char *r_addr, char *cmd) {

	char buf[64];
	struct tac_attrib *attr;
	int retval;

	attr = (struct tac_attrib *) xcalloc(1, sizeof(struct tac_attrib));

	sprintf(buf, "%lu", (unsigned long) time(NULL));

	if (type == TAC_PLUS_ACCT_FLAG_START) {
		tac_add_attrib(&attr, "start_time", buf);
	} else if (type == TAC_PLUS_ACCT_FLAG_STOP) {
		tac_add_attrib(&attr, "stop_time", buf);
	}
	sprintf(buf, "%hu", task_id);
	tac_add_attrib(&attr, "task_id", buf);
	tac_add_attrib(&attr, "service", tac_service);
	if (tac_protocol[0] != '\0')
		tac_add_attrib(&attr, "protocol", tac_protocol);
	if (cmd != NULL) {
		tac_add_attrib(&attr, "cmd", cmd);
	}

	retval = tac_acct_send(tac_fd, type, user, tty, r_addr, attr);

	/* this is no longer needed */
	tac_free_attrib(&attr);

	if (retval < 0) {
		_pam_log(LOG_WARNING, "%s: send %s accounting failed (task %hu)",
				__FUNCTION__, tac_acct_flag2str(type), task_id);
		close(tac_fd);
		return -1;
	}

	struct areply re;
	if (tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS) {
		_pam_log(LOG_WARNING, "%s: accounting %s failed (task %hu)",
				__FUNCTION__, tac_acct_flag2str(type), task_id);

		if (re.msg != NULL)
			free(re.msg);

		close(tac_fd);
		return -1;
	}

	if (re.msg != NULL)
		free(re.msg);

	close(tac_fd);
	return 0;
}

int _pam_account(pam_handle_t *pamh, int argc, const char **argv, int type,
		char *cmd) {

	int retval;
	static int ctrl;
	char *user = NULL;
	char *tty = NULL;
	char *r_addr = NULL;
	char *typemsg;
	int status = PAM_SESSION_ERR;
	int srv_i, tac_fd;

	typemsg = tac_acct_flag2str(type);
	ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG) {
		syslog(LOG_DEBUG, "%s: [%s] called (pam_tacplus v%u.%u.%u)",
				__FUNCTION__, typemsg, PAM_TAC_VMAJ, PAM_TAC_VMIN,
				PAM_TAC_VPAT);
		syslog(LOG_DEBUG, "%s: tac_srv_no=%d", __FUNCTION__, tac_srv_no);
	}

	if ((user = _pam_get_user(pamh)) == NULL)
		return PAM_USER_UNKNOWN;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username [%s] obtained", __FUNCTION__, user);

	tty = _pam_get_terminal(pamh);
	if (!strncmp(tty, "/dev/", 5))
		tty += 5;
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	r_addr = _pam_get_rhost(pamh);
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __FUNCTION__, r_addr);

	/* checks for specific data required by TACACS+, which should
	 be supplied in command line  */
	if (*tac_service == '\0') {
		_pam_log(LOG_ERR, "ACC: TACACS+ service type not configured");
		return PAM_AUTH_ERR;
	}
	if (*tac_protocol == '\0') {
		_pam_log(LOG_ERR,
				"ACC: TACACS+ protocol type not configured (IGNORED)");
	}

	/* when this module is called from within pppd or other
	 application dealing with serial lines, it is likely
	 that we will get hit with signal caused by modem hangup;
	 this is important only for STOP packets, it's relatively
	 rare that modem hangs up on accounting start */
	if (type == TAC_PLUS_ACCT_FLAG_STOP) {
		signal(SIGALRM, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}

	status = PAM_SESSION_ERR;
	for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
		tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
				NULL, tac_timeout);
		if (tac_fd < 0) {
			_pam_log(LOG_WARNING, "%s: error sending %s (fd)", __FUNCTION__,
					typemsg);
			continue;
		}
		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: connected with fd=%d (srv %d)", __FUNCTION__,
					tac_fd, srv_i);

		retval = _pam_send_account(tac_fd, type, user, tty, r_addr, cmd);
		if (retval < 0) {
			_pam_log(LOG_WARNING, "%s: error sending %s (acct)", __FUNCTION__,
					typemsg);
		} else {
			status = PAM_SUCCESS;
			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: [%s] for [%s] sent", __FUNCTION__,
						typemsg, user);
		}
		close(tac_fd);

		if ((status == PAM_SUCCESS) && !(ctrl & PAM_TAC_ACCT)) {
			/* do not send acct start/stop packets to _all_ servers */
			break;
		}
	}

	if (type == TAC_PLUS_ACCT_FLAG_STOP) {
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
int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
		const char **argv) {

	int ctrl, retval;
	char *user;
	char *pass;
	char *tty;
	char *r_addr;
	int srv_i;
	int tac_fd, status, msg, communicating;

	user = pass = tty = r_addr = NULL;

	ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)", __FUNCTION__,
				PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	if ((user = _pam_get_user(pamh)) == NULL)
		return PAM_USER_UNKNOWN;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] obtained", __FUNCTION__, user);

	retval = tacacs_get_password(pamh, flags, ctrl, &pass);
	if (retval != PAM_SUCCESS || pass == NULL || *pass == '\0') {
		_pam_log(LOG_ERR, "unable to obtain password");
		free(pass);
		return PAM_CRED_INSUFFICIENT;
	}

	retval = pam_set_item(pamh, PAM_AUTHTOK, pass);
	if (retval != PAM_SUCCESS) {
		_pam_log(LOG_ERR, "unable to set password");
		free(pass);
		return PAM_CRED_INSUFFICIENT;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: password obtained", __FUNCTION__);

	tty = _pam_get_terminal(pamh);
	if (!strncmp(tty, "/dev/", 5))
		tty += 5;
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	r_addr = _pam_get_rhost(pamh);
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __FUNCTION__, r_addr);

	status = PAM_AUTHINFO_UNAVAIL;
	for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: trying srv %d", __FUNCTION__, srv_i);

		tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
				NULL, tac_timeout);
		if (tac_fd < 0) {
			_pam_log(LOG_ERR, "connection failed srv %d: %m", srv_i);
			active_server.addr = NULL;
			continue;
		}
		if (tac_authen_send(tac_fd, user, pass, tty, r_addr,
				TAC_PLUS_AUTHEN_LOGIN) < 0) {
			close(tac_fd);
			_pam_log(LOG_ERR, "error sending auth req to TACACS+ server");
			active_server.addr = NULL;
			continue;
		}
		communicating = 1;
		while (communicating) {
			struct areply re = { .attr = NULL, .msg = NULL, .status = 0,
					.flags = 0 };
			struct pam_message conv_msg = { .msg_style = 0, .msg = NULL };
			struct pam_response *resp = NULL;

			msg = tac_authen_read(tac_fd, &re);

			if (NULL != re.msg) {
				conv_msg.msg = re.msg;
			}

			/* talk the protocol */
			switch (msg) {
			case TAC_PLUS_AUTHEN_STATUS_PASS:
				/* success */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_PASS");

				if (NULL != conv_msg.msg) {
					conv_msg.msg_style = PAM_TEXT_INFO;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d",
								__FUNCTION__, conv_msg.msg, retval);
					}

				}
				status = PAM_SUCCESS;
				communicating = 0;
				set_active_server(&tac_srv[srv_i]);

				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: active srv %d", __FUNCTION__, srv_i);

				break;

			case TAC_PLUS_AUTHEN_STATUS_FAIL:
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_FAIL");

				if (NULL != conv_msg.msg) {
					conv_msg.msg_style = PAM_ERROR_MSG;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d",
								__FUNCTION__, conv_msg.msg, retval);
					}

				}
				status = PAM_AUTH_ERR;
				communicating = 0;

				_pam_log(LOG_ERR, "auth failed: %d", msg);

				break;

			case TAC_PLUS_AUTHEN_STATUS_GETDATA:
				if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETDATA");

				if (NULL != conv_msg.msg) {
					int echo_off = (0x1 == (re.flags & 0x1));

					conv_msg.msg_style =
							echo_off ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "sent msg=\"%s\", resp=\"%s\"",
									conv_msg.msg, resp->resp);

						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "%s: calling tac_cont_send",
									__FUNCTION__);

						if (0
								> tac_cont_send_seq(tac_fd, resp->resp,
										re.seq_no + 1)) {
							_pam_log(LOG_ERR,
									"error sending continue req to TACACS+ server");
							status = PAM_AUTH_ERR;
							communicating = 0;
						}
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d (%s)",
								__FUNCTION__, conv_msg.msg, retval,
								pam_strerror(pamh, retval));
						status = PAM_AUTH_ERR;
						communicating = 0;
					}
				} else {
					syslog(LOG_ERR,
							"GETDATA response with no message, returning PAM_AUTH_ERR");

					status = PAM_AUTH_ERR;
					communicating = 0;
				}

				break;

			case TAC_PLUS_AUTHEN_STATUS_GETUSER:
				/* not implemented */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETUSER");

				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_GETPASS:
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETPASS");

				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: tac_cont_send called", __FUNCTION__);

				if (tac_cont_send(tac_fd, pass) < 0) {
					_pam_log(LOG_ERR,
							"error sending continue req to TACACS+ server");
					communicating = 0;
				}
				/* continue the while loop; go read tac response */
				break;

			case TAC_PLUS_AUTHEN_STATUS_RESTART:
				/* try it again */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_RESTART");

				/*
				 * not implemented
				 * WdJ: I *think* you can just do tac_authen_send(user, pass) again
				 *      but I'm not sure
				 */
				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_ERROR:
				/* server has problems */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_ERROR");

				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
				/* server tells to try a different server address */
				/* not implemented */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_FOLLOW");

				communicating = 0;
				break;

			default:
				if (msg < 0) {
					/* connection error */
					communicating = 0;
					if (ctrl & PAM_TAC_DEBUG)
						syslog(LOG_DEBUG,
								"error communicating with tacacs server");
					break;
				}

				/* unknown response code */
				communicating = 0;
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "tacacs status: unknown response 0x%02x",
							msg);
			}

			if (NULL != resp) {
				free(resp->resp);
				free(resp);
			}

			free(re.msg);

		} /* end while(communicating) */
		close(tac_fd);

		if (status == PAM_SUCCESS || status == PAM_AUTH_ERR)
			break;
	}
	if (status != PAM_SUCCESS && status != PAM_AUTH_ERR)
		_pam_log(LOG_ERR, "no more servers to connect");

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: exit with pam status: %d", __FUNCTION__, status);

	if (NULL != pass) {
		bzero(pass, strlen(pass));
		free(pass);
		pass = NULL;
	}

	return status;
} /* pam_sm_authenticate */

/* no-op function to satisfy PAM authentication module */
PAM_EXTERN
int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv) {

	int ctrl = _pam_parse(argc, argv);

	pamh = pamh;
	flags = flags;				/* unused */

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)", __FUNCTION__,
				PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	return PAM_SUCCESS;
} /* pam_sm_setcred */

/* authorizes user on remote TACACS+ server, i.e. checks
 * his permission to access requested service
 * returns PAM_SUCCESS if the service is allowed
 */
PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
		const char **argv) {

	int retval, ctrl, status = PAM_AUTH_ERR;
	char *user;
	char *tty;
	char *r_addr;
	struct areply arep;
	struct tac_attrib *attr = NULL;
	int tac_fd;

	flags = flags;				/* unused */

	user = tty = r_addr = NULL;
	memset(&arep, 0, sizeof(arep));

	/* this also obtains service name for authorization
	 this should be normally performed by pam_get_item(PAM_SERVICE)
	 but since PAM service names are incompatible TACACS+
	 we have to pass it via command line argument until a better
	 solution is found ;) */
	ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)", __FUNCTION__,
				PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	if ((user = _pam_get_user(pamh)) == NULL)
		return PAM_USER_UNKNOWN;

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: username obtained [%s]", __FUNCTION__, user);

	tty = _pam_get_terminal(pamh);
	if (!strncmp(tty, "/dev/", 5))
		tty += 5;
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty obtained [%s]", __FUNCTION__, tty);

	r_addr = _pam_get_rhost(pamh);
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: rhost obtained [%s]", __FUNCTION__, r_addr);

	/* checks if user has been successfully authenticated
	 by TACACS+; we cannot solely authorize user if it hasn't
	 been authenticated or has been authenticated by method other
	 than TACACS+ */
	if (active_server.addr == NULL) {
		_pam_log(LOG_ERR, "user not authenticated by TACACS+");
		return PAM_AUTH_ERR;
	}
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: active server is [%s]", __FUNCTION__,
				tac_ntop(active_server.addr->ai_addr));

	/* checks for specific data required by TACACS+, which should
	 be supplied in command line  */
	if (!*tac_service) {
		_pam_log(LOG_ERR, "SM: TACACS+ service type not configured");
		return PAM_AUTH_ERR;
	}
	if (!*tac_protocol) {
		_pam_log(LOG_ERR, "SM: TACACS+ protocol type not configured (IGNORED)");
	}

	tac_add_attrib(&attr, "service", tac_service);
	if (tac_protocol[0] != '\0')
		tac_add_attrib(&attr, "protocol", tac_protocol);

	tac_fd = tac_connect_single(active_server.addr, active_server.key, NULL,
			tac_timeout);
	if (tac_fd < 0) {
		_pam_log(LOG_ERR, "TACACS+ server unavailable");
		return PAM_AUTH_ERR;
	}

	retval = tac_author_send(tac_fd, user, tty, r_addr, attr);

	tac_free_attrib(&attr);

	if (retval < 0) {
		_pam_log(LOG_ERR, "error getting authorization");
		close(tac_fd);
		active_server.addr = NULL;
		return PAM_AUTH_ERR;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: sent authorization request", __FUNCTION__);

	tac_author_read(tac_fd, &arep);

	if (arep.status != AUTHOR_STATUS_PASS_ADD
			&& arep.status != AUTHOR_STATUS_PASS_REPL) {

		_pam_log(LOG_ERR, "TACACS+ authorisation failed for [%s]", user);
		if (arep.msg != NULL)
			free(arep.msg);

		close(tac_fd);
		return PAM_PERM_DENIED;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] successfully authorized", __FUNCTION__,
				user);

	status = PAM_SUCCESS;

	attr = arep.attr;
	while (attr != NULL) {
		size_t len = strcspn(attr->attr, "=*");
		if (len < attr->attr_len) {
			char avpair[attr->attr_len+1];
			bcopy(attr->attr, avpair, attr->attr_len+1); /* Also copy terminating NUL */

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: returned attribute `%s' from server",
						__FUNCTION__, avpair);

			avpair[len] = '='; // replace '*' by '='
			size_t i;
			for (i = 0; i < len; i++) {
				avpair[i] = toupper(avpair[i]);
				if (avpair[i] == '-')
					avpair[i] = '_';
			}

			if (ctrl & PAM_TAC_DEBUG)
				syslog(LOG_DEBUG, "%s: setting PAM environment `%s'",
						__FUNCTION__, avpair);

			/* make returned attributes available for other PAM modules via PAM environment */
			if (pam_putenv(pamh, avpair) != PAM_SUCCESS)
				syslog(LOG_WARNING, "%s: unable to set PAM environment",
						__FUNCTION__);

		} else {
			syslog(LOG_WARNING, "%s: invalid attribute `%s', no separator",
					__FUNCTION__, attr->attr);
		}
		attr = attr->next;
	}

	/* free returned attributes */
	if (arep.attr != NULL)
		tac_free_attrib(&arep.attr);

	if (arep.msg != NULL)
		free(arep.msg);

	close(tac_fd);

	return status;
} /* pam_sm_acct_mgmt */

/* sends START accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
/* accounting packets may be directed to any TACACS+ server,
 * independent from those used for authentication and authorization;
 * it may be also directed to all specified servers
 */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
		const char **argv) {
#if defined(HAVE_OPENSSL_RAND_H) && defined(HAVE_LIBCRYPTO)
# if defined(HAVE_RAND_BYTES)
	RAND_bytes((unsigned char *) &task_id, sizeof(task_id));
# else
	RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
# endif
#else
	task_id=(short int) magic();
#endif
	flags = flags;				/* unused */

	return _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_START, NULL);
} /* pam_sm_open_session */

/* sends STOP accounting request to the remote TACACS+ server
 * returns PAM error only if the request was refused or there
 * were problems connection to the server
 */
PAM_EXTERN
int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
		const char **argv) {

	flags = flags;				/* unused */

	return _pam_account(pamh, argc, argv, TAC_PLUS_ACCT_FLAG_STOP, NULL);
} /* pam_sm_close_session */

#ifdef PAM_SM_PASSWORD
/* no-op function for future use */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
		const char **argv) {

	int ctrl, retval;
	char *user;
	char *pass;
	char *tty;
	char *r_addr;
	const void *pam_pass = NULL;
	int srv_i;
	int tac_fd, status, msg, communicating;

	user = pass = tty = r_addr = NULL;

	ctrl = _pam_parse(argc, argv);

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: called (pam_tacplus v%u.%u.%u)", __FUNCTION__,
				PAM_TAC_VMAJ, PAM_TAC_VMIN, PAM_TAC_VPAT);

	syslog(LOG_DEBUG, "%s(flags=%d, argc=%d)", __func__, flags, argc);

	if ((pam_get_item(pamh, PAM_OLDAUTHTOK, &pam_pass) == PAM_SUCCESS)
			&& (pam_pass != NULL)) {
		if ((pass = strdup(pam_pass)) == NULL)
			return PAM_BUF_ERR;
	} else {
		pass = strdup("");
	}

	if ((user = _pam_get_user(pamh)) == NULL) {
		if (pass) {
			free(pass);
		}
		return PAM_USER_UNKNOWN;
	}

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: user [%s] obtained", __FUNCTION__, user);

	tty = _pam_get_terminal(pamh);
	if (!strncmp(tty, "/dev/", 5))
		tty += 5;
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: tty [%s] obtained", __FUNCTION__, tty);

	r_addr = _pam_get_rhost(pamh);
	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: rhost [%s] obtained", __FUNCTION__, r_addr);

	if (PAM_SILENT == (flags & PAM_SILENT)) {
		status = PAM_AUTHTOK_ERR;
		goto finish;
	}

	status = PAM_TRY_AGAIN;
	for (srv_i = 0; srv_i < tac_srv_no; srv_i++) {
		if (ctrl & PAM_TAC_DEBUG)
			syslog(LOG_DEBUG, "%s: trying srv %d", __FUNCTION__, srv_i);

		tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
				NULL, tac_timeout);
		if (tac_fd < 0) {
			_pam_log(LOG_ERR, "connection failed srv %d: %m", srv_i);
			continue;
		}
		if (PAM_PRELIM_CHECK == (flags & PAM_PRELIM_CHECK)) {
			if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
				syslog(LOG_DEBUG, "%s: finishing PAM_PRELIM_CHECK with srv %d",
						__FUNCTION__, srv_i);

			close(tac_fd);
			status = PAM_SUCCESS;
			goto finish;
		}

		if (tac_authen_send(tac_fd, user, "", tty, r_addr,
				TAC_PLUS_AUTHEN_CHPASS) < 0) {
			close(tac_fd);
			_pam_log(LOG_ERR, "error sending auth req to TACACS+ server");
			continue;
		}
		communicating = 1;
		while (communicating) {
			struct areply re = { .attr = NULL, .msg = NULL, .status = 0,
					.flags = 0 };
			struct pam_message conv_msg = { .msg_style = 0, .msg = NULL };
			struct pam_response *resp = NULL;

			msg = tac_authen_read(tac_fd, &re);

			if (NULL != re.msg) {
				conv_msg.msg = re.msg;
			}

			/* talk the protocol */
			switch (msg) {
			case TAC_PLUS_AUTHEN_STATUS_PASS:
				/* success */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_PASS");

				if (NULL != conv_msg.msg) {
					conv_msg.msg_style = PAM_TEXT_INFO;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d",
								__FUNCTION__, conv_msg.msg, retval);
					}

				}
				status = PAM_SUCCESS;
				communicating = 0;
				set_active_server(&tac_srv[srv_i]);

				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: active srv %d", __FUNCTION__, srv_i);

				break;

			case TAC_PLUS_AUTHEN_STATUS_FAIL:
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_FAIL");

				if (NULL != conv_msg.msg) {
					conv_msg.msg_style = PAM_ERROR_MSG;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "send msg=\"%s\"", conv_msg.msg);
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d",
								__FUNCTION__, conv_msg.msg, retval);
					}

				}
				status = PAM_AUTHTOK_ERR;
				communicating = 0;

				_pam_log(LOG_ERR, "chauthtok failed: %d", msg);

				break;

			case TAC_PLUS_AUTHEN_STATUS_GETDATA:
				if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETDATA");

				if (NULL != conv_msg.msg) {
					int echo_off = (0x1 == (re.flags & 0x1));

					conv_msg.msg_style =
							echo_off ? PAM_PROMPT_ECHO_OFF : PAM_PROMPT_ECHO_ON;
					retval = converse(pamh, 1, &conv_msg, &resp);
					if (PAM_SUCCESS == retval) {
						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "sent msg=\"%s\", resp=\"%s\"",
									conv_msg.msg, resp->resp);

						if (PAM_TAC_DEBUG == (ctrl & PAM_TAC_DEBUG))
							syslog(LOG_DEBUG, "%s: calling tac_cont_send",
									__FUNCTION__);

						if (0
								> tac_cont_send_seq(tac_fd, resp->resp,
										re.seq_no + 1)) {
							_pam_log(LOG_ERR,
									"error sending continue req to TACACS+ server");
							communicating = 0;
						}
					} else {
						_pam_log(LOG_WARNING,
								"%s: error sending msg=\"%s\", retval=%d",
								__FUNCTION__, conv_msg.msg, retval);
						communicating = 0;
					}
				} else {
					syslog(LOG_ERR,
							"GETDATA response with no message, returning PAM_TRY_AGAIN");
					communicating = 0;
				}

				break;

			case TAC_PLUS_AUTHEN_STATUS_GETUSER:
				/* not implemented */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETUSER");

				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_GETPASS:
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_GETPASS");

				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "%s: calling tac_cont_send",
							__FUNCTION__);

				if (tac_cont_send(tac_fd, pass) < 0) {
					_pam_log(LOG_ERR,
							"error sending continue req to TACACS+ server");
					communicating = 0;
					break;
				}
				/* continue the while loop; go read tac response */
				break;

			case TAC_PLUS_AUTHEN_STATUS_RESTART:
				/* try it again */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_RESTART");

				/*
				 * not implemented
				 * WdJ: I *think* you can just do tac_authen_send(user, pass) again
				 *      but I'm not sure
				 */
				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_ERROR:
				/* server has problems */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_ERROR");

				communicating = 0;
				break;

			case TAC_PLUS_AUTHEN_STATUS_FOLLOW:
				/* server tells to try a different server address */
				/* not implemented */
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG,
							"tacacs status: TAC_PLUS_AUTHEN_STATUS_FOLLOW");

				communicating = 0;
				break;

			default:
				if (msg < 0) {
					/* connection error */
					communicating = 0;
					if (ctrl & PAM_TAC_DEBUG)
						syslog(LOG_DEBUG,
								"error communicating with tacacs server");
					break;
				}

				/* unknown response code */
				communicating = 0;
				if (ctrl & PAM_TAC_DEBUG)
					syslog(LOG_DEBUG, "tacacs status: unknown response 0x%02x",
							msg);
			}

			if (NULL != resp) {
				free(resp->resp);
				free(resp);
			}

			free(re.msg);

		} /* end while(communicating) */
		close(tac_fd);

		if (status == PAM_SUCCESS || status == PAM_AUTHTOK_ERR)
			break;
	}

	finish: if (status != PAM_SUCCESS && status != PAM_AUTHTOK_ERR)
		_pam_log(LOG_ERR, "no more servers to connect");

	if (ctrl & PAM_TAC_DEBUG)
		syslog(LOG_DEBUG, "%s: exit with pam status: %d", __FUNCTION__, status);

	if (NULL != pass) {
		bzero(pass, strlen(pass));
		free(pass);
		pass = NULL;
	}

	return status;
} /* pam_sm_chauthtok */
#endif

#ifdef PAM_STATIC
struct pam_module _pam_tacplus_modstruct {
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

