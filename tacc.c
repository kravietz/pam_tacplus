/* tacc.c  TACACS+ PAP authentication client
 *
 * Copyright 1997-98 by Pawel Krawczyk <kravietz@ceti.com.pl>
 * Portions copyright (c) 1989 Carnegie Mellon University.
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 */

#include <stdio.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <stdarg.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_PUTUTXLINE)
#include <utmpx.h>
#elif defined(HAVE_LOGWTMP)
#include <utmp.h>
#endif

#include "tacplus.h"
#include "libtac.h"

/* Prompt displayed when asking for password */
#define PASSWORD_PROMPT "Password: "

/* if defined, given command will be run after
 * successful authentication and proper wtmp
 * entries will be made
 */
#define DEFAULT_COMMAND "/usr/sbin/pppd -detach"

/* message that will be displayed to user
 * before starting COMMAND
 */
#define COMMAND_MESSAGE "Starting PPP\n"

/* timeout for reading password from user (seconds) */
#define GETPASS_TIMEOUT 60

/* end of CONFIGURABLE PARAMETERS */

/* prototypes */
void sighandler(int sig);
unsigned long getservername(char *serv);
void showusage(char *progname);
void showversion(char *progname);
void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
		const char *user, const char *pass, const char *tty,
		const char *remote_addr);
void timeout_handler(int signum);

#define	EXIT_OK		0
#define	EXIT_FAIL	1	/* AAA failure (or server error) */
#define	EXIT_ERR	2	/* local error */

#define USE_SYSTEM	1

/* globals */
int tac_encryption = 1;
typedef unsigned char flag;
flag quiet = 0;
char *user = NULL; /* global, because of signal handler */

#if defined(HAVE_PUTUTXLINE)
struct utmpx utmpx;
#endif

/* take the length of a string constant without the NUL */
#define C_STRLEN(str)	(sizeof("" str) - 1)

/* command line options */
static struct option long_options[] =
		{
		/* operation */
		{ "authenticate", no_argument, NULL, 'T' }, { "authorize", no_argument,
				NULL, 'R' }, { "account", no_argument, NULL, 'A' }, { "version",
				no_argument, NULL, 'V' }, { "help", no_argument, NULL, 'h' },

		/* data */
		{ "username", required_argument, NULL, 'u' }, { "remote",
				required_argument, NULL, 'r' }, { "password", required_argument,
				NULL, 'p' }, { "server", required_argument, NULL, 's' }, {
				"secret", required_argument, NULL, 'k' }, { "command",
				required_argument, NULL, 'c' }, { "exec", required_argument,
				NULL, 'c' }, { "service", required_argument, NULL, 'S' }, {
				"protocol", required_argument, NULL, 'P' }, { "remote",
				required_argument, NULL, 'r' }, { "login", required_argument,
				NULL, 'L' }, { "tty", required_argument, NULL, 'y' },

		/* modifiers */
		{ "quiet", no_argument, NULL, 'q' },
				{ "silent", no_argument, NULL, 'q' }, { "no-wtmp", no_argument,
						NULL, 'w' }, { "no-encrypt", no_argument, NULL, 'n' }, {
						0, 0, 0, 0 } };

/* command line letters */
char *opt_string = "TRAVhu:p:s:k:c:qr:wnS:P:L:y:";

int main(int argc, char **argv) {
	char *pass = NULL;
	char *tty = NULL;
	char *command = NULL;
	char *remote_addr = NULL;
	char *service = NULL;
	char *protocol = NULL;
	struct addrinfo *tac_server;
	char *tac_server_name = NULL;
	char *tac_secret = NULL;
	int tac_fd;
	short int task_id = 0;
	char buf[40];
	int ret;
#ifndef USE_SYSTEM
	pid_t pid;
#endif
	struct areply arep;

	/* options */
	flag log_wtmp = 1;
	flag do_author = 0;
	flag do_authen = 0;
	flag do_account = 0;
	flag login_mode = 0;

	/* check argc */
	if (argc < 2) {
		showusage(argv[0]);
		exit(EXIT_ERR);
	}

	/* check for login mode */
	if (argc == 2 && isalpha(*argv[1])) {
		user = argv[1];
		do_author = do_authen = do_account = 1;
		command = DEFAULT_COMMAND;
		login_mode = 1;
	} else {
		int c;
		int opt_index;

		while ((c = getopt_long(argc, argv, opt_string, long_options,
				&opt_index)) != EOF) {
			switch (c) {
			case 'T':
				do_authen = 1;
				break;
			case 'R':
				do_author = 1;
				break;
			case 'A':
				do_account = 1;
				break;
			case 'V':
				showversion(argv[0]);
				/*NOTREACHED*/
				break;
			case 'h':
				showusage(argv[0]);
				/*NOTREACHED*/
				break;
			case 'u':
				user = optarg;
				break;
			case 'r':
				remote_addr = optarg;
				break;
			case 'L':
				// tac_login is a global variable initialized in libtac
				xstrcpy(tac_login, optarg, sizeof(tac_login));
				break;
			case 'p':
				pass = optarg;
				break;
			case 's':
				tac_server_name = optarg;
				break;
			case 'k':
				tac_secret = optarg;
				break;
			case 'c':
				command = optarg;
				break;
			case 'S':
				service = optarg;
				break;
			case 'P':
				protocol = optarg;
				break;
			case 'q':
				quiet = 1;
				break;
			case 'w':
				log_wtmp = 0;
				break;
			case 'n':
				tac_encryption = 0;
				break;
			case 'y':
				tty = optarg;
				break;
			}
		}
	}

	/* check available information and set to defaults if needed */
	if (do_authen + do_author + do_account == 0) {
		printf("error: one of -TRAVh options is required\n");
		exit(EXIT_ERR);
	}

	if (user == NULL) {
		printf("error: username is required.\n");
		exit(EXIT_ERR);
	}

	if (remote_addr == NULL) {
		printf("error: remote address is required.\n");
		exit(EXIT_ERR);
	}

	if (service == NULL) {
		printf("error: service is required.\n");
		exit(EXIT_ERR);
	}

	if (protocol == NULL) {
		printf("error: protocol is required.\n");
		exit(EXIT_ERR);
	}

	if (tac_server_name == NULL) {
		printf("error: server name is required.\n");
		exit(EXIT_ERR);
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(tac_server_name, "tacacs", &hints, &tac_server);
	if (ret != 0) {
		printf("error: resolving name %s: %s", tac_server_name,
				gai_strerror(ret));
		exit(EXIT_ERR);
	}

	if (tac_secret == NULL) {
		printf("error: server secret is required.\n");
		exit(EXIT_ERR);
	}

	if (pass == NULL) {
		signal(SIGALRM, timeout_handler);
		alarm(GETPASS_TIMEOUT);
		pass = getpass(PASSWORD_PROMPT);
		alarm(0);
		signal(SIGALRM, SIG_DFL);
		if (!strlen(pass))
			exit(EXIT_ERR);
	}

	if (tty == NULL) {
		printf("error: tty name is required.\n");
		exit(EXIT_ERR);
	}

	/* open syslog before any TACACS+ calls */
	openlog("tacc", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

	if (do_authen)
		authenticate(tac_server, tac_secret, user, pass, tty, remote_addr);

	if (do_author) {
		/* authorize user */
		struct tac_attrib *attr = NULL;
		tac_add_attrib(&attr, "service", service);
		tac_add_attrib(&attr, "protocol", protocol);

		tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
		if (tac_fd < 0) {
			if (!quiet)
				printf("Error connecting to TACACS+ server: %m\n");
			exit(EXIT_ERR);
		}

		tac_author_send(tac_fd, user, tty, remote_addr, attr);

		tac_author_read(tac_fd, &arep);
		if (arep.status != AUTHOR_STATUS_PASS_ADD
				&& arep.status != AUTHOR_STATUS_PASS_REPL) {
			if (!quiet)
				printf("Authorization FAILED: %s\n", arep.msg);
			exit(EXIT_FAIL);
		} else {
			if (!quiet)
				printf("Authorization OK: %s\n", arep.msg);
		}

		tac_free_attrib(&attr);
	}

	/* we no longer need the password in our address space */
	bzero(pass, strlen(pass));
	pass = NULL;

	if (do_account) {
		/* start accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "start_time", buf);
#ifdef HAVE_RAND_BYTES
		RAND_bytes((unsigned char *) &task_id, sizeof(task_id));
#else
		RAND_pseudo_bytes((unsigned char *) &task_id, sizeof(task_id));
#endif
		sprintf(buf, "%hu", task_id);
		tac_add_attrib(&attr, "task_id", buf);
		tac_add_attrib(&attr, "service", service);
		tac_add_attrib(&attr, "protocol", protocol);

		tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
		if (tac_fd < 0) {
			if (!quiet)
				printf("Error connecting to TACACS+ server: %m\n");
			exit(EXIT_ERR);
		}

		tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, tty, remote_addr,
				attr);

		ret = tac_acct_read(tac_fd, &arep);
		if (ret == 0) {
			if (!quiet)
				printf("Accounting: START failed: %s\n", arep.msg);
			syslog(LOG_INFO, "TACACS+ accounting start failed: %s", arep.msg);
		} else if (!login_mode && !quiet)
			printf("Accounting: START OK\n");

		close(tac_fd);

		tac_free_attrib(&attr);

	}

	/* log in local utmp */
	if (log_wtmp) {
#if defined(HAVE_PUTUTXLINE)
		struct timeval tv;

		gettimeofday(&tv, NULL);

		memset(&utmpx, 0, sizeof(utmpx));
		utmpx.ut_type = USER_PROCESS;
		utmpx.ut_pid = getpid();
		xstrcpy(utmpx.ut_line, tty, sizeof(utmpx.ut_line));
		strncpy(utmpx.ut_id, tty + C_STRLEN("tty"), sizeof(utmpx.ut_id));
		xstrcpy(utmpx.ut_host, "dialup", sizeof(utmpx.ut_host));
		utmpx.ut_tv.tv_sec = tv.tv_sec;
		utmpx.ut_tv.tv_usec = tv.tv_usec;
		xstrcpy(utmpx.ut_user, user, sizeof(utmpx.ut_user));
		/* ut_addr unused ... */
		setutxent();
		pututxline(&utmpx);
#elif defined(HAVE_LOGWTMP)
		logwtmp(tty, user, "dialup");
#endif
	}

	if (command != NULL) {
		int ret;

		syslog(LOG_DEBUG, "starting %s for %s", command, user);

		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);

#ifdef COMMAND_MESSAGE
		printf(COMMAND_MESSAGE);
#endif

#if USE_SYSTEM
		ret = system(command);
		if (ret < 0)
			syslog(LOG_WARNING, "command failed: %m");
		else
			syslog(LOG_NOTICE, "command exit code %u", ret);
#else
		pid=fork();

		if(pid == 0) {
			/* child */

			execl(DEFAULT_COMMAND, DEFAULT_COMMAND, ARGS, NULL);
			syslog(LOG_ERR, "execl() failed: %m");
			_exit(EXIT_FAIL);
		}

		if(pid < 0) {
			/* error */
			syslog(LOG_ERR, "fork failed: %m");
			exit(EXIT_FAIL);
		}

		if(pid > 0) {
			/* parent */
			int st, r;

			r=wait(&st);
		}
#endif
	}

	if (do_account) {
		/* stop accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "stop_time", buf);
		sprintf(buf, "%hu", task_id);
		tac_add_attrib(&attr, "task_id", buf);

		tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
		if (tac_fd < 0) {
			if (!quiet)
				printf("Error connecting to TACACS+ server: %m\n");
			exit(EXIT_ERR);
		}

		tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user, tty, remote_addr,
				attr);
		ret = tac_acct_read(tac_fd, &arep);
		if (ret == 0) {
			if (!quiet)
				printf("Accounting: STOP failed: %s", arep.msg);
			syslog(LOG_INFO, "TACACS+ accounting stop failed: %s\n", arep.msg);
		} else if (!login_mode && !quiet)
			printf("Accounting: STOP OK\n");

		close(tac_fd);

		tac_free_attrib(&attr);
	}

	/* logout from utmp */
	if (log_wtmp) {
#if defined(HAVE_PUTUTXLINE)
		utmpx.ut_type = DEAD_PROCESS;
		memset(utmpx.ut_line, 0, sizeof(utmpx.ut_line));
		memset(utmpx.ut_user, 0, sizeof(utmpx.ut_user));
		memset(utmpx.ut_host, 0, sizeof(utmpx.ut_host));
		utmpx.ut_tv.tv_sec = utmpx.ut_tv.tv_usec = 0;
		setutxent();
		pututxline(&utmpx);
#elif defined(HAVE_LOGWTMP)
		logwtmp(tty, "", "");
#endif
	}

	exit(EXIT_OK);
}

void sighandler(int sig __Unused) {
	TACDEBUG(LOG_DEBUG, "caught signal %d", sig);
}

void authenticate(const struct addrinfo *tac_server, const char *tac_secret,
		const char *user, const char *pass, const char *tty,
		const char *remote_addr) {
	int tac_fd;
	int ret;
	struct areply arep;

	tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
	if (tac_fd < 0) {
		if (!quiet)
			printf("Error connecting to TACACS+ server: %m\n");
		exit(EXIT_ERR);
	}

	/* start authentication */

	if (tac_authen_send(tac_fd, user, pass, tty, remote_addr,
			TAC_PLUS_AUTHEN_LOGIN) < 0) {
		if (!quiet)
			printf("Error sending query to TACACS+ server\n");
		exit(EXIT_ERR);
	}

	ret = tac_authen_read(tac_fd, &arep);

	if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {

		if (tac_cont_send(tac_fd, pass) < 0) {
			if (!quiet)
				printf("Error sending query to TACACS+ server\n");
			exit(EXIT_ERR);
		}

		ret = tac_authen_read(tac_fd, &arep);
	}

	if (ret != TAC_PLUS_AUTHEN_STATUS_PASS) {
		if (!quiet)
			printf("Authentication FAILED: %s\n", arep.msg);
		syslog(LOG_ERR, "authentication failed for %s: %s", user, arep.msg);
		exit(EXIT_FAIL);
	}

	if (!quiet)
		printf("Authentication OK\n");
	syslog(LOG_INFO, "authentication OK for %s", user);

	close(tac_fd);
}

void showusage(char *progname) {
	char *a;

	a = rindex(progname, '/');
	progname = (a == NULL) ? progname : ++a;

	printf("%s -- simple TACACS+ client and login, version %u.%u.%u\n",
			progname, tac_ver_major, tac_ver_minor, tac_ver_patch);
	printf("Copyright 1997-2016 by Pawel Krawczyk <pawel.krawczyk@hush.com>\n");
	printf("Usage: %s option [option, ...]\n\n", progname);
	printf(" Action:\n");
	printf(
			"  -T, --authenticate  perform authentication with username and password\n");
	printf(
			"  -R, --authorize     perform authorization for requested service\n");
	printf("  -A, --account       account session beginning and end\n");
	printf("  -h, --help          display this help and exit\n");
	printf("  -V, --version       display version number and exit\n\n");
	printf(" Data:\n");
	printf("  -u, --username      remote user name\n");
	printf("  -p, --password      remote user password\n");
	printf("  -s, --server        server IP address or FQDN\n");
	printf("  -r, --remote        remote client's IP address\n");
	printf("  -S, --service       requested service (e.g. ppp)\n");
	printf("  -P, --protocol      requested protocl (e.g. ip)\n");
	printf("  -L, --login         TACACS+ login mode (e.g. chap, login)\n");
	printf("  -k, --secret        server encryption key\n");
	printf("  -c, --command       command to execute after successful AAA\n");
	printf("       --exec         alias for --command\n\n");
	printf(" Modifiers:\n");
	printf(
			"  -q, --quiet         don't display messages to screen (but still\n");
	printf("      --silent        report them via syslog(3))\n");
	printf("  -w, --no-wtmp       don't write records to wtmp(5)\n");
	printf(
			"  -n, --no-encrypt    don't encrypt AAA packets sent to servers\n\n");
	printf("  -y, --tty           remote user tty or port\n");
	printf("Example usage:\n\n");
	printf(
			"  tacc -TRA -u test1 -p test1 -s localhost -r 1.1.1.1 -k test1 -S ppp -P ip -y ttyS17\n");

	exit(EXIT_ERR);
}

void showversion(char *progname) {
	char *a;

	a = rindex(progname, '/');
	progname = (a == NULL) ? progname : ++a;

	printf("%s %u.%u.%u\n", progname, tac_ver_major, tac_ver_minor,
			tac_ver_patch);
	exit(EXIT_OK);
}

unsigned long getservername(char *serv) {
	struct in_addr addr;
	struct hostent *h;

	if (inet_aton(serv, &addr) == 0) {
		if ((h = gethostbyname(serv)) == NULL) {
			herror("gethostbyname");
		} else {
			bcopy(h->h_addr, (char *)&addr, sizeof(struct in_addr));
			return(addr.s_addr);
		}
	} else
	return(addr.s_addr);

	return (-1);
}

void timeout_handler(int signum __Unused) {
	syslog(LOG_ERR, "timeout reading password from user %s", user);
}

#ifdef TACDEBUG_AT_RUNTIME
void logmsg(int level __Unused, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}
#endif
