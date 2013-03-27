/* support.c - support functions for pam_tacplus.c
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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
/* #define PAM_SM_PASSWORD */

#ifndef __linux__
    #include <security/pam_appl.h>
#endif
#include <security/pam_modules.h>

#include "pam_tacplus.h"
#include "libtac.h"

struct addrinfo *tac_srv[TAC_PLUS_MAXSERVERS];
int tac_srv_no = 0;
char *tac_srv_key[TAC_PLUS_MAXSERVERS];
int tac_srv_key_no = 0;
char *tac_service = NULL;
char *tac_protocol = NULL;
char *tac_prompt = NULL;

/* libtac */
extern char *tac_login;
extern int tac_timeout;

/*
    FIXME using xcalloc() leaks memory for long-running programs that authenticate multiple times
*/
#ifndef xcalloc
void *_xcalloc (size_t size) {
    register void *val = calloc (1, size);
    if (val == 0) {
        syslog (LOG_ERR, "xcalloc: calloc(1,%u) failed", (unsigned) size);
        abort();
    }
    return val;
}
#else
#define _xcalloc xcalloc
#endif

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

char *_pam_get_user(pam_handle_t *pamh) {
    int retval;
    char *user;

    retval = pam_get_user(pamh, (void *)&user, "Username: ");
    if (retval != PAM_SUCCESS || user == NULL || *user == '\0') {
        _pam_log(LOG_ERR, "unable to obtain username");
        user = NULL;
    }
    return user;
}

char *_pam_get_terminal(pam_handle_t *pamh) {
    int retval;
    char *tty;

    retval = pam_get_item(pamh, PAM_TTY, (void *)&tty);
    if (retval != PAM_SUCCESS || tty == NULL || *tty == '\0') {
        tty = ttyname(STDIN_FILENO);
        if(tty == NULL || *tty == '\0')
            tty = "unknown";
    }
    return tty;
}

char *_pam_get_rhost(pam_handle_t *pamh) {
    int retval;
    char *rhost;

    retval = pam_get_item(pamh, PAM_RHOST, (void *)&rhost);
    if (retval != PAM_SUCCESS || rhost == NULL || *rhost == '\0') {
        rhost = "unknown";
    }
    return rhost;
}

int converse(pam_handle_t * pamh, int nargs, const struct pam_message *message,
    struct pam_response **response) {

    int retval;
    struct pam_conv *conv;

    if ((retval = pam_get_item (pamh, PAM_CONV, (const void **)&conv)) == PAM_SUCCESS) {
        retval = conv->conv(nargs, &message, response, conv->appdata_ptr);

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

    const void *pam_pass;
    char *pass = NULL;

    if (ctrl & PAM_TAC_DEBUG)
        syslog (LOG_DEBUG, "%s: called", __FUNCTION__);

    if ( (ctrl & (PAM_TAC_TRY_FIRST_PASS | PAM_TAC_USE_FIRST_PASS))
        && (pam_get_item(pamh, PAM_AUTHTOK, &pam_pass) == PAM_SUCCESS)
        && (pam_pass != NULL) ) {
         if ((pass = strdup(pam_pass)) == NULL)
              return PAM_BUF_ERR;
    } else if ((ctrl & PAM_TAC_USE_FIRST_PASS)) {
         _pam_log(LOG_WARNING, "no forwarded password");
         return PAM_PERM_DENIED;
    } else {
         struct pam_message msg;
         struct pam_response *resp = NULL;
         int retval;

         /* set up conversation call */
         msg.msg_style = PAM_PROMPT_ECHO_OFF;

         if (!tac_prompt) {
             msg.msg = "Password: ";
         } else {
             msg.msg = tac_prompt;
         }

         if ((retval = converse (pamh, 1, &msg, &resp)) != PAM_SUCCESS)
             return retval;

         if (resp != NULL) {
             if (resp->resp == NULL && (ctrl & PAM_TAC_DEBUG))
                 _pam_log (LOG_DEBUG, "pam_sm_authenticate: NULL authtok given");

             pass = resp->resp;    /* remember this! */
             resp->resp = NULL;

             free(resp);
             resp = NULL;
         } else {
             if (ctrl & PAM_TAC_DEBUG) {
               _pam_log (LOG_DEBUG, "pam_sm_authenticate: no error reported");
               _pam_log (LOG_DEBUG, "getting password, but NULL returned!?");
             }
             return PAM_CONV_ERR;
         }
    }

    /*
       FIXME *password can still turn out as NULL
       and it can't be free()d when it's NULL
    */
    *password = pass;       /* this *MUST* be free()'d by this module */

    if(ctrl & PAM_TAC_DEBUG)
        syslog(LOG_DEBUG, "%s: obtained password", __FUNCTION__);

    return PAM_SUCCESS;
}

int _pam_parse (int argc, const char **argv) {
    int ctrl = 0;

    /* otherwise the list will grow with each call */
    tac_srv_no = tac_srv_key_no = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        if (!strcmp (*argv, "debug")) { /* all */
            ctrl |= PAM_TAC_DEBUG;
        } else if (!strcmp (*argv, "use_first_pass")) {
            ctrl |= PAM_TAC_USE_FIRST_PASS;
        } else if (!strcmp (*argv, "try_first_pass")) { 
            ctrl |= PAM_TAC_TRY_FIRST_PASS;
        } else if (!strncmp (*argv, "service=", 8)) { /* author & acct */
            tac_service = (char *) _xcalloc (strlen (*argv + 8) + 1);
            strcpy (tac_service, *argv + 8);
        } else if (!strncmp (*argv, "protocol=", 9)) { /* author & acct */
            tac_protocol = (char *) _xcalloc (strlen (*argv + 9) + 1);
            strcpy (tac_protocol, *argv + 9);
        } else if (!strncmp (*argv, "prompt=", 7)) { /* authentication */
            tac_prompt = (char *) _xcalloc (strlen (*argv + 7) + 1);
            strcpy (tac_prompt, *argv + 7);
            /* Replace _ with space */
            int chr;
            for (chr = 0; chr < strlen(tac_prompt); chr++) {
                if (tac_prompt[chr] == '_') {
                    tac_prompt[chr] = ' ';
                }
            }
        } else if (!strcmp (*argv, "acct_all")) {
            ctrl |= PAM_TAC_ACCT;
        } else if (!strncmp (*argv, "server=", 7)) { /* authen & acct */
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) { 
                struct addrinfo hints, *servers, *server;
                int rv;
                char *port, server_buf[256];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                if (strlen(*argv + 7) >= sizeof(server_buf)) {
                    _pam_log(LOG_ERR, "server address too long, sorry");
                    continue;
                }
                strcpy(server_buf, *argv + 7);

                port = strchr(server_buf, ':');
                if (port != NULL) {
                    *port = '\0';
					port++;
                }
                if ((rv = getaddrinfo(server_buf, (port == NULL) ? "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL && tac_srv_no < TAC_PLUS_MAXSERVERS; server = server->ai_next) {
                        tac_srv[tac_srv_no] = server;
                        tac_srv_no++;
                    }
                } else {
                    _pam_log (LOG_ERR,
                        "skip invalid server: %s (getaddrinfo: %s)",
                        server_buf, gai_strerror(rv));
                }
            } else {
                _pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
                    TAC_PLUS_MAXSERVERS);
            }
        } else if (!strncmp (*argv, "secret=", 7)) {
            if(tac_srv_key_no < TAC_PLUS_MAXSERVERS) {
                tac_srv_key[tac_srv_key_no] = (char *) _xcalloc (strlen (*argv + 7) + 1);
                strcpy (tac_srv_key[tac_srv_key_no], *argv + 7);
                tac_srv_key_no++;
            } else {
                _pam_log(LOG_ERR, "maximum number of secrets (%d) exceeded, skipping",
                    TAC_PLUS_MAXSERVERS);
            }
        } else if (!strncmp (*argv, "timeout=", 8)) {
            tac_timeout = atoi(*argv + 8);
        } else if (!strncmp (*argv, "login=", 6)) {
            tac_login = (char *) _xcalloc (strlen (*argv + 6) + 1);
            strcpy (tac_login, *argv + 6);
        } else {
            _pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
        }
    }

    if (tac_srv_key_no == 0) {
        /* FIXME this should really be NULL
           but watch out with breaking other code
        */
        tac_srv_key[0] = "";
        tac_srv_key_no++;
    }
    for (;tac_srv_key_no < tac_srv_no;tac_srv_key_no++) {
        tac_srv_key[tac_srv_key_no] = tac_srv_key[0];
    }

    return ctrl;
}    /* _pam_parse */

