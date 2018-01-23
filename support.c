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
#define PAM_SM_PASSWORD

#include "support.h"
#include "pam_tacplus.h"

#include <stdlib.h>
#include <string.h>

tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
int tac_srv_no = 0;

char tac_service[64];
char tac_protocol[64];
char tac_prompt[64];
struct addrinfo tac_srv_addr[TAC_PLUS_MAXSERVERS];
struct sockaddr tac_sock_addr[TAC_PLUS_MAXSERVERS];
char tac_srv_key[TAC_PLUS_MAXSERVERS][TAC_SECRET_MAX_LEN+1];

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
int tacacs_get_password (pam_handle_t * pamh, int flags __Unused,
    int ctrl, char **password) {

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

         if (!tac_prompt[0]) {
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

void tac_copy_addr_info (struct addrinfo *p_dst, const struct addrinfo *p_src)
{
    if (p_dst && p_src) {
        p_dst->ai_flags = p_src->ai_flags;
        p_dst->ai_family = p_src->ai_family;
        p_dst->ai_socktype = p_src->ai_socktype;
        p_dst->ai_protocol = p_src->ai_protocol;
        p_dst->ai_addrlen = p_src->ai_addrlen;
        memcpy (p_dst->ai_addr, p_src->ai_addr, sizeof(struct sockaddr));
        p_dst->ai_canonname = NULL; /* we do not care it */
        p_dst->ai_next = NULL;      /* no more chain */
    }
}

static void set_tac_srv_addr (unsigned int srv_no, const struct addrinfo *addr)
{
    if (srv_no < TAC_PLUS_MAXSERVERS) {
        if (addr) {
            tac_srv_addr[srv_no].ai_addr = &tac_sock_addr[srv_no];
            tac_copy_addr_info (&tac_srv_addr[srv_no], addr);
            tac_srv[srv_no].addr = &tac_srv_addr[srv_no];
        }
        else {
            tac_srv[srv_no].addr = NULL;
        }
    }
}

static void set_tac_srv_key (unsigned int srv_no, const char *key)
{
    if (srv_no < TAC_PLUS_MAXSERVERS) {
        if (key) {
            strncpy (tac_srv_key[srv_no], key, TAC_SECRET_MAX_LEN-1);
            tac_srv[srv_no].key = tac_srv_key[srv_no];
        }
        else {
            tac_srv[srv_no].key = NULL;
        }
    }
}

int _pam_parse (int argc, const char **argv) {
    int ctrl = 0;
    const char *current_secret = NULL;

    /* otherwise the list will grow with each call */
    memset(tac_srv, 0, sizeof(tacplus_server_t) * TAC_PLUS_MAXSERVERS);
    tac_srv_no = 0;

    tac_service[0] = 0;
    tac_protocol[0] = 0;
    tac_prompt[0] = 0;
    tac_login[0] = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        if (!strcmp (*argv, "debug")) { /* all */
            ctrl |= PAM_TAC_DEBUG;
        } else if (!strcmp (*argv, "use_first_pass")) {
            ctrl |= PAM_TAC_USE_FIRST_PASS;
        } else if (!strcmp (*argv, "try_first_pass")) { 
            ctrl |= PAM_TAC_TRY_FIRST_PASS;
        } else if (!strncmp (*argv, "service=", 8)) { /* author & acct */
            xstrcpy (tac_service, *argv + 8, sizeof(tac_service));
        } else if (!strncmp (*argv, "protocol=", 9)) { /* author & acct */
            xstrcpy (tac_protocol, *argv + 9, sizeof(tac_protocol));
        } else if (!strncmp (*argv, "prompt=", 7)) { /* authentication */
            xstrcpy (tac_prompt, *argv + 7, sizeof(tac_prompt));
            /* Replace _ with space */
            unsigned chr;
            for (chr = 0; chr < strlen(tac_prompt); chr++) {
                if (tac_prompt[chr] == '_') {
                    tac_prompt[chr] = ' ';
                }
            }
        } else if (!strncmp (*argv, "login=", 6)) {
            xstrcpy (tac_login, *argv + 6, sizeof(tac_login));
        } else if (!strcmp (*argv, "acct_all")) {
            ctrl |= PAM_TAC_ACCT;
        } else if (!strncmp (*argv, "server=", 7)) { /* authen & acct */
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) { 
                struct addrinfo hints, *servers, *server;
                int rv;
                char *close_bracket, *server_name, *port, server_buf[256];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                if (strlen(*argv + 7) >= sizeof(server_buf)) {
                    _pam_log(LOG_ERR, "server address too long, sorry");
                    continue;
                }
                strcpy(server_buf, *argv + 7);

                if (*server_buf == '[' && (close_bracket = strchr(server_buf, ']')) != NULL) { /* Check for URI syntax */
                    server_name = server_buf + 1;
                    port = strchr(close_bracket, ':');
                    *close_bracket = '\0';
                } else { /* Fall back to traditional syntax */
                    server_name = server_buf;
                    port = strchr(server_buf, ':');
                }
                if (port != NULL) {
                    *port = '\0';
                    port++;
                }
                if ((rv = getaddrinfo(server_name, (port == NULL) ? "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL && tac_srv_no < TAC_PLUS_MAXSERVERS; server = server->ai_next) {
                        set_tac_srv_addr (tac_srv_no, server);
                        set_tac_srv_key (tac_srv_no, current_secret);
                        tac_srv_no++;
                    }
                    freeaddrinfo (servers);
                } else {
                    _pam_log (LOG_ERR,
                        "skip invalid server: %s (getaddrinfo: %s)",
                        server_name, gai_strerror(rv));
                }
            } else {
                _pam_log(LOG_ERR, "maximum number of servers (%d) exceeded, skipping",
                    TAC_PLUS_MAXSERVERS);
            }
        } else if (!strncmp (*argv, "secret=", 7)) {
            int i;

            current_secret = *argv + 7;     /* points right into argv (which is const) */

            /* if 'secret=' was given after a 'server=' parameter, fill in the current secret */
            for(i = tac_srv_no-1; i >= 0; i--) {
                if (tac_srv[i].key != NULL)
                    break;

                set_tac_srv_key (i, current_secret);
            }
        } else if (!strncmp (*argv, "timeout=", 8)) {
            /* FIXME atoi() doesn't handle invalid numeric strings well */
            tac_timeout = atoi(*argv + 8);

            if (tac_timeout < 0) {
                tac_timeout = 0;
            } else { 
                tac_readtimeout_enable = 1;
            }
        } else {
            _pam_log (LOG_WARNING, "unrecognized option: %s", *argv);
        }
    }

    if (ctrl & PAM_TAC_DEBUG) {
        int n;

        _pam_log(LOG_DEBUG, "%d servers defined", tac_srv_no);

        for(n = 0; n < tac_srv_no; n++) {
            _pam_log(LOG_DEBUG, "server[%d] { addr=%s, key='%s' }", n, tac_ntop(tac_srv[n].addr->ai_addr), tac_srv[n].key);
        }

        _pam_log(LOG_DEBUG, "tac_service='%s'", tac_service);
        _pam_log(LOG_DEBUG, "tac_protocol='%s'", tac_protocol);
        _pam_log(LOG_DEBUG, "tac_prompt='%s'", tac_prompt);
        _pam_log(LOG_DEBUG, "tac_login='%s'", tac_login);
    }

    return ctrl;
}    /* _pam_parse */

