//
// Created by pawelkrawczyk on 21/10/2021.
//

#include "libtac.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

#include <tests/tap/basic.h>

int main() {

    int tac_fd = 0;
    int ret;
    struct areply arep;
    char *server_name;
    char user[] = "testuser1";
    char tty[] = "ttyS0";
    char remote_addr[] = "1.1.1.1";
    gl_list_t send_attr;
    struct addrinfo hints;
    struct addrinfo *tac_server;

    tac_secret = "testkey123";

    server_name = getenv("TACPLUS_SERVER");
    if (server_name == NULL)
        server_name = "localhost";

    plan_lazy();

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ret = getaddrinfo(server_name, "tacacs", &hints, &tac_server);
    is_bool(ret == 0, true, "getaddrinfo");
    if (ret != 0) {
        sysbail("getaddrinfo");
    }

    memset(&arep, 0, sizeof(arep));
    arep.attr = gl_list_create_empty(GL_ARRAY_LIST, NULL, NULL, NULL, false);
    send_attr = gl_list_create_empty(GL_ARRAY_LIST, NULL, NULL, NULL, false);
    tac_add_attrib(send_attr, "start_time", "2021-10-31T20:10:21+00:00");
    tac_add_attrib(send_attr, "task_id", "1234567890");

    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    is_bool(tac_fd > 0, true, "tac_connect_single");
    if (tac_fd <= 0) {
        sysbail("tac_connect_single\n");
    }
    ret = tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, tty, remote_addr, send_attr);
    is_int(ret, 0, "tac_acct_send");

    ret = tac_acct_read(tac_fd, &arep);
    is_int(ret, TAC_PLUS_ACCT_STATUS_SUCCESS, "tac_acct_read");
    is_int(arep.status, TAC_PLUS_ACCT_STATUS_SUCCESS, "tac_acct_read");
    tac_free_attrib(arep.attr);

    tac_free_attrib(send_attr);
    if (arep.msg != NULL)
        free(arep.msg);
    freeaddrinfo(tac_server);
}
