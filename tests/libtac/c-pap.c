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
    char pass[] = "testpass123";
    char tty[] = "ttyS0";
    char remote_addr[] = "1.1.1.1";

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
    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    is_bool(tac_fd > 0, true, "tac_connect_single");
    if (tac_fd <= 0) {
        sysbail("tac_connect_single\n");
    }
    ret = tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN);
    is_int(ret, 0, "tac_authen_send PAP");

    memset(&arep, 0, sizeof(arep));
    ret = tac_authen_read(tac_fd, &arep);
    is_int(ret, TAC_PLUS_AUTHEN_STATUS_PASS, "tac_authen_read PAP");

    if (arep.msg != NULL)
        free(arep.msg);

    // with incorrect login credentials
    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    is_bool(tac_fd > 0, true, "tac_connect_single");
    if (tac_fd <= 0) {
        sysbail("tac_connect_single\n");
    }
    ret = tac_authen_send(tac_fd, user, "incorrect password", tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN);
    is_int(ret, 0, "tac_authen_send PAP");

    memset(&arep, 0, sizeof(arep));
    ret = tac_authen_read(tac_fd, &arep);
    is_int(ret, TAC_PLUS_AUTHEN_STATUS_FAIL, "tac_authen_read PAP bad password");

    if (arep.msg != NULL)
        free(arep.msg);

    // with incorrect TACACS+ key
    tac_secret = "badkey";
    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    is_bool(tac_fd > 0, true, "tac_connect_single");
    if (tac_fd <= 0) {
        sysbail("tac_connect_single\n");
    }
    ret = tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN);
    is_int(ret, 0, "tac_authen_send PAP");

    memset(&arep, 0, sizeof(arep));
    ret = tac_authen_read(tac_fd, &arep);
    is_int(ret, LIBTAC_STATUS_PROTOCOL_ERR, "tac_authen_read PAP bad key");

    if (arep.msg != NULL)
        free(arep.msg);
    freeaddrinfo(tac_server);
}
