#!/bin/bash

# This test script is expected to run in Multipass or Docker image
# under test environment as run by Travis CI for example - it depends
# on installing packages, adding users and sudo

set -exo pipefail

# preserve PATH to clang
sudo -E PATH="${PATH}" make install

sudo tee /etc/tacacs+/tac_plus.conf <<_EOT
accounting file = /var/log/tac_plus.acct

key = testkey123

user = testuser1 {
        global = cleartext "testpass123"
        service = ppp protocol = ip {
                addr=1.2.3.4
        }
}
user = testuser2 {
        global = cleartext "testpass123"
        service = ppp protocol = ip {
                addr=2.3.4.5
        }
}
_EOT

sudo tee /etc/pam.d/test <<_EOT
auth       required     /lib/security/pam_tacplus.so debug server=127.0.0.1 secret=testkey123
account    required     /lib/security/pam_tacplus.so debug server=127.0.0.1 secret=testkey123 service=ppp protocol=ip
password   required     /lib/security/pam_tacplus.so debug server=127.0.0.1 secret=testkey123
session    required     /lib/security/pam_tacplus.so debug server=127.0.0.1 secret=testkey123 server=127.0.0.2 secret=testkey123 service=ppp protocol=ip
_EOT

sudo service tacacs_plus restart

/usr/local/bin/tacc --authenticate --authorize --account --username testuser1 \
    --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 \
    --secret testkey123 --service ppp --protocol ip --login pap

/usr/local/bin/tacc --authenticate --authorize --account --username testuser1 \
    --password badpass --server localhost --remote 5.6.7.8 --tty ttyS0 \
    --secret testkey123 --service ppp --protocol ip --login pap && false

/usr/local/bin/tacc --authenticate --authorize --account --username testuser1 \
    --password testpass123 --server localhost --remote 5.6.7.8 --tty ttyS0 \
    --secret badkey --service ppp --protocol ip --login pap && false

sudo tail -20 /var/log/syslog
sudo tail -20 /var/log/auth.log

ls -l /lib/security/pam_tacplus.so

sudo expect <<_EOT || true
set timeout -1
spawn pamtester -v -I rhost=localhost test testuser1 authenticate acct_mgmt open_session close_session
match_max 100000
expect -exact "pamtester: invoking pam_start(test, testuser1, ...)\r
pamtester: performing operation - authenticate\r
Password: "
send -- "testpass123\r"
expect "pamtester: successfully authenticated\r"
expect eof
_EOT

sudo tail -20 /var/log/syslog
sudo tail -20 /var/log/auth.log

expect <<_EOT
set timeout -1
spawn pamtester -v -I rhost=localhost test testuserX authenticate acct_mgmt open_session close_session
match_max 100000
expect -exact "pamtester: invoking pam_start(test, testuserX, ...)\r
pamtester: performing operation - authenticate\r
Password: "
send -- "badpass\r"
expect "pamtester: Authentication failure\r"
expect eof
_EOT


