[![Build Status](https://travis-ci.org/jeroennijhof/pam_tacplus.svg?branch=master)](https://travis-ci.org/jeroennijhof/pam_tacplus)
[![Analysis Status](https://scan.coverity.com/projects/5499/badge.svg)](https://scan.coverity.com/projects/5499)
[![GitHub forks](https://img.shields.io/github/forks/jeroennijhof/pam_tacplus.svg)](https://github.com/jeroennijhof/pam_tacplus/network)
[![GitHub license](https://img.shields.io/badge/license-GPLv2-blue.svg)](https://raw.githubusercontent.com/jeroennijhof/pam_tacplus/master/COPYING)

# TACACS+ client toolkit

This repository contains three modules that are typically used to perform requests to a TACACS+ server:

* `libtac` - core TACACS+ client library
* `pam_tacplus` - [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) module for authenticating users against TACACS+
* `tacc` - a simple command-line TACACS+ client

The following core TACACS+ functions are supported:

* authentication
* authorization (account management)
* accounting (session management)

The [TACACS+](https://tools.ietf.org/html/draft-grant-tacacs-02) protocol was designed by Cisco Systems back in 90's and was intended to provide simple means of validating users connecting to simple network routers (e.g. over PPP) against a central authentication server. The router can send queries about authentication (validate user credentials), authorization (entitlement for requested service) and accounting (marking the start and end of user's session). The server can respond with either simple yes/no response, or send back attributes, such as text of a password prompt, effectively instructing the router to present it to the user and send back the obtained password.

Unlike RADIUS, which was designed for similar purposes, the TACACS+ protocol offers basic packet encryption but, as with most crypto designed back then, it's [not secure](http://www.openwall.com/articles/TACACS+-Protocol-Security) and definitely should not be used over untrusted networks.

This package has been successfully used with free [tac_plus](http://www.shrubbery.net/tac_plus/) TACACS+ server on variety of operating systems.

### Recognized options:

| Option             | Management group | Description |
|------------------- | ---------------- | ----------- |
| `debug` | ALL | output debugging information via syslog(3); note, that the debugging is heavy, including passwords! |
| `secret` | ALL | *string* can be specified more than once; secret key used to encrypt/decrypt packets sent/received from the server |
| `server` | auth, session | *string* hostname, IP or hostname:port, can be specified more than once |
| `timeout` | ALL | *integer* connection timeout in seconds; default is 5 seconds |
| `login` | auth | TACACS+ authentication service, this can be *pap*, *chap* or *login*; default is *pap* |
| `prompt` | auth | *string* custom password prompt; use `_` instead of spaces  |
| `acct_all` | session | if multiple servers are supplied, pam\_tacplus will send accounting start/stop packets to all servers on the list |
| `service` | account, session | *string* TACACS+ service for authorization and accounting |
| `protocol` | account, session | *string* TACACS+ protocol for authorization and accounting |

Semantics of these options only makes sense in the context of the [TACACS+](https://tools.ietf.org/html/draft-grant-tacacs-02) specification - for example, a dial-up router might request *ppp* service with protocol *ip* for their users, authenticating them with *pap* protocol which reflects the typical usage of TACACS+ back in 90's. These values however do not really need to match the actual service offered by your server as the TACACS+ server only cares about the service and protocol fields matching what it has in its configuration.

### Basic installation:
The code uses standard GNU autotools:
```
$ ./auto.sh
$ ./configure && make && sudo make install
```
### Example configuration:
```
#%PAM-1.0
auth       required     /lib/security/pam_tacplus.so debug server=1.1.1.1 secret=SECRET-1
account	   required	/lib/security/pam_tacplus.so debug secret=SECRET-1 service=ppp protocol=lcp
account    sufficient	/lib/security/pam_exec.so /usr/local/bin/showenv.sh
password   required	/lib/security/pam_cracklib.so
password   required	/lib/security/pam_pwdb.so shadow use_authtok
session    required	/lib/security/pam_tacplus.so debug server=1.1.1.1 server=2.2.2.2 secret=SECRET-1 secret=SECRET-2 service=ppp protocol=lcp
```

### More on server lists:

1. Having more that one TACACS+ server defined for given management group
has following effects on authentication:

 	* if the first server on the list is unreachable or failing
	  pam\_tacplus will try to authenticate the user against the other
	  servers until it succeeds

	* the `first_hit' option has been deprecated

	* when the authentication function gets a positive reply from
	  a server, it saves its address for future use by account
	  management function (see below)

2. The account management (authorization) function asks *only one*
TACACS+ server and it ignores the whole server list passed from command
line. It uses server saved by authentication function after successful
authenticating user on that server. We assume that the server is
authoriative for queries about that user.

3. The session management (accounting) functions obtain their server lists
independently from the other functions. This allows you to account user
sessions on different servers than those used for authentication and
authorization.

	* normally, without the `acct_all' modifier, the extra servers
	  on the list will be considered as backup servers, mostly like
	  in point 1. i.e. they will be used only if the first server
	  on the list will fail to accept our accounting packets.

	* with `acct_all' pam_tacplus will try to deliver the accounting
	  packets to all servers on the list; failure of one of the servers
	  will make it try another one. This is useful when your have several accounting, billing or
	  logging hosts and want to have the accounting information appear
	  on all of them at the same time.


### Short introduction to PAM via TACACS+:

This diagram should show general idea of how the whole process looks:

```
                                              +-----+
          Authen -user/pass valid?----------> | T S |
        /                                     | A e |
     PAM- Author -service allowed?----------> | C r |
      ^ \                                     | A v |
      |   Acct ,-----start session----------> | C e |
      |         `----stop session-----------> | S r |
  Application                                 +-----+

  *Client Host*          *Network*           *Server Host*
```

Consider `login' application:

1. Login accepts username and password from the user.
2. Login calls PAM function pam\_authenticate() to verify if the
   supplied username/password pair is valid.
3. PAM loads pam\_tacplus module (as defined in /etc/pam.d/login)
   and calls pam\_sm\_authenticate() function supplied by this module.
4. This function sends an encrypted packet to the TACACS+ server.
   The packet contains username and password to verify. TACACS+ server
   replied with either positive or negative response. If the reponse
   is negative, the whole thing is over
5. PAM calls another function from pam\_tacplus - pam\_sm\_acct\_mgmt().
   This function is expected to verify whether the user is allowed
   to get the service he's requesting (in this case: unix shell).
   The function again verifies the permission on TACACS+ server. Assume
   the server granted the user with requested service.
6. Before user gets the shell, PAM calls one another function from
   pam\_tacplus - pam\_sm\_open\_session(). This results in sending an
   accounting START packet to the server. Among other things it contains
   the terminal user loggen in on and the time session started.
7. When user logs out, pam\_sm\_close\_session() sends STOP packet to the
   server. The whole session is closed.

### TACACS+ client program
The library comes with a simple TACACS+ client program `tacc` which can be used for testing as well as simple scripting. Sample usage:

```
tacc --authenticate --authorize --account --username user1
    --password pass1 --server localhost --remote 1.1.1.1
    --secret enckey1 --service ppp --protocol ip --login pap
```
This configuration runs full AAA round (authentication, authorization and accounting). The `server` and `secret` option specify server connection parameters and all remaining options supply data specific to TACACS+ protocol. The `tac_plus` daemon (found in `tacacs+` package in Debian and Ubuntu) can be used for testing with the following example configuration:
```
key = enckey1
user = user1 {
    global = cleartext "pass1"
    service = ppp protocol = ip {
            addr=8.8.8.8
    }
}
```

For debugging run the `tac_plus` server with the following options - the `-d 512` will debug encryption, for other values see `man 8 tac_plus`:

```
tac_plus -C /etc/tacacs+/tac_plus.conf -G -g -d 512
```

### Limitations:

* only subset of TACACS+ protocol is supported; it's enough for most need, though
* `tacc` does not support password prompts and other interactive protocol features
		
### Authors:

Pawel Krawczyk <pawel.krawczyk@hush.com>
https://ipsec.pl/

Jeroen Nijhof <jeroen@jeroennijhof.nl>
