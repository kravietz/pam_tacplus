[![Analysis Status](https://scan.coverity.com/projects/5499/badge.svg)](https://scan.coverity.com/projects/5499)

# pam_tacplus

This PAM module support the following functions:

* authentication
* authorization (account management)
* accounting (session management)

All are performed using TACACS+ protocol [1], designed by Cisco Systems.
This is remote AAA protocol, supported by most Cisco hardware. 
A free TACACS+ server is available [2], which I'm using without any
major problems for about a year. Advantages of TACACS+ is that all
(unlike RADIUS) packets exchanged with the authentication server are
encrypted. This module is an attempt to provide most useful part of
TACACS+ functionality to applications using the PAM interface on Linux.


### Recognized options:

| Option             | Management group | Description |
|------------------- | ---------------- | ----------- |
| debug | ALL | output debugging information via syslog(3); note, that the debugging is heavy, including passwords! |
| secret=STRING | ALL | can be specified more than once; secret key used to encrypt/decrypt packets sent/received from the server |
| server=HOSTNAME server=IP_ADDR server=HOSTNAME:PORT server=IP_ADDR:PORT | auth, session | can be specified more than once; adds a TACACS+ server to the servers list |
| timeout=INT | ALL | connection timeout in seconds default is 5 seconds |
| login=STRING | auth | TACACS+ authentication service, this can be "pap", "chap" or "login" at the moment. Default is pap. |
| prompt=STRING | auth | Custom password prompt. If you want to use a space use '_' character instead. |
| acct_all | session | if multiple servers are supplied, pam_tacplus will send accounting start/stop packets to all servers on the list |
| service | account, session | TACACS+ service for authorization and accounting |
| protocol | account, session | TACACS+ protocol for authorization and accounting |

The last two items are widely described in TACACS+ draft [1]. They are
required by the server, but it will work if they don't match the real
service authorized :)
During PAM account the AV pairs returned by the TACACS+ servers are made available to the
PAM environment, so you can use i.e. pam_exec.so to do something with these AV pairs.

### Basic installation:
This project is using autotools for building, so please run autoreconf first.
```
$ autoreconf -i
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
	  pam_tacplus will try to authenticate the user against the other
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
	  on the list will fail to accept our accounting packets

	* with `acct_all' pam_tacplus will try to deliver the accounting
	  packets to all servers on the list; failure of one of the servers
	  will make it try another one

	  this is useful when your have several accounting, billing or
	  logging hosts and want to have the accounting information appear
	  on all of them at the same time


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
2. Login calls PAM function pam_authenticate() to verify if the
   supplied username/password pair is valid.
3. PAM loads pam_tacplus module (as defined in /etc/pam.d/login)
   and calls pam_sm_authenticate() function supplied by this module.
4. This function sends an encrypted packet to the TACACS+ server.
   The packet contains username and password to verify. TACACS+ server
   replied with either positive or negative response. If the reponse
   is negative, the whole thing is over ;)
5. PAM calls another function from pam_tacplus - pam_sm_acct_mgmt().
   This function is expected to verify whether the user is allowed
   to get the service he's requesting (in this case: unix shell).
   The function again verifies the permission on TACACS+ server. Assume
   the server granted the user with requested service.
6. Before user gets the shell, PAM calls one another function from
   pam_tacplus - pam_sm_open_session(). This results in sending an
   accounting START packet to the server. Among other things it contains
   the terminal user loggen in on and the time session started.
7. When user logs out, pam_sm_close_session() sends STOP packet to the
   server. The whole session is closed.

### Limitations:

Many of them for now :)

* only subset of TACACS+ protocol is supported; it's enough for most need, though
* utilize PAM_SERVICE item obtained from PAM for TACACS+ services
* clean options and configuration code
		
### Authors:

Pawel Krawczyk <pawel.krawczyk@hush.com>
http://ipsec.pl

Jeroen Nijhof <jeroen@jeroennijhof.nl>
