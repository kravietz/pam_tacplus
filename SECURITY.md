# Security Policy

## Security assumptions

`pam_tacplus` and `libtac` are both used with privileges of the calling user and process the following
external data:

* user data - login and password strings, which are considered untrusted and are subject to security
  validation
* configuration data - parameters set in PAM configuration file in `/etc/pam.d` such as server address
  or secret, which are considered trusted and are subject to basic semantic validation

Code in `tests` is _not_ assumed to perform any security validation.

## Supported Versions

All versions of `pam_tacplus` and `libtac` are supported.

## Reporting a Vulnerability

For low and medium level vulnerabilities please [create an issue](https://github.com/kravietz/pam_tacplus/issues/new)
or [pull request](https://github.com/kravietz/pam_tacplus/pulls) with fixes.

For high severity issues please [contact Paweł Krawczyk](https://krvtz.net/pages/contact.html),
numerous secure means of communication are supported.
