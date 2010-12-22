dnl
dnl File:        configure.in
dnl Revision:    $Id: configure.ac,v 1.4 2010/06/11 12:04:29 j-nijhof Exp $
dnl Created:     2010/06/09
dnl Author:      Jeroen Nijhof <jeroen@nijhofnet.nl>
dnl              Benoit Donneaux <benoit.donneaux@gmail.com>
dnl
dnl Process this file with autoconf to produce a configure script
dnl You need autoconf 2.59 or better!
dnl
dnl ---------------------------------------------------------------------------

AC_PREREQ(2.59)
AC_COPYRIGHT([
See the included file: COPYING for copyright information.
])
AC_INIT(pam_tacplus, 1.3.2, [jeroen@nijhofnet.nl,kravietz@ceti.com.pl])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([pam_tacplus.c])
AC_CONFIG_HEADER([config.h])

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

dnl --------------------------------------------------------------------
dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_start)
AC_CHECK_LIB(tac, tac_connect)

case "$host" in
	sparc-* | sparc64-*)
		LIBS="$LIBS -lresolv";;
esac

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h])

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa select socket])

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile
                 pam_tacplus.spec])
AC_OUTPUT
