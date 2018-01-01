dnl
dnl File:        configure.in
dnl Revision:    $Id: configure.ac,v 1.4 2010/06/11 12:04:29 j-nijhof Exp $
dnl Created:     2010/06/09
dnl Author:      Jeroen Nijhof <jeroen@jeroennijhof.nl>
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
AC_INIT(pam_tacplus, 1.4.1, [jeroen@jeroennijhof.nl,pawel.krawczyk@hush.com])

AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([pam_tacplus.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([config])

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT([disable-static])
AM_PROG_CC_C_O

dnl --------------------------------------------------------------------
dnl Checks for libraries.
AC_CHECK_LIB(pam, pam_start)
AC_CHECK_LIB(tac, tac_connect)
AC_CHECK_LIB(crypto, MD5_Init)
AC_CHECK_LIB(crypto, RAND_pseudo_bytes,
            [AC_DEFINE([HAVE_RAND_PSEUDO_BYTES], [1], [Define to 1 if you have the `RAND_pseudo_bytes' function.])])
AC_CHECK_LIB(crypto, RAND_bytes,
             [AC_DEFINE([HAVE_RAND_BYTES], [1], [Define to 1 if you have the `RAND_bytes' function.])])
AC_CHECK_LIB(c, pututxline,
	     [AC_DEFINE([HAVE_PUTUTXLINE], [1], [Define to 1 if you have the `pututxline' function.])],
	     [AC_CHECK_LIB(util, logwtmp)])

case "$host" in
	sparc-* | sparc64-*)
		LIBS="$LIBS -lresolv";;
esac

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h])
AC_CHECK_HEADERS([syslog.h unistd.h openssl/md5.h openssl/rand.h sys/random.h])
AC_CHECK_HEADER(security/pam_appl.h, [], [AC_MSG_ERROR([PAM libraries missing. Install with "yum install pam-devel" or "apt-get install libpam-dev".])] )
AM_CONDITIONAL(MY_MD5, [test "$ac_cv_header_openssl_md5_h" = "no" ])
AM_CONDITIONAL(TACC, [test "$ac_cv_lib_crypto_RAND_bytes" = "yes" || test "$ac_cv_lib_crypto_RAND_pseudo_bytes" = "yes"])

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_ARG_ENABLE(am-ldcflags, AS_HELP_STRING([--disable-am-ldcflags], [do not add various 'AM_CFLAGS/AM_LDFLAGS']))
if test "x$enable_am_ldcflags" != "xno"; then
   for flag in -fstack-protector-all -Wl,-z,relro -Wl,-z,now -fPIE -pie -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2; do
	my_save_cflags="$CFLAGS"
	CFLAGS=$flag
	AC_MSG_CHECKING([whether CC supports $flag])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	    [AC_MSG_RESULT([yes])]
	    [AM_CFLAGS="$AM_CFLAGS $flag"]
	    [AC_MSG_RESULT([no])]
	)
	CFLAGS="$my_save_cflags"
    done
    AC_SUBST([AM_CFLAGS])
    AC_SUBST([AM_LDFLAGS])
fi

dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa select socket logwtmp getrandom])

dnl --------------------------------------------------------------------
dnl Switch for pam module dir
AC_ARG_ENABLE([pamdir], [AS_HELP_STRING([--enable-pamdir],
              [Location to install the pam module ($libdir/security)])],
              [pamdir=$enableval], [pamdir=$libdir/security])
AC_SUBST(pamdir)

AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [do not build docs]))
AM_CONDITIONAL(DOC, test "x$enable_doc" != "xno")

dnl --------------------------------------------------------------------
dnl Switch for run-time debugging
AC_ARG_ENABLE(runtime-debugging, [AS_HELP_STRING([--enable-runtime-debugging],
	      [Build with run-time debugging])],
	      [rt_debug_defines="-DTACDEBUG_AT_RUNTIME=1"])
AC_SUBST(rt_debug_defines)
AM_SUBST_NOTMAKE(rt_debug_defines)

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile
		 libtac.pc
                 pam_tacplus.spec])
AC_OUTPUT
