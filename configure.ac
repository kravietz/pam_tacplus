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

AC_PREREQ([2.69])
AC_COPYRIGHT([
See the included file: LICENSE for copyright information.
])
AC_INIT([pam_tacplus],[1.7.0],[https://github.com/kravietz/pam_tacplus/issues/],[pam_tacplus],[https://github.com/kravietz/pam_tacplus/])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([pam_tacplus.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([config])
AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_PROG([GNULIB], [gnulib-tool], [gnulib-tool], [
Gnulib is required to compile this program. On Ubuntu Focal you can run "apt install gnulib", but
most other systems will ship a very old version so you fetch it from GNU repository:

git clone https://git.savannah.gnu.org/git/gnulib.git \$HOME/gnulib
export PATH=\$PATH:\$HOME/gnulib

])

if ! test -f "lib/malloc.c"; then
AC_MSG_ERROR([
lib/malloc.c not found!
Gnulib files not imported. Run:

$ac_cv_prog_GNULIB --makefile-name=Makefile.gnulib --libtool --import \
fcntl crypto/md5 array-list list xlist getrandom realloc-posix \
explicit_bzero xalloc getopt-gnu

])
fi

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
gl_EARLY
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR
AC_C_RESTRICT
LT_INIT([disable-static])

dnl Gnulib
gl_INIT
gl_MD5
gl_FUNC_EXPLICIT_BZERO
if test $HAVE_EXPLICIT_BZERO = 0; then
  AC_LIBOBJ([explicit_bzero])
  gl_PREREQ_EXPLICIT_BZERO
fi
gl_STRING_MODULE_INDICATOR([explicit_bzero])
gl_XALLOC
gl_MODULE_INDICATOR([xalloc])

dnl --------------------------------------------------------------------
dnl Checks for libraries.

AC_CHECK_LIB(pam, pam_start)
AC_CHECK_LIB(tac, tac_connect)
AC_CHECK_LIB(c, pututxline,
	     [AC_DEFINE([HAVE_PUTUTXLINE], [1], [Define to 1 if you have the `pututxline' function.])],
	     [AC_CHECK_LIB(util, logwtmp)])

case "$host" in
	sparc-* | sparc64-*)
		LIBS="$LIBS -lresolv";;
esac

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h limits.h])
AC_CHECK_HEADERS([syslog.h unistd.h sys/random.h])
AC_CHECK_HEADER(security/pam_appl.h, [], [AC_MSG_ERROR([PAM libraries missing. Install with "yum install pam-devel" or "apt-get install libpam-dev".])] )
AM_CONDITIONAL(TACC, [true])

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

AC_ARG_ENABLE(am-ldcflags, AS_HELP_STRING([--disable-am-ldcflags], [do not add various 'AM_CFLAGS/AM_LDFLAGS']))
if test "x$enable_am_ldcflags" != "xno"; then
	# Compiler flags
	my_save_cflags="$CFLAGS"
    for flag in -fstack-protector-all -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2; do
		CFLAGS=$flag
		AC_MSG_CHECKING([whether CC compiler supports $flag])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
			[AC_MSG_RESULT([yes])]
			[new_CFLAGS="$new_CFLAGS $flag"],
			[AC_MSG_RESULT([no])]
		)
    done
	CFLAGS="$my_save_cflags $new_CFLAGS"

	# Linker flags
	my_save_cflags="$LDFLAGS"
	for flag in -Wl,-z,relro -Wl,-z,now -pie; do	
		LDFLAGS=$flag
		AC_MSG_CHECKING([whether CC linker supports $flag])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
			[AC_MSG_RESULT([yes])]
			[new_LDFLAGS="$new_LDFLAGS $flag"],
			[AC_MSG_RESULT([no])]
		)
    done
	LDFLAGS="$my_save_cflags $new_LDFLAGS"
fi

AC_ARG_ENABLE(asan,
	[AS_HELP_STRING([--enable-asan],[enable gcc asan])],
        asan=$enableval, asan=no)

AC_MSG_CHECKING(whether to use gcc sanitizer)
if test "x$enable_asan" == "xyes"; then
	AC_MSG_RESULT(yes)
	my_save_cflags="$CFLAGS"
	for flag in -fsanitize=address -fsanitize=undefined -fsanitize=leak \
	    -fsanitize-address-use-after-scope -fcf-protection=full -fno-omit-frame-pointer -fno-common; do
		CFLAGS=$flag
		AC_MSG_CHECKING([whether CC supports $flag])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
			[AC_MSG_RESULT([yes])]
			[new_CFLAGS="$new_CFLAGS $flag"],
			[AC_MSG_RESULT([no])]
		)
    done
	LDFLAGS="$LDFLAGS $new_CFLAGS"
	dnl Disable optimizations when running ASAN
	CFLAGS="$my_save_cflags -O0 -ggdb $new_CFLAGS"
else
	AC_MSG_RESULT(no)
fi

dnl --------------------------------------------------------------------
dnl Checks for library functions.
dnl AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa select socket logwtmp strtol abort])

dnl --------------------------------------------------------------------
dnl Switch for pam module dir
AC_ARG_ENABLE([pamdir], [AS_HELP_STRING([--enable-pamdir],
              [Location to install the pam module ($libdir/security)])],
              [pamdir=$enableval], [pamdir=$libdir/security])
AC_SUBST(pamdir)

AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [do not build docs]))
AM_CONDITIONAL(DOC, test "x$enable_doc" != "xno")

AC_ARG_ENABLE(werror, AS_HELP_STRING([--disable-werror], [do not build with -Werror]))
AM_CONDITIONAL(ENABLE_WERROR, test "x$enable_werror" != "xno")

dnl --------------------------------------------------------------------
dnl Switch for run-time debugging
AC_ARG_ENABLE(runtime-debugging, [AS_HELP_STRING([--enable-runtime-debugging],
	      [Build with run-time debugging])],
	      [rt_debug_defines="-DTACDEBUG_AT_RUNTIME=1"])
AC_SUBST(rt_debug_defines)
AM_SUBST_NOTMAKE(rt_debug_defines)

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile lib/Makefile libtac.pc pam_tacplus.spec])
AC_OUTPUT
