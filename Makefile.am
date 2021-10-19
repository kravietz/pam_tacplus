###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.3 2010/06/11 12:04:29 j-nijhof Exp $
## Created:     2010/06/09
##
###########################################################################

ACLOCAL_AMFLAGS = -I config -I m4
SUBDIRS = lib
AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = -Wall -Wextra

if ENABLE_WERROR
AM_CFLAGS += -Werror
endif

if TACC
bin_PROGRAMS = tacc
tacc_SOURCES = tacc.c
tacc_LDADD = libtac.la $(LTLIBINTL) $(LIB_CRYPTO)  $(LIB_GETRANDOM)
tacc_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include @rt_debug_defines@ -I $(top_srcdir)/lib/include -I $(top_srcdir)/lib/lib
endif

libtac_includedir = $(includedir)/libtac
libtac_include_HEADERS = \
    libtac/include/tacplus.h \
    libtac/include/libtac.h \
    libtac/include/cdefs.h

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html#Updating-version-info
libtac_la_LDFLAGS = -version-info 5:0:0 -shared
lib_LTLIBRARIES = libtac.la
libtac_la_SOURCES = \
    libtac/lib/acct_r.c \
    libtac/lib/acct_s.c \
    libtac/lib/attrib.c \
    libtac/lib/authen_r.c \
    libtac/lib/authen_s.c \
    libtac/lib/author_r.c \
    libtac/lib/author_s.c \
    libtac/lib/connect.c \
    libtac/lib/cont_s.c \
    libtac/lib/crypt.c \
    libtac/lib/hdr_check.c \
    libtac/lib/header.c \
    libtac/lib/messages.c \
    libtac/lib/messages.h \
    libtac/lib/read_wait.c \
    libtac/lib/xalloc.c \
    $(libtac_include_HEADERS)

libtac_la_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include -I $(top_srcdir)/lib @rt_debug_defines@
libtac_la_LIBADD = lib/libgnu.la $(LTLIBINTL) $(LIB_CRYPTO) $(LIB_GETRANDOM)

moduledir = @pamdir@
module_LTLIBRARIES = pam_tacplus.la
pam_tacplus_la_SOURCES = pam_tacplus.h \
    pam_tacplus.c \
    support.h \
    support.c
pam_tacplus_la_CFLAGS = $(AM_CFLAGS) -I $(top_srcdir)/libtac/include -I $(top_srcdir)/libtac/lib \
    -I $(top_srcdir)/lib/include -I $(top_srcdir)/lib/lib
pam_tacplus_la_LDFLAGS = -module -avoid-version
pam_tacplus_la_LIBADD = libtac.la

EXTRA_DIST = pam_tacplus.spec libtac.pc.in m4/gnulib-cache.m4
if DOC
dist_doc_DATA = sample.pam README.md AUTHORS ChangeLog
endif

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtac.pc

EXTRA_DIST += gnulib-m4/gnulib-cache.m4
