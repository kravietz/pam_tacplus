###########################################################################
##
## File:        ./Makefile.am
## Versions:    $Id: Makefile.am,v 1.3 2010/06/11 12:04:29 j-nijhof Exp $
## Created:     2010/06/09
##
###########################################################################

ACLOCAL_AMFLAGS = -I config

moduledir = @libdir@
module_LTLIBRARIES = pam_tacplus.la
pam_tacplus_la_SOURCES = pam_tacplus.h \
pam_tacplus.c \
support.h \
support.c \
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
libtac/lib/magic.c \
libtac/lib/magic.h \
libtac/lib/md5.c \
libtac/lib/md5.h \
libtac/lib/messages.c \
libtac/lib/messages.h \
libtac/lib/version.c \
libtac/lib/xalloc.c \
libtac/lib/xalloc.h \
libtac/include/tacplus.h \
libtac/include/libtac.h \
libtac/include/cdefs.h

pam_tacplus_la_CFLAGS = $(AM_CFLAGS) -Ilibtac/include
pam_tacplus_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = pam_tacplus.spec sample.pam

MAINTAINERCLEANFILES = Makefile.in config.h.in configure aclocal.m4 \
                       config/config.guess  config/config.sub  config/depcomp \
                       config/install-sh config/ltmain.sh config/missing


install-data-hook:
	-rm $(DESTDIR)$(libdir)/pam_tacplus.la
	-rm $(DESTDIR)$(libdir)/pam_tacplus.a
	-rm $(DESTDIR)$(libdir)/pam_tacplus.so
	${INSTALL} -d $(DESTDIR)$(libdir)/security
	${INSTALL} -m 755 .libs/pam_tacplus.so $(DESTDIR)$(libdir)/security
	${INSTALL} -d $(DESTDIR)$(docdir)
	${INSTALL} -m 644 sample.pam $(DESTDIR)$(docdir)

