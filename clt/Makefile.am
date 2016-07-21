SUBDIRS = .
EXTRA_DIST = clevis.sym

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

noinst_LTLIBRARIES = libclt.la
libclt_la_SOURCES = adv.c rec.c http.c clt.h
libclt_la_LIBADD = @jose_LIBS@ -lhttp_parser

nagiosdir = $(libdir)/nagios/plugins
nagios_PROGRAMS = nagios/tang
nagios_tang_LDADD = libclt.la

# if USE_CLEVIS
# clevispin_LTLIBRARIES = tang.la
# tang_la_SOURCES = clevis.c
# tang_la_LIBADD = libclt.la @clevis_LIBS@
# tang_la_LDFLAGS = -module -avoid-version -export-symbols $(srcdir)/clevis.sym

# install-data-hook:
# 	rm -f $(DESTDIR)$(clevispindir)/tang.la
# endif
