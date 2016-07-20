SUBDIRS = .
EXTRA_DIST = clevis.sym

AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

noinst_LTLIBRARIES = libclt.la
libclt_la_SOURCES = adv.c adv.h rec.c rec.h http.c http.h
libclt_la_LIBADD = @jose_LIBS@ -lhttp_parser

bin_PROGRAMS = tang
tang_SOURCES = tang.c
tang_LDADD = libclt.la

# nagiosdir = $(libdir)/nagios/plugins
# nagios_PROGRAMS = tang-nagios
# tang_nagios_SOURCES = nagios.c
# tang_nagios_LDADD = libclt.la

# if USE_CLEVIS
# clevispin_LTLIBRARIES = tang.la
# tang_la_SOURCES = clevis.c
# tang_la_LIBADD = libclt.la @clevis_LIBS@
# tang_la_LDFLAGS = -module -avoid-version -export-symbols $(srcdir)/clevis.sym

# install-data-hook:
# 	rm -f $(DESTDIR)$(clevispindir)/tang.la
# endif
