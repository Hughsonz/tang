SUBDIRS = .
EXTRA_DIST = clevis.sym

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

noinst_LTLIBRARIES = libclt.la
libclt_la_SOURCES = adv.c rec.c http.c clt.h
libclt_la_LIBADD = @jose_LIBS@ -lhttp_parser

nagiosdir = $(libdir)/nagios/plugins
nagios_PROGRAMS = nagios/tang
nagios_tang_LDADD = libclt.la

clevisdir = $(libdir)/clevis/pins
clevis_PROGRAMS = clevis/tang
clevis_tang_LDADD = libclt.la
