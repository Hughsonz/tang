SUBDIRS = .

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

bin_PROGRAMS = tang
tang_SOURCES = adv.c rec.c http.c clt.h tang.c
tang_LDADD = @jose_LIBS@ -lhttp_parser
