AM_CFLAGS = @TANG_CFLAGS@ @libcrypto_CFLAGS@

check_LIBRARIES = libtest.a
libtest_a_SOURCES = srv.c

if USE_SYSTEMD
if USE_LIBSYSTEMD
check_PROGRAMS = keyd clt

keyd_LDADD = libtest.a ../libclt.a ../libcore.a @libcrypto_LIBS@
clt_LDADD = libtest.a ../libclt.a ../libcore.a @libcrypto_LIBS@

TESTS = $(check_PROGRAMS)
endif
endif
