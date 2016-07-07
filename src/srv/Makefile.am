tangdir = $(localstatedir)/$(PACKAGE_NAME)

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

systemdsystemunit_DATA = tang-keyd.socket tang-keyd.service
EXTRA_DIST = tang-keyd.socket.in tang-keyd.service.in
CLEANFILES = tang-keyd.socket tang-keyd.service

libexec_PROGRAMS = tang-keyd
tang_keyd_SOURCES = eng.h eng_openssl.c tang-keyd.c
tang_keyd_LDADD = @jose_LIBS@

install-data-hook:
	mkdir -p $(DESTDIR)$(tangdir)
	chmod 2570 $(DESTDIR)$(tangdir)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(tangdir),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
