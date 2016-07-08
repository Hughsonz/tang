tangdir = $(localstatedir)/$(PACKAGE_NAME)

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

systemdsystemunit_DATA = tang-jrpcd.socket tang-jrpcd.service
EXTRA_DIST = tang-jrpcd.socket.in tang-jrpcd.service.in
CLEANFILES = tang-jrpcd.socket tang-jrpcd.service

libexec_PROGRAMS = tang-jrpcd tang-httpd
tang_jrpcd_SOURCES = eng.h eng_openssl.c tang-jrpcd.c
tang_jrpcd_LDADD = @jose_LIBS@
tang_httpd_SOURCES = eng.h eng_openssl.c tang-httpd.c
tang_httpd_LDADD = @jose_LIBS@

install-data-hook:
	mkdir -p $(DESTDIR)$(tangdir)
	chmod 2570 $(DESTDIR)$(tangdir)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(tangdir),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
