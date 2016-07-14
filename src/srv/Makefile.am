tangdir = $(localstatedir)/$(PACKAGE_NAME)

AM_CFLAGS = @TANG_CFLAGS@ @jose_CFLAGS@

systemdsystemunit_DATA = tangd.socket tangd.service
EXTRA_DIST = tangd.socket.in tangd.service.in
CLEANFILES = tangd.socket tangd.service

libexec_PROGRAMS = tangd
tangd_SOURCES = eng.h eng_jose.c tangd.c
tangd_LDADD = @jose_LIBS@

install-data-hook:
	mkdir -p $(DESTDIR)$(tangdir)
	chmod 2570 $(DESTDIR)$(tangdir)

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@TANG_DB\@,$(tangdir),g' \
		-e 's,@TANG_PORT\@,$(TANG_PORT),g' \
		$(srcdir)/$@.in > $@
