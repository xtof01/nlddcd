%.service: %.service.in $(top_builddir)/config.status
	$(AM_V_GEN)$(SED)				\
	    -e 's|[@]sbindir[@]|$(sbindir)|g'		\
	    -e 's|[@]sysconfdir[@]|$(sysconfdir)|g'	\
	    < $< > $@-t &&				\
	    mv $@-t $@

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/sysconfig
	$(INSTALL_DATA) $(srcdir)/nlddcd.sysconfig \
	    $(DESTDIR)$(sysconfdir)/sysconfig/nlddcd

uninstall-local:
	rm -f $(DESTDIR)$(sysconfdir)/sysconfig/nlddcd
	rmdir $(DESTDIR)$(sysconfdir)/sysconfig || :

sbin_PROGRAMS = nlddcd
dist_sysconf_DATA = nlddcd.conf
systemdsystemunit_DATA = nlddcd.service
dist_man_MANS = nlddcd.8

AM_CFLAGS = $(MNL_CFLAGS) $(CONFUSE_CFLAGS) $(CURL_CFLAGS)
AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

nlddcd_SOURCES = nlddcd.c conf.c conf.h
nlddcd_LDADD = $(MNL_LIBS) $(CONFUSE_LIBS) $(CURL_LIBS)

CLEANFILES = $(systemdsystemunit_DATA)
EXTRA_DIST = nlddcd.service.in nlddcd.sysconfig
