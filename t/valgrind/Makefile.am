AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .

syddir=$(libexecdir)/$(PACKAGE)/t/valgrind
syd_SCRIPTS= analyze.sh valgrind.sh
syd_DATA= default.supp

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(syddir)/bin
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox-dump
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydfmt
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/shoebox

EXTRA_DIST= $(syd_SCRIPTS) $(syd_DATA)
