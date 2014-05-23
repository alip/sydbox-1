AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .

syddir=$(libexecdir)/$(PACKAGE)/t/valgrind
syd_SCRIPTS= analyze.sh valgrind.sh
syd_DATA= default.supp

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(syddir)/bin
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox-dump
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydfmt
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/bin/shoebox
