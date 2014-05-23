SUBDIRS= .

syddir=$(libexecdir)/$(PACKAGE)/t/valgrind
syd_SCRIPTS= analyze.sh valgrind.sh
syd_DATA= default.supp

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(syddir)/bin
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/sydbox
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/sydbox-dump
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/sydfmt
	$(LN_S) ../valgrind.sh $(DESTDIR)$(syddir)/shoebox
