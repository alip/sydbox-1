SUBDIRS= .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov

sydbox: sydbox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@

sydbox-dump: sydbox-dump.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@

shoebox: shoebox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir)/$(PACKAGE):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@

sydfmt: sydfmt.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@

check_SCRIPTS= \
	       sydbox \
	       sydbox-dump \
	       shoebox \
	       sydfmt

syddir=$(libexecdir)/$(PACKAGE)/t/bin-wrappers
syd_SCRIPTS= $(check_SCRIPTS)
