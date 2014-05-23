SUBDIRS= .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=
noinst_DATA=
noinst_HEADERS=
noinst_SCRIPTS=

sydbox: sydbox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= sydbox
EXTRA_DIST+= sydbox.in

sydbox-dump: sydbox-dump.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= sydbox-dump
EXTRA_DIST+= sydbox-dump.in

shoebox: shoebox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= shoebox
EXTRA_DIST+= shoebox.in

sydfmt: sydfmt.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= sydfmt
EXTRA_DIST+= sydfmt.in

check_SCRIPTS= \
	       sydbox \
	       sydbox-dump \
	       shoebox \
	       sydfmt
