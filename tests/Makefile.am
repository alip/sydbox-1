CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CFLAGS= \
	   -DNDEBUG \
	   -I$(top_builddir)/include \
	   -I$(top_srcdir)/include \
	   @SYDBOX_CFLAGS@

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" $< > $@
CLEANFILES+= test-lib.sh

emily_SOURCES= \
	       emily.c \
	       emily-stat.c \
	       emily-chmod.c \
	       emily-chown.c \
	       emily-open.c \
	       emily-creat.c \
	       emily-mkdir.c \
	       $(top_srcdir)/src/util.c
emily_CFLAGS= \
	      $(DEFS) \
	      $(AM_CFLAGS) \
	      -I$(top_srcdir)/src

noinst_DATA= wildtest.txt
wildtest_SOURCES= \
		  wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c \
		 $(DEFS) \
		 $(AM_CFLAGS)

noinst_SCRIPTS= \
		bin-wrappers/sydbox \
		valgrind/analyze.sh \
		valgrind/default.supp \
		valgrind/valgrind.sh \
		valgrind/bin/sydbox

.PHONY: check-valgrind
check-valgrind:
	$(MAKE) SYDBOX_CHECK_OPTS="$(SYDBOX_CHECK_OPTS) --valgrind" check

TESTS_ENVIRONMENT= $(srcdir)/test-runner.sh
TESTS= \
	t000-basic.sh \
	t001-wildmatch.sh \
	t002-canonicalize.sh \
	t003-chmod.sh \
	t004-fchmodat.sh \
	t005-chown.sh \
	t006-lchown.sh \
	t007-fchownat.sh \
	t008-open.sh \
	t009-openat.sh \
	t010-creat.sh \
	t011-mkdir.sh
EXTRA_DIST= $(TESTS) \
	    test-lib.sh.in \
	    test-lib-functions.sh

check_PROGRAMS= \
		wildtest \
		test-lib.sh \
		emily

