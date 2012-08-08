CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

AM_CFLAGS= \
	   $(pinktrace_CFLAGS) \
	   $(pinktrace_easy_CFLAGS) \
	   @SYDBOX_CFLAGS@

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" $< > $@
CLEANFILES+= test-lib.sh

emily_SOURCES= \
	       emily.c \
	       emily-chmod.c \
	       emily-chown.c \
	       emily-open.c \
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
	t002-chmod.sh \
	t003-fchmodat.sh
	t004-chown.sh \
	t005-lchown.sh \
	t006-fchownat.sh
#	t007-open.sh \
#	t008-creat.sh \
#	t009-mkdir.sh \
#	t010-mknod.sh \
#	t011-rmdir.sh \
#	t012-truncate.sh \
#	t013-umount.sh \
#	t014-umount2.sh \
#	t015-utime.sh \
#	t016-utimes.sh \
#	t017-unlink.sh \
#	t018-link.sh \
#	t019-rename.sh \
#	t020-symlink.sh \
#	t021-mount.sh \
#	t022-openat.sh \
#	t023-mknodat.sh \
#	t024-mkdirat.sh \
#	t025-unlinkat.sh \
#	t026-linkat.sh

EXTRA_DIST= $(TESTS) \
	    test-lib.sh.in \
	    test-lib-functions.sh

check_PROGRAMS= \
		wildtest \
		test-lib.sh \
		emily

