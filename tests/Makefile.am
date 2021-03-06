AM_MAKEFLAGS= --no-print-directory
SUBDIRS= bin .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log \
	    *.trs
EXTRA_DIST= \
	    README
noinst_DATA=
noinst_HEADERS=
noinst_SCRIPTS=
check_SCRIPTS=
BUILT_SOURCES=

check_SCRIPTS+= \
		test-lib-functions.sh \
		test-lib-sydbox.sh \
		test-runner.sh \
		valgrind/analyze.sh
EXTRA_DIST+= $(check_SCRIPTS)

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" \
		-e "s:@PTRACE_SEIZE@:$(PTRACE_SUPPORTS_SEIZE):g" \
		-e "s:@PTRACE_SECCOMP@:$(SYDBOX_HAVE_SECCOMP):g" \
		$< > $@
BUILT_SOURCES+= test-lib.sh
EXTRA_DIST+= test-lib.sh.in
CLEANFILES+= test-lib.sh

noinst_DATA+= \
	      wildtest.txt \
	      valgrind/default.supp
EXTRA_DIST+= $(noinst_DATA)

SYDBOX_CHECK_OPTIONS= --verbose
export SYDBOX_CHECK_OPTIONS

.PHONY: check-valgrind
check-valgrind:
	$(MAKE) SYDBOX_CHECK_OPTIONS="$(SYDBOX_CHECK_OPTIONS) --valgrind" check

TEST_EXTENSIONS= .sh
SH_LOG_COMPILER= $(srcdir)/test-runner.sh
TESTS= \
	t0000-basic.sh \
	t0001-sydbox.sh \
	t2000-path-wildmatch.sh \
	t2001-path-realpath.sh \
	t3000-fs-chmod.sh \
	t3001-fs-fchmodat.sh \
	t3002-fs-chown.sh \
	t3003-fs-lchown.sh \
	t3004-fs-fchownat.sh \
	t3005-fs-open.sh \
	t3006-fs-openat.sh \
	t3007-fs-creat.sh \
	t3008-fs-mkdir.sh \
	t3009-fs-mkdirat.sh \
	t3010-fs-mknod.sh \
	t3011-fs-mknodat.sh \
	t3012-fs-rmdir.sh \
	t3013-fs-truncate.sh \
	t3014-fs-umount.sh \
	t3015-fs-umount2.sh \
	t3016-fs-utime.sh \
	t3017-fs-utimensat.sh \
	t3018-fs-utimes.sh \
	t3019-fs-unlink.sh \
	t3020-fs-unlinkat.sh \
	t3021-fs-link.sh \
	t3022-fs-linkat.sh \
	t3023-fs-rename.sh \
	t3024-fs-renameat.sh \
	t3025-fs-symlink.sh \
	t3026-fs-symlinkat.sh \
	t3027-fs-mount.sh
check_SCRIPTS+= $(TESTS)
EXTRA_DIST+= $(TESTS)
