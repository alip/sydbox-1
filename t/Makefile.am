SUBDIRS= bin-wrappers sb .
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

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" \
		-e "s:@PTRACE_SEIZE@:$(PINKTRACE_HAVE_SEIZE):g" \
		-e "s:@PTRACE_SECCOMP@:$(SYDBOX_HAVE_SECCOMP):g" \
		$< > $@
BUILT_SOURCES+= test-lib.sh
EXTRA_DIST+= test-lib.sh.in
CLEANFILES+= test-lib.sh

TEST_EXTENSIONS= .sh
SH_LOG_COMPILER= $(srcdir)/test-runner.sh
TESTS= \
       t0000-basic.sh \
       t0001-sydbox.sh
check_SCRIPTS+= $(TESTS)
EXTRA_DIST+= $(check_SCRIPTS)
