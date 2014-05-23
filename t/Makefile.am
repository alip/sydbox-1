SUBDIRS= bin-wrappers sb valgrind .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log \
	    *.trs
check_SCRIPTS=
BUILT_SOURCES=

check_SCRIPTS+= \
		test-lib-functions.sh \
		test-lib-sydbox.sh \
		test-runner.sh

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" \
		-e "s:@PTRACE_SEIZE@:$(PINKTRACE_HAVE_SEIZE):g" \
		-e "s:@PTRACE_SECCOMP@:$(SYDBOX_HAVE_SECCOMP):g" \
		$< > $@
BUILT_SOURCES+= test-lib.sh
check_SCRIPTS+= test-lib.sh

TEST_EXTENSIONS= .sh
SH_LOG_COMPILER= $(srcdir)/test-runner.sh
TESTS= \
       t0000-basic.sh \
       t0001-sydbox.sh
check_SCRIPTS+= $(TESTS)

syddir=$(libexecdir)/$(PACKAGE)/t
syd_SCRIPTS= $(check_SCRIPTS)
syd_DATA= README

EXTRA_DIST= Makefile.test
install-data-local:
	cp Makefile.test $(DESTDIR)$(syddir)/Makefile
