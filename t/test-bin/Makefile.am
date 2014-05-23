AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CFLAGS= \
	   -DNDEBUG \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   -I$(top_srcdir)/src \
	   $(pinktrace_CFLAGS) \
	   @SYDBOX_CFLAGS@

wildtest_SOURCES= tap.h wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c \
		 $(DEFS) \
		 $(AM_CFLAGS)

syddir=$(libexecdir)/$(PACKAGE)/t/test-bin
syd_PROGRAMS= wildtest
