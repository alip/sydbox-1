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

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CFLAGS= \
	   -DNDEBUG \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   -I$(top_srcdir)/src \
	   @SYDBOX_CFLAGS@

noinst_HEADERS+= \
		 tap.h \
		 emily.h

canontest_SOURCES= \
		   canontest.c \
		   $(top_srcdir)/src/canonicalize.c \
		   $(top_srcdir)/src/file.c \
		   $(top_srcdir)/src/util.c
canontest_CFLAGS= \
		  $(DEFS) \
		  $(AM_CFLAGS) \
		  -I$(top_srcdir)/src

emily_SOURCES= \
	       emily.c \
	       emily-access.c \
	       emily-stat.c \
	       emily-chmod.c \
	       emily-chown.c \
	       emily-open.c \
	       emily-creat.c \
	       emily-mkdir.c \
	       emily-mknod.c \
	       emily-rename.c \
	       emily-rmdir.c \
	       $(top_srcdir)/src/util.c
emily_CFLAGS= \
	      $(DEFS) \
	      $(AM_CFLAGS) \
	      -I$(top_srcdir)/src

wildtest_SOURCES= \
		  wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c \
		 $(DEFS) \
		 $(AM_CFLAGS)

check_PROGRAMS= \
		emily \
		canontest \
		wildtest
