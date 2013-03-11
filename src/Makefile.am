CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=
noinst_HEADERS=

noinst_SCRIPTS=\
	       kingbee.py

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITVERSION=\"$(GITVERSION)\"
AM_CFLAGS= \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   @SYDBOX_CFLAGS@

bin_PROGRAMS= sydbox sydfmt
sydbox_CPPFLAGS= -DSYDBOX
sydfmt_CPPFLAGS= -DSYDFMT
noinst_HEADERS+= \
		 asyd.h \
		 file.h \
		 log.h \
		 macro.h \
		 path.h \
		 pathlookup.h \
		 proc.h \
		 seccomp.h \
		 slist.h \
		 pathdecode.h \
		 pathmatch.h \
		 sockmatch.h \
		 sockmap.h \
		 util.h \
		 xfunc.h \
		 sydhash.h \
		 sydconf.h \
		 sydbox.h
sydbox_SOURCES= \
		 file.c \
		 log.c \
		 path.c \
		 pathlookup.c \
		 pink.c \
		 proc.c \
		 seccomp.c \
		 pathdecode.c \
		 pathmatch.c \
		 sockmatch.c \
		 util.c \
		 xfunc.c \
		 magic-panic.c \
		 magic-sandbox.c \
		 magic-socklist.c \
		 magic-strlist.c \
		 magic-trace.c \
		 magic-whitelist.c \
		 magic-log.c \
		 magic-match.c \
		 magic-if_match.c \
		 magic-cmd.c \
		 magic.c \
		 sandbox.c \
		 panic.c \
		 syscall-file.c \
		 syscall-sock.c \
		 syscall-special.c \
		 syscall.c \
		 systable.c \
		 config.c \
		 sydbox.c
sydfmt_SOURCES= \
		sydfmt.c

# http://troydhanson.github.com/uthash/
noinst_HEADERS+= \
		 uthash.h

# Imported from rsync!
noinst_HEADERS+= \
		 wildmatch.h
sydbox_SOURCES+= \
		 wildmatch.c

# Imported from gnulib!
noinst_HEADERS+= \
		 canonicalize.h
sydbox_SOURCES+= \
		 canonicalize.c

sydbox_LDADD= \
	      $(top_builddir)/pinktrace/libpinktrace_@PINKTRACE_PC_SLOT@.la

SPARSE=sparse
SPARSE_CPPFLAGS= $(DEFAULT_INCLUDES) \
		 -D__STDC_VERSION__=199901L \
		 -Wbitwise -Wcast-to-as -Wdefault-bitfield-sign \
		 -Wparen-string -Wptr-subtraction-blows \
		 -Wreturn-void -Wshadow -Wtypesign -Wundef \
		 -I$(shell $(CC) -print-file-name=include) \
		 -I$(shell $(CC) -print-file-name=include-fixed)
# Fix this flag for your architecture!
SPARSE_CPPFLAGS+= -D__x86_64__=1

sparse-check:
	for src in $(sydbox_SOURCES); \
	do \
		$(SPARSE) $(DEFS) $(AM_CFLAGS) $(SPARSE_CPPFLAGS) $$src || exit 1; \
	done
.PHONY: sparse-check
