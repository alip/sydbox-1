CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITVERSION=\"$(GITVERSION)\"
AM_CFLAGS= \
	   -I$(top_builddir)/include \
	   -I$(top_srcdir)/include \
	   @SYDBOX_CFLAGS@

bin_PROGRAMS= sydbox
noinst_HEADERS= \
		JSON_parser.h \
		byteorder.h \
		canonicalize.h \
		file.h \
		hashtable.h \
		log.h \
		macro.h \
		path.h
		proc.h \
		seccomp.h \
		slist.h \
		strtable.h \
		util.h \
		wildmatch.h \
		sys-check.h \
		sydbox-conf.h \
		sydbox-magic.h \
		sydbox-defs.h
sydbox_SOURCES= \
		 JSON_parser.c \
		 canonicalize.c \
		 file.c \
		 hashtable.c \
		 log.c \
		 path.c \
		 proc.c \
		 seccomp.c \
		 util.c \
		 wildmatch.c \
		 magic-panic.c \
		 magic-sandbox.c \
		 magic-socklist.c \
		 magic-strlist.c \
		 magic-trace.c \
		 magic-whitelist.c \
		 magic-log.c \
		 magic-match.c \
		 magic-if_match.c \
		 sydbox-box.c \
		 sydbox-callback.c \
		 sydbox-config.c \
		 sydbox-magic.c \
		 sydbox-panic.c \
		 sydbox-path.c \
		 sydbox-sock.c \
		 sydbox-sockinfo.c \
		 sydbox-syscall.c \
		 sydbox-systable.c \
		 sydbox-wild.c \
		 sydbox-xfunc.c \
		 sys-access.c \
		 sys-chdir.c \
		 sys-execve.c \
		 sys-stat.c \
		 sys-dup.c \
		 sys-fcntl.c \
		 sys-chmod.c \
		 sys-chown.c \
		 sys-open.c \
		 sys-creat.c \
		 sys-close.c \
		 sys-mkdir.c \
		 sys-mknod.c \
		 sys-rmdir.c \
		 sys-truncate.c \
		 sys-mount.c \
		 sys-utime.c \
		 sys-unlink.c \
		 sys-setxattr.c \
		 sys-removexattr.c \
		 sys-link.c \
		 sys-rename.c \
		 sys-symlink.c \
		 sys-socketcall.c \
		 sys-bind.c \
		 sys-connect.c \
		 sys-getsockname.c \
		 sydbox.c
sydbox_LDADD= \
	      $(top_builddir)/pinktrace/libpinktrace_@PINKTRACE_PC_SLOT@.la \
	      $(top_builddir)/pinktrace/easy/libpinktrace_easy_@PINKTRACE_PC_SLOT@.la

SPARSE=sparse
SPARSE_CPPFLAGS= $(DEFAULT_INCLUDES) \
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
