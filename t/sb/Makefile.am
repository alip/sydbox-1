EXTRA_DIST = test-skel-0.c tests.h headers.s localdecls.h

AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = `expr $@ : .*_pthread >/dev/null && echo -pthread`
AM_LDFLAGS = `expr $@ : .*_static >/dev/null && echo -all-static`

check_PROGRAMS= \
		access-0 \
		chmod-0 \
		chown-0 \
		creat-0 \
		creat64-0 \
		faccessat-0 \
		fchmodat-0 \
		fchownat-0 \
		futimesat-0 \
		lchown-0 \
		link-0 \
		linkat-0 \
		linkat_static-0 \
		lutimes-0 \
		mkdir-0 \
		mkdirat-0 \
		mkdir_static-0 \
		mkfifo-0 \
		mkfifoat-0 \
		mknod-0 \
		mknodat-0 \
		open-0 \
		open64-0 \
		openat-0 \
		openat64-0 \
		openat_static-0 \
		open_static-0 \
		remove-0 \
		rename-0 \
		renameat-0 \
		rmdir-0 \
		signal_static-0 \
		symlink-0 \
		symlinkat-0 \
		truncate-0 \
		truncate64-0 \
		unlink-0 \
		unlinkat-0 \
		unlink_static-0 \
		utime-0 \
		utimensat-0 \
		utimensat_static-0 \
		utimes-0 \
		vfork-0 \
		syd_true \
		syd_true_static \
		syd_true_fork \
		syd_true_fork_static \
		syd_true_pthread \
		syd_false \
		syd_false_static \
		syd_false_fork \
		syd_false_fork_static \
		syd_false_pthread

syddir=$(libexecdir)/$(PACKAGE)/t/sb
syd_PROGRAMS= $(check_PROGRAMS)
