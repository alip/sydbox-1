SUBDIRS= bin .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log
EXTRA_DIST=
noinst_DATA=
noinst_HEADERS=
noinst_SCRIPTS=

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" $< > $@
CLEANFILES+= test-lib.sh

noinst_DATA+= wildtest.txt

noinst_DATA+= valgrind/default.supp
noinst_SCRIPTS+= valgrind/analyze.sh

.PHONY: check-valgrind
check-valgrind:
	$(MAKE) SYDBOX_CHECK_OPTS="$(SYDBOX_CHECK_OPTS) --valgrind" check

TESTS_ENVIRONMENT= $(srcdir)/test-runner.sh
TESTS= \
	t0000-basic.sh \
	t1000-config-json.sh \
	t2000-path-wildmatch.sh \
	t2001-path-canonicalize.sh \
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
	t3017-fs-utimes.sh \
	t3018-fs-unlink.sh \
	t3019-fs-unlinkat.sh \
	t3020-fs-link.sh \
	t3021-fs-linkat.sh \
	t3022-fs-rename.sh \
	t3023-fs-renameat.sh \
	t3024-fs-symlink.sh \
	t3025-fs-symlinkat.sh \
	t3026-fs-mount.sh
EXTRA_DIST+= \
	     README \
	     $(TESTS) \
	     test-lib.sh.in \
	     test-lib-functions.sh

check_SCRIPTS= \
	       test-lib.sh

# Imported from: http://www.json.org/JSON_checker/test.zip
noinst_DATA+= \
	      json/pass1.json \
	      json/pass2.json \
	      json/pass3.json \
	      json/fail1.json \
	      json/fail2.json \
	      json/fail3.json \
	      json/fail4.json \
	      json/fail5.json \
	      json/fail6.json \
	      json/fail7.json \
	      json/fail8.json \
	      json/fail9.json \
	      json/fail10.json \
	      json/fail11.json \
	      json/fail12.json \
	      json/fail13.json \
	      json/fail14.json \
	      json/fail15.json \
	      json/fail16.json \
	      json/fail17.json \
	      json/fail18.json \
	      json/fail19.json \
	      json/fail20.json \
	      json/fail21.json \
	      json/fail22.json \
	      json/fail23.json \
	      json/fail24.json \
	      json/fail25.json \
	      json/fail26.json \
	      json/fail27.json \
	      json/fail28.json \
	      json/fail29.json \
	      json/fail30.json \
	      json/fail31.json \
	      json/fail32.json \
	      json/fail33.json
