/*
 * libsyd/proc-TEST.c
 *
 * file and path utility tests
 *
 * Copyright (c) 2015 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU Lesser General Public License v3 (or later)
 */

#define _GNU_SOURCE 1
#include "check.h"

#include <limits.h>
#include <stdlib.h>

#if AT_FDCWD == -128
#define INVALID_FD -129
#else
#define INVALID_FD -128
#endif

#define TMPDIR		"./file-TEST-tmp"
#define TMP_FILE	"file"
#define TMP_VOID_FILE	"void"
#define TMP_LINK	"link"
#define TMP_DANG_LINK	"dang"
#define TMP_LOOP_LINK	"loop"
static char *tmpdir;
static char *tmp_file;
static char *tmp_void_file;
static char *tmp_link;
static char *tmp_dang_link;
static char *tmp_loop_link;

static void test_setup(void)
{
	assert_int_equal(0, system("rm -fr "TMPDIR));
	assert_int_equal(0, system("mkdir -p -m700 "TMPDIR));
	assert_int_equal(0, system("touch "TMPDIR"/"TMP_FILE));
	assert_int_equal(0, system("ln -s file "TMPDIR"/"TMP_LINK));
	assert_int_equal(0, system("ln -s void "TMPDIR"/"TMP_DANG_LINK));
	assert_int_equal(0, system("ln -s loop "TMPDIR"/"TMP_LOOP_LINK"-loop"));
	assert_int_equal(0, system("ln -s loop-loop "TMPDIR"/"TMP_LOOP_LINK));
	tmpdir = realpath(TMPDIR, NULL);
	assert_true(tmpdir != NULL);
	assert_true(asprintf(&tmp_file, "%s/"TMP_FILE, tmpdir) != -1);
	assert_true(asprintf(&tmp_void_file, "%s/"TMP_VOID_FILE, tmpdir) != -1);
	assert_true(asprintf(&tmp_link, "%s/"TMP_LINK, tmpdir) != -1);
	assert_true(asprintf(&tmp_dang_link, "%s/"TMP_DANG_LINK, tmpdir) != -1);
	assert_true(asprintf(&tmp_loop_link, "%s/"TMP_LOOP_LINK, tmpdir) != -1);
	;
}

static void test_teardown(void)
{
	assert_int_equal(0, system("rm -fr ./file-TEST-tmp"));
	if (tmpdir)
		free(tmpdir);
	;
}

static void test_syd_readlink_alloc_01(void)
{
	char *buf;

	assert_int_equal(-EINVAL, syd_readlink_alloc(NULL, &buf));
	assert_int_equal(-EINVAL, syd_readlink_alloc("root", NULL));
}

static void test_syd_path_root_check_01(void)
{
	assert_int_equal(-EINVAL, syd_path_root_check(NULL));
	assert_int_equal(-EINVAL, syd_path_root_check("root"));
	assert_int_equal(-ENOENT, syd_path_root_check("/.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/./.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/../.../"));
	assert_int_equal(-ENOENT, syd_path_root_check("/..."));
	assert_int_equal(-ENOENT, syd_path_root_check("/./..."));
	assert_int_equal(-ENOENT, syd_path_root_check("/../..."));
	assert_int_equal(0, syd_path_root_check("/"));
	assert_int_equal(0, syd_path_root_check("//"));
	assert_int_equal(0, syd_path_root_check("///"));
	assert_int_equal(0, syd_path_root_check("////"));
	assert_int_equal(0, syd_path_root_check("/./"));
	assert_int_equal(0, syd_path_root_check("/././"));
	assert_int_equal(0, syd_path_root_check("/../"));
	assert_int_equal(0, syd_path_root_check("/.././"));
	assert_int_equal(0, syd_path_root_check("/../../"));
	assert_int_equal(0, syd_path_root_check("/../.././"));
	assert_int_equal(0, syd_path_root_check("/../../../"));
	assert_int_equal(1, syd_path_root_check("//root"));
	assert_int_equal(2, syd_path_root_check("///root"));
	assert_int_equal(3, syd_path_root_check("////root"));
	assert_int_equal(2, syd_path_root_check("/./root"));
	assert_int_equal(4, syd_path_root_check("/././root"));
	assert_int_equal(3, syd_path_root_check("/../root"));
	assert_int_equal(5, syd_path_root_check("/.././root"));
	assert_int_equal(6, syd_path_root_check("/../../root"));
	assert_int_equal(8, syd_path_root_check("/../.././root"));
	assert_int_equal(9, syd_path_root_check("/../../../root"));
}

static void test_syd_path_stat_01(void)
{
	struct stat sb;

	assert_int_equal(-EINVAL, syd_path_stat(NULL, 0, false, &sb));
	assert_int_equal(-EINVAL, syd_path_stat("/root", 0, false, NULL));
	assert_int_equal(-EINVAL, syd_path_stat("root", 0, false, &sb));

	assert_int_equal(0, syd_path_stat(tmp_file, 0, false, &sb));
	assert_true(S_ISREG(sb.st_mode));

	assert_int_equal(-ENOENT, syd_path_stat(tmp_void_file, 0, false, &sb));
	assert_int_equal(-ENOENT, syd_path_stat(tmp_void_file, SYD_REALPATH_NOLAST, false, &sb));

	assert_int_equal(0, syd_path_stat(tmp_void_file, SYD_REALPATH_NOLAST, true, &sb));
	assert_true(sb.st_mode == 0);

	assert_int_equal(0, syd_path_stat(tmp_link, 0, false, &sb));
	assert_true(S_ISREG(sb.st_mode));

	assert_int_equal(0, syd_path_stat(tmp_link, SYD_REALPATH_NOFOLLOW, false, &sb));
	assert_true(S_ISLNK(sb.st_mode));

	assert_int_equal(-ENOENT, syd_path_stat(tmp_dang_link, 0, false, &sb));

	assert_int_equal(0, syd_path_stat(tmp_dang_link, SYD_REALPATH_NOFOLLOW, false, &sb));
	assert_true(S_ISLNK(sb.st_mode));

	assert_int_equal(0, syd_path_stat(tmp_dang_link, SYD_REALPATH_NOFOLLOW, true, &sb));
	assert_true(S_ISLNK(sb.st_mode));

	assert_int_equal(-ELOOP, syd_path_stat(tmp_loop_link, 0, false, &sb));
	assert_int_equal(-ELOOP, syd_path_stat(tmp_loop_link, SYD_REALPATH_NOLAST, false, &sb));

	assert_int_equal(0, syd_path_stat(tmp_loop_link, SYD_REALPATH_NOLAST, true, &sb));
	assert_true(sb.st_mode == 0);
}

static void test_syd_realpath_at_01(void)
{
	int r;
	char *buf;

	/* 3rd argument is NULL should return -EINVAL" */
	r = syd_realpath_at(1, "/root", NULL, 0);
	assert_int_equal(-EINVAL, r); 

	r = syd_realpath_at(INVALID_FD, NULL, &buf, 0);
	assert_int_equal(-EINVAL, r);
	r = syd_realpath_at(INVALID_FD, NULL, &buf, SYD_REALPATH_EXIST);
	assert_int_equal(-EINVAL, r);
	r = syd_realpath_at(INVALID_FD, NULL, &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(-EINVAL, r);

	r = syd_realpath_at(INVALID_FD, "/", &buf, 0);
	assert_int_equal(-EINVAL, r);

	r = syd_realpath_at(INVALID_FD, "", &buf, 0);
	assert_int_equal(-ENOENT, r);
}

static void test_syd_realpath_at_02(void)
{
	int r;
	char *buf;

	r = syd_realpath_at(0, "/", &buf, 0);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "//", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "//", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "///", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "///", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "////", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "////", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/./", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/./", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/.././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/.././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../.././", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../.././", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../../", &buf, SYD_REALPATH_EXIST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);

	r = syd_realpath_at(0, "/../../../", &buf, SYD_REALPATH_NOLAST);
	assert_int_equal(0, r);
	assert_string_equal("/", buf);
	free(buf);
}

static void test_syd_realpath_at_03(void)
{
	/* TODO */;
}

static void test_fixture_file(void)
{
	test_fixture_start();

	fixture_setup(test_setup);
	fixture_teardown(test_teardown);

	run_test(test_syd_readlink_alloc_01);
	run_test(test_syd_path_root_check_01);
	run_test(test_syd_path_stat_01);
	run_test(test_syd_realpath_at_01);
	run_test(test_syd_realpath_at_02);
	run_test(test_syd_realpath_at_03);

	test_fixture_end();
}

void test_suite_file(void)
{
	test_fixture_file();
}
