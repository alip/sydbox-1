/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#include "emily.h"

#if 0
enum test_type {
	TEST_EEXIST,
	TEST_EFAULT,
	TEST_EPERM,
	TEST_SUCCESS,
};

static enum test_type get_test_type_from_environment(void)
{
	if (getenv("SYDBOX_TEST_EEXIST"))
		return TEST_EEXIST;
	if (getenv("SYDBOX_TEST_EFAULT"))
		return TEST_EFAULT;
	else if (getenv("SYDBOX_TEST_EPERM"))
		return TEST_EPERM;
	else
		return TEST_SUCCESS;
}

static int test_helper_chown(bool resolve_symlinks, int argc, char **argv)
{
	int r;
	const char *foo;
	enum test_type type = get_test_type_from_environment();
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily chown path\n");
		return 127;
	}

	r = resolve_symlinks ? chown(foo, uid, gid) : lchown(foo, uid, gid);
	if (r < 0) {
		if (type == TEST_SUCCESS) {
			perror("chown-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("chown");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_chown(int argc, char **argv)
{
	return test_helper_chown(true, argc, argv);
}

static int test_lchown(int argc, char **argv)
{
	return test_helper_chown(false, argc, argv);
}

static int test_open(int argc, char **argv)
{
	int fd, flags;
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	flags = 0;
	if (type == TEST_EFAULT) {
		foo = NULL;
	} else if (argc >= 2) {
		foo = argv[0];
		if (!strcmp(argv[1], "rdonly")) {
			flags = O_RDONLY;
			fd = open(foo, flags);
			if (fd < 0) {
				perror("open-rdonly");
				return 1;
			}
			return 0;
		}

		if (!strcmp(argv[1], "rdonly-creat"))
			flags |= O_RDONLY | O_CREAT;
		else if (!strcmp(argv[1], "rdonly-creat-excl"))
			flags |= O_RDONLY | O_CREAT | O_EXCL;
		else if (!strcmp(argv[1], "wronly"))
			flags |= O_WRONLY;
		else if (!strcmp(argv[1], "wronly-creat"))
			flags |= O_WRONLY | O_CREAT;
		else if (!strcmp(argv[1], "wronly-creat-excl"))
			flags |= O_WRONLY | O_CREAT | O_EXCL;
		else if (!strcmp(argv[1], "rdwr"))
			flags |= O_RDWR;
		else if (!strcmp(argv[1], "rdwr-creat"))
			flags |= O_RDWR | O_CREAT;
		else if (!strcmp(argv[1], "rdwr-creat-excl"))
			flags |= O_RDWR | O_CREAT | O_EXCL;
		else {
			fprintf(stderr, "emily: Unrecognized flag argument '%s'\n", argv[1]);
			return 127;
		}
	} else {
		fprintf(stderr, "Usage: emily open path flags data\n");
		return 127;
	}

	fd = open(foo, flags, 0644);
	if (fd < 0) {
		if (type == TEST_SUCCESS) {
			perror("open-success");
			return 1;
		} else if (type == TEST_EEXIST && errno == EEXIST) {
			return 0;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("open");
			return 1;
		}
	}

	printf("fd:%d\n", fd);
	if (!(flags & O_CREAT) && argc >= 3)
		do_write(fd, argv[2], strlen(argv[2]));
	do_close(fd);
	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_creat(int argc, char **argv)
{
	int fd;
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily creat path\n");
		return 127;
	}

	fd = creat(foo, 0644);
	if (fd < 0) {
		if (type == TEST_SUCCESS) {
			perror("creat-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("creat");
			return 1;
		}
	}

	printf("fd:%d\n", fd);
	if (argc >= 2)
		do_write(fd, argv[1], strlen(argv[1]));
	do_close(fd);
	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_mkdir(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily mkdir path\n");
		return 127;
	}

	if (mkdir(foo, 0000) < 0) {
		if (type == TEST_SUCCESS) {
			perror("mkdir-success");
			return 1;
		} else if (type == TEST_EEXIST && errno == EEXIST) {
			return 0;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("mkdir");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_mknod(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily mknod path\n");
		return 127;
	}

	if (mknod(foo, S_IFIFO, 0) < 0) {
		if (type == TEST_SUCCESS) {
			perror("mknod-success");
			return 1;
		} else if (type == TEST_EEXIST && errno == EEXIST) {
			return 0;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("mknod");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_rmdir(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily rmdir path\n");
		return 127;
	}

	if (rmdir(foo) < 0) {
		if (type == TEST_SUCCESS) {
			perror("rmdir-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("rmdir");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_truncate(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily truncate path\n");
		return 127;
	}

	if (truncate(foo, 0) < 0) {
		if (type == TEST_SUCCESS) {
			perror("truncate-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("truncate");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_umount(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily umount path\n");
		return 127;
	}

	if (umount(foo) < 0) {
		if (type == TEST_SUCCESS) {
			perror("umount-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("umount");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_umount2(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily umount2 path\n");
		return 127;
	}

	if (umount2(foo, 0) < 0) {
		if (type == TEST_SUCCESS) {
			perror("umount2-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("umount2");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_utime(int argc, char **argv)
{
	const char *foo;
	struct utimbuf t;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily utime path\n");
		return 127;
	}

	t.actime = 0;
	t.modtime = 0;

	if (utime(foo, &t) < 0) {
		if (type == TEST_SUCCESS) {
			perror("utime-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("utime");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_utimes(int argc, char **argv)
{
	const char *foo;
	struct timeval times[2];
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily utimes path\n");
		return 127;
	}

	times[0].tv_sec = times[1].tv_sec = 0;
	times[0].tv_usec = times[1].tv_usec = 0;

	if (utimes(foo, times) < 0) {
		if (type == TEST_SUCCESS) {
			perror("utimes-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("utimes");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_unlink(int argc, char **argv)
{
	const char *foo;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = NULL;
	else if (argc >= 1)
		foo = argv[0];
	else {
		fprintf(stderr, "Usage: emily unlink path\n");
		return 127;
	}

	if (unlink(foo) < 0) {
		if (type == TEST_SUCCESS) {
			perror("unlink-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("unlink");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}

static int test_link(int argc, char **argv)
{
	const char *foo, *bar;
	enum test_type type = get_test_type_from_environment();

	if (type == TEST_EFAULT)
		foo = bar = NULL;
	else if (argc >= 2) {
		foo = argv[0];
		bar = argv[1];
	} else {
		fprintf(stderr, "Usage: emily link path1 path2\n");
		return 127;
	}

	if (link(foo, bar) < 0) {
		if (type == TEST_SUCCESS) {
			perror("link-success");
			return 1;
		} else if (type == TEST_EFAULT && errno == EFAULT) {
			return 0;
		} else if (type == TEST_EPERM && errno == EPERM) {
			return 0;
		} else {
			perror("link");
			return 1;
		}
	}

	if (type == TEST_SUCCESS)
		return 0;
	return 2;
}
#endif

struct test {
	const char *name;
	int (*func) (int argc, char **argv);
} test_table[] = {
	{"chmod",	test_chmod},
	{"fchmodat",	test_fchmodat},
	{"chown",	test_chown},
	{"lchown",	test_lchown},
	{"fchownat",	test_fchownat},
	{"open",	test_open},
	{"openat",	test_openat},
#if 0
	{"creat",	test_creat},
	{"mkdir",	test_mkdir},
	{"mknod",	test_mknod},
	{"rmdir",	test_rmdir},
	{"truncate",	test_truncate},
	{"umount",	test_umount},
	{"umount2",	test_umount2},
	{"utime",	test_utime},
	{"utimes",	test_utimes},
	{"unlink",	test_unlink},
	{"link",	test_link},
#endif
	{NULL,		NULL},
};

static void usage(FILE *outfile, int exitcode)
{
	int i;

	fprintf(outfile, "Usage: emily test [arguments]\n");
	fprintf(outfile, "Available tests:\n");
	for (i = 0; test_table[i].name != NULL; i++)
		fprintf(outfile, "\t%s\n", test_table[i].name);
	exit(exitcode);
}

int main(int argc, char **argv)
{
	int i;
	const char *test_name;

	if (argc < 2)
		usage(stderr, 1);
	test_name = argv[1];
	argc -= 1;
	argv += 1;

	for (i = 0; test_table[i].name; i++) {
		if (!strcmp(test_name, test_table[i].name))
			return test_table[i].func(argc, argv);
	}

	usage(stderr, 127);
}

/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */
