/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef EMILY_H
#define EMILY_H 1

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <getopt.h>

#include "strtable.h"

#define TEST_ERRNO_INVALID -1
#define TEST_DIRFD_INVALID STDERR_FILENO
#define TEST_DIRFD_NOEXIST 1023

static inline int expect_errno(int real_errno, int expected_errno)
{
	if (real_errno != expected_errno) {
		fprintf(stderr, "errno:%d %s != expected:%d %s\n",
				real_errno, errno_to_string(real_errno),
				expected_errno, errno_to_string(expected_errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

extern int test_chmod(int argc, char **argv);
extern int test_fchmodat(int argc, char **argv);
extern int test_chown(int argc, char **argv);
extern int test_lchown(int argc, char **argv);
extern int test_fchownat(int argc, char **argv);
extern int test_open(int argc, char **argv);
extern int test_openat(int argc, char **argv);

#endif /* !EMILY_H */
