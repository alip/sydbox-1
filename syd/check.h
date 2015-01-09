/*
 * syd/check.h -- Syd's utility library check headers
 *
 * Copyright (c) 2014, 2015 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU Lesser General Public License v3 (or later)
 */

#ifndef LIBSYD_CHECK_H
#define LIBSYD_CHECK_H 1

#include "seatest.h"
#include "syd.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

extern char syd_fail_message[128];
#define fail_msg(...) \
	do { \
		snprintf(syd_fail_message, 256, __VA_ARGS__); \
		seatest_simple_test_result(0, syd_fail_message, __func__, __LINE__); \
	} while (0)
#define assert_true_msg(x, fmt, ...) \
	do { \
		if (!(x)) { \
			fail_msg((fmt), __VA_ARGS__); \
		} \
	} while (0)
#define assert_false_msg(x, fmt, ...) \
	do { \
		if ((x)) { \
			fail_msg((fmt), __VA_ARGS__); \
		} \
	} while (0)

void test_suite_proc(void);

#endif
