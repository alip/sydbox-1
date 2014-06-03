/*
 * syd/check.c -- Syd's utility library checks
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "check.h"
#include <stdlib.h>
#include <string.h>

char syd_fail_message[128];

static void all_tests(void)
{
	const char *skip = getenv("SYD_CHECK_SKIP");

	if (!skip || !strstr(skip, "proc"))
		test_suite_proc();
}

int main(int argc, char *argv[])
{
	int r;

	r = seatest_testrunner(argc, argv, all_tests, NULL, NULL);
	return (r != 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
