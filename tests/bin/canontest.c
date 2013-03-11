/*
 * Check program for sydbox/canonicalize.c
 * Copyright 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "emily.h"

static struct option long_options[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"errno",	required_argument,	NULL,	'e'},
	{"mode",	required_argument,	NULL,	'm'},
	{NULL,		0,			NULL,	0},
};

static void usage(FILE *outfile, int exitcode)
{
	fprintf(outfile, "\
Usage: canontest [-hcr] -e errno -m <mode> <path>\
\n\
Options:\n\
-h, --help                  -- Show help\n\
-e <errno, --errno=<errno>  -- Expected errno\n\
-m <mode>, --mode=<mode>    -- One of `existing', `all_but_last', `missing' and `nolinks'\n\
-c, --compare               -- Compare result with realpath(3)\n\
-r, --realpath              -- Output result of realpath(3)\n\
");
	exit(exitcode);
}


int main(int argc, char **argv)
{
	int optc, r;
	bool test_realpath = false;
	int test_cmp = 0;
	int test_errno = 0;
	int test_mode = -1;
	const char *test_file;
	char *path1, *path2;
	int save_errno1, save_errno2;

	while ((optc = getopt_long(argc, argv, "he:m:cr", long_options, NULL)) != EOF) {
		switch (optc) {
		case 'h':
			usage(stdout, 0);
			break;
		case 'e':
			test_errno = pink_lookup_errno(optarg, 0);
			if (test_errno == -1)
				usage(stderr, 2);
			break;
		case 'm':
			if (test_mode == -1)
				test_mode = 0;
			if (!strcmp(optarg, "existing"))
				test_mode |= CAN_EXISTING;
			else if (!strcmp(optarg, "all_but_last"))
				test_mode |= CAN_ALL_BUT_LAST;
			else if (!strcmp(optarg, "missing"))
				test_mode |= CAN_MISSING;
			else if (!strcmp(optarg, "nolinks"))
				test_mode |= CAN_NOLINKS;
			else
				usage(stderr, 2);
			break;
		case 'c':
			test_cmp = 1;
			break;
		case 'r':
			test_realpath = true;
			break;
		default:
			usage(stderr, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (test_mode == -1 && !test_realpath)
		usage(stderr, 1);
	if (test_cmp && test_realpath) /* mutually exclusive! */
		usage(stderr, 1);
	if (argc != 1)
		usage(stderr, 1);
	test_file = argv[0];

	if (test_errno != 0) {
		/* Expecting failure */
		r = canonicalize_filename_mode(test_file, (can_mode_t)test_mode, &path1);
		if (r < 0)
			return expect_errno(-r, test_errno);
		return expect_errno(0, test_errno);
	}
	if (test_realpath) {
		/* Output result of realpath() */
		errno = 0;
		path1 = realpath(test_file, NULL);
		save_errno1 = errno;

		if (!path1)
			return EXIT_FAILURE;
		if (expect_errno(save_errno1, 0) == EXIT_FAILURE)
			return EXIT_FAILURE;
		printf("%s", path1);
		return EXIT_SUCCESS;
	} else if (test_cmp) {
		/* Compare with realpath() */
		errno = 0;
		path1 = realpath(test_file, NULL);
		save_errno1 = errno;

		path2 = NULL;
		r = canonicalize_filename_mode(test_file, (can_mode_t)test_mode, &path2);
		save_errno2 = -r;

		if (expect_errno(save_errno2, save_errno1) == EXIT_FAILURE)
			return EXIT_FAILURE;
		if (!path1 && !path2)
			return EXIT_SUCCESS;
		if ((path1 && !path2)
		    || (!path1 && path2)
		    || (strcmp(path1, path2) != 0)) {
			fprintf(stderr, "realpath(`%s', %#x) -> `%s'\n",
				test_file, test_mode, path1);
			fprintf(stderr, "canon_f_m(`%s', %#x) -> `%s'\n",
				test_file, test_mode, path2);
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	}

	r = canonicalize_filename_mode(test_file, (can_mode_t)test_mode, &path1);
	if (r < 0) {
		fprintf(stderr, "canon_f_m(`%s', %#x) -> NULL (errno:%d %s)\n",
			test_file, (can_mode_t)test_mode,
			-r, strerror(-r));
		return EXIT_FAILURE;
	}
	printf("%s", path1);
	return EXIT_SUCCESS;
}
