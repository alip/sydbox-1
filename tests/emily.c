/* Syd: See Emily Play!
 * Check program for sydbox tests
 * Copyright 2009, 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#include "emily.h"

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
	{"creat",	test_creat},
	{"mkdir",	test_mkdir},
	{"mkdirat",	test_mkdirat},
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
