/*
 * Check program for the JSON parser
 * Copyright 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#include "emily.h"

static const char *JSON_strerror(JSON_error error)
{
	switch (error) {
	case JSON_E_NONE:
		return "success";
	case JSON_E_INVALID_CHAR:
		return "invalid char";
	case JSON_E_INVALID_KEYWORD:
		return "invalid keyword";
	case JSON_E_INVALID_ESCAPE_SEQUENCE:
		return "invalid escape sequence";
	case JSON_E_INVALID_UNICODE_SEQUENCE:
		return "invalid unicode sequence";
	case JSON_E_INVALID_NUMBER:
		return "invalid number";
	case JSON_E_NESTING_DEPTH_REACHED:
		return "nesting depth reached";
	case JSON_E_UNBALANCED_COLLECTION:
		return "unbalanced collection";
	case JSON_E_EXPECTED_KEY:
		return "expected key";
	case JSON_E_EXPECTED_COLON:
		return "expected colon";
	case JSON_E_OUT_OF_MEMORY:
		return "out of memory";
	default:
		return "unknown";
	}
}

static JSON_parser json_init(void)
{
	JSON_config jc;

	init_JSON_config(&jc);
	jc.depth = 19; /* json/fail18.json */
	jc.allow_comments = 1;
	jc.handle_floats_manually = 0;
	jc.callback = NULL;
	jc.callback_ctx = NULL;
	jc.malloc = tap_xmalloc;
	jc.free = tap_xfree;

	return new_JSON_parser(&jc);
}

static int json_parse(JSON_parser jp, const char *pathname)
{
	bool ok;
	unsigned i = 0;
	int c, r;
	FILE *fp;
	char *bname;

	r = basename_alloc(pathname, &bname);
	if (r < 0)
		tap_xbail_out("basename `%s' failed (errno:%d %s)",
			      pathname, -r, strerror(-r));

	if (!strncmp(bname, "pass", 4))
		ok = true;
	else if (!strncmp(bname, "fail", 4))
		ok = false;
	else
		tap_xbail_out("invalid pathname `%s' (base:`%s')"
			      "(must start either with `pass' or `fail')",
			      pathname, bname);
	free(bname);

	fp = fopen(pathname, "r");
	if (!fp)
		tap_xbail_out("can't open pathname `%s' (errno:%d %s)",
			      pathname, errno, strerror(errno));

	for (;; ++i) {
		c = fgetc(fp);
		if (c == EOF) {
			fclose(fp);
			break;
		}
		if (!JSON_parser_char(jp, c)) {
			if (!ok) {
				tap_ok("%s: invalid JSON", pathname);
				return EXIT_SUCCESS;
			}
			tap_not_ok("%s: byte %u, char:%#x: %s",
				   pathname, i, (unsigned)c,
				   JSON_strerror(JSON_parser_get_last_error(jp)));
			return EXIT_FAILURE;
		}
	}

	if (!JSON_parser_done(jp)) {
		if (!ok) {
			tap_ok("%s -> invalid", pathname);
			return EXIT_SUCCESS;
		}
		tap_not_ok("%s: valid JSON didn't parse", pathname);
		return EXIT_FAILURE;
	}

	if (ok) {
		tap_ok("%s -> valid", pathname);
		return EXIT_SUCCESS;
	}
	tap_not_ok("%s: invalid JSON parsed!", pathname);
	return EXIT_FAILURE;
}

#if 0
static void json_reset(JSON_parser jp)
{
	JSON_parser_reset(jp);
}
#endif

int main(int argc, char **argv)
{
	int r;
	const char *pathname;
	JSON_parser jp;

	if (argc != 2) {
		/* tap_plan("JSON_parser"); */
		tap_xbail_out("usage: ./jsontest <path> <count>");
	}

	pathname = argv[1];
	if (getenv("json_parser_round"))
		tap_test_count = atoi(getenv("json_parser_round"));

	jp = json_init();
	r = json_parse(jp, pathname);

	/* tap_plan("JSON_parser `%s'", pathname); */
	return r;
}
