/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>

int
main(int argc, char **argv)
{
	struct timeval times[2];

	if (argc < 2)
		return 125;

	times[0].tv_sec = times[1].tv_sec = 0;
	times[0].tv_usec = times[1].tv_usec = 0;

	if (utimes(argv[1], times) < 0) {
		if (getenv("SYDBOX_TEST_SUCCESS")) {
			perror(__FILE__);
			return 1;
		}
		else if (getenv("SYDBOX_TEST_EPERM") && errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	return getenv("SYDBOX_TEST_SUCCESS") ? 0 : 2;
}
