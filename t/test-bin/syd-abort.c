#include "headers.h"

int main(int argc, char *argv[])
{
	int s;
	pid_t p;

	s = atoi(argv[1]);
	p = getpid();
	errno = 0;

	kill(p, s);

	return errno;
}
