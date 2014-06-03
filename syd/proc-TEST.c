/*
 * libsyd/proc-TEST.c
 *
 * proc utility tests
 *
 * Copyright (c) 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "check.h"

static void test_proc_comm(void)
{
	pid_t pid;
	char comm_real[] = "check-pause";

	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execl("./check-pause", comm_real, (char *)NULL);
		_exit(1);
	} else {
		pid_t cpid = -1;
		int r, pfd, status;
		char comm[sizeof(comm_real)];
		char comm_trunc[sizeof(comm_real) - 2];
		size_t comm_len = sizeof(comm_real);
		size_t comm_trunc_len = sizeof(comm_real) - 2;

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		pfd = syd_proc_open(cpid);
		if (pfd < 0) {
			fail_msg("syd_proc_open failed: errno:%d %s", errno, strerror(errno));
		} else {
			r = syd_proc_comm(pfd, comm, comm_len);
			if (r < 0)
				fail_msg("syd_proc_comm failed: %d %s", errno, strerror(errno));
			else if ((r = strcmp(comm, comm_real)) != 0)
				fail_msg("comm: strcmp('%s', '%s') = %d", comm, comm_real, r);

			r = syd_proc_comm(pfd, comm_trunc, comm_trunc_len);
			if (r < 0)
				fail_msg("syd_proc_comm failed (trunc): %d %s", errno, strerror(errno));
			else if ((r = strncmp(comm_trunc, comm_real, comm_trunc_len - 1)) != 0)
				fail_msg("comm: strncmp('%s', '%s', %zu) = %d", comm_trunc, comm_real, comm_trunc_len - 1, r);
			else if (comm_trunc[comm_trunc_len - 1] != '\0')
				fail_msg("comm: truncated '%s' not null-terminated: '%c'", comm_trunc, comm_trunc[comm_trunc_len - 1]);
		}
		kill(cpid, SIGKILL);
	}
}

static void test_proc_cmdline(void)
{
	pid_t pid;
	char *const argv[] = {"check-pause", "arg1", "arg2", "arg3", NULL};

	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execv("./check-pause", argv);
		_exit(1);
	} else {
		pid_t cpid = -1;
		int r, pfd, status;
		char cmdline_orig[] = "check-pause arg1 arg2 arg3";
		char cmdline_trunc1_orig[] = "check-pause arg1 arg2 ar";
		char cmdline_trunc2_orig[] = "check-pause arg1 arg2 a";
		char cmdline[sizeof(cmdline_orig)];
		char cmdline_trunc1[sizeof(cmdline_trunc1_orig)];
		char cmdline_trunc2[sizeof(cmdline_trunc2_orig)];

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		pfd = syd_proc_open(cpid);
		if (pfd < 0) {
			fail_msg("syd_proc_open failed: errno:%d %s", errno, strerror(errno));
		} else {
			r = syd_proc_cmdline(pfd, cmdline, sizeof(cmdline));
			if (r < 0)
				fail_msg("syd_proc_cmdline failed: %d %s", errno, strerror(errno));
			else if ((r = strcmp(cmdline, cmdline_orig)) != 0)
				fail_msg("cmdline: strcmp('%s', '%s') = %d", cmdline, cmdline_orig, r);

			r = syd_proc_cmdline(pfd, cmdline_trunc1, sizeof(cmdline) - 2);
			if (r < 0)
				fail_msg("syd_proc_cmdline (trunc1) failed: %d %s", errno, strerror(errno));
			else if ((r = strcmp(cmdline_trunc1, cmdline_trunc1_orig)) != 0)
				fail_msg("cmdline: (trunc1) strcmp('%s', '%s') = %d", cmdline_trunc1, cmdline_trunc1_orig, r);

			r = syd_proc_cmdline(pfd, cmdline_trunc2, sizeof(cmdline) - 3);
			if (r < 0)
				fail_msg("syd_proc_cmdline (trunc2) failed: %d %s", errno, strerror(errno));
			else if ((r = strcmp(cmdline_trunc2, cmdline_trunc2_orig)) != 0)
				fail_msg("cmdline: (trunc2) strcmp('%s', '%s') = %d", cmdline_trunc2, cmdline_trunc2_orig, r);
		}
		kill(cpid, SIGKILL);
	}
}
static void test_fixture_proc(void)
{
	test_fixture_start();

	run_test(test_proc_comm);
	run_test(test_proc_cmdline);

	test_fixture_end();
}

void test_suite_proc(void)
{
	test_fixture_proc();
}
