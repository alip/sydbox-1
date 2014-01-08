/*
 * sydbox/magic-cmd.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <pinktrace/pink.h>

#include "log.h"
#include "proc.h"
#include "util.h"
#include "xfunc.h"

/*
 * Convert errno's which execve() doesn't set to a valid errno to avoid
 * confusion.
 */
static inline int execve_errno(int err_no)
{
	switch (err_no) {
	case EAGAIN: /* fork() */
	case ECHILD: /* waitpid() */
		return EACCES;
	default:
		return err_no;
	}
}

static void free_argv(char **argv)
{
	if (argv) {
		for (unsigned i = 0; i < ELEMENTSOF(argv); i++)
			if (argv[i])
				free(argv[i]);
		free(argv);
	}
}

int magic_cmd_exec(const void *val, syd_process_t *current)
{
	int r = MAGIC_RET_OK;
	unsigned i, j, k;
	const char *args = val;
	char **argv = NULL;

	assert(val);

	if (current == NULL)
		return MAGIC_RET_INVALID_OPERATION;

	/* Step 1: args -> argv[] */
	i = 0;
	argv = xmalloc(sizeof(char *) * i+2);
	argv[i] = xmalloc(sizeof(char) * MAX_ARG_STRLEN);
	argv[i][0] = '\0';
	argv[i+1] = NULL;
	for (j = 0, k = 0; args[j] != '\0'; j++) {
		if (j >= MAX_ARG_STRLEN) {
			r = -E2BIG;
			goto out;
		}
		if (args[j] == 037) { /* end of unit */
			i++;
			if (i+2 >= MAX_ARG_STRINGS) {
				r = -E2BIG;
				goto out;
			}
			argv = xrealloc(argv, sizeof(char *) * (i+2));
			argv[i] = xmalloc(sizeof(char) * MAX_ARG_STRLEN);
			argv[i][0] = '\0';
			argv[i+1] = NULL;
			k = 0;
		} else {
			argv[i][k++] = args[j];
		}
	}

	/*
	 * Step 2: fork, set the environment and execute the process
	 */
	pid_t childpid;
	int err_no, status;

	childpid = fork();
	if (childpid < 0) {
		err_no = execve_errno(errno);
		log_magic("fork failed (errno:%d %s)", errno, strerror(errno));
		r = deny(current, err_no);
		return r;
	} else if (childpid == 0) {
		if (clearenv() != 0)
			_exit(ENOMEM);
		if (proc_environ(current->pid) < 0)
			_exit(errno);
		if (chdir(P_CWD(current)) < 0)
			_exit(errno);
		if (pink_trace_me() < 0)
			_exit(errno);
		execvp(argv[0], argv);
		_exit(errno);
	}

	if (waitpid_nointr(childpid, &status, 0) < 0) {
		err_no = execve_errno(errno);
		log_magic("exec(`%s'): waitpid(%u) failed (errno:%d %s)",
			  argv[0], childpid, errno, strerror(errno));
		r = -err_no;
		goto out;
	}
	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		log_magic("exec(`%s') successful, detaching from pid:%u",
			  argv[0], childpid);
		if (pink_trace_detach(childpid, 0) < 0)
			log_magic("detach from pid:%u failed (errno:%d %s)",
				  childpid, errno, strerror(errno));
		r = 0;
	} else if (WIFEXITED(status)) {
		err_no = WEXITSTATUS(status);
		log_magic("exec(`%s') failed (errno:%d %s)", argv[0],
			  err_no, strerror(err_no));
		r = -err_no;
	} else if (WIFSIGNALED(status)) {
		log_magic("exec(`%s') terminated (signal:%d)", argv[0],
			  WTERMSIG(status));
		log_magic("sending signal:%d to %s[%u]", WTERMSIG(status),
			  P_COMM(current), current->pid);
		pink_trace_kill(current->pid, current->ppid, WTERMSIG(status));
		r = MAGIC_RET_PROCESS_TERMINATED;
	} else {
		log_magic("exec(`%s') unknown status:0x%04x pid:%u", argv[0],
			  status, childpid);
		r = -ENOEXEC;
	}

out:
	free_argv(argv);

	return r;
}
