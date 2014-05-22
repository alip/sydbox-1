/*
 * sydbox/sydbox.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#ifndef SYDBOX_GUARD_SYDBOX_H
#define SYDBOX_GUARD_SYDBOX_H 1

#include "sydconf.h"

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE 1
#endif /* !_ATFILE_SOURCE */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <sched.h>
#include "pink.h"
#include "acl-queue.h"
#include "sockmatch.h"
#include "sockmap.h"
#include "util.h"
#include "xfunc.h"

/* Definitions */
#ifdef KERNEL_VERSION
#undef KERNEL_VERSION
#endif
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

#define strbool(arg)	((arg) ? "yes" : "no")

/* Process flags */
#define SYD_STARTUP		00001 /* process attached, needs to be set up */
#define SYD_IGNORE_ONE_SIGSTOP	00002 /* initial sigstop is to be ignored */
#define SYD_READY		00004 /* process' sandbox is initialised */
#define SYD_IN_SYSCALL		00010 /* process is in system call */
#define SYD_DENY_SYSCALL	00020 /* system call is to be denied */
#define SYD_STOP_AT_SYSEXIT	00040 /* seccomp: stop at system call exit */
#define SYD_WAIT_FOR_CHILD	00100 /* parent waiting for child notification */
#define SYD_WAIT_FOR_PARENT	00200 /* child waiting for parent notification */
#define SYD_SYDBOX_CHILD	00400 /* process is the child exec()'ed by sydbox */

#define SYD_PPID_NONE		0      /* no parent PID (yet) */
#define SYD_PPID_ORPHAN		-0xbad /* special parent process id for orphans */

/* Type declarations */
enum sandbox_mode {
	SANDBOX_OFF,
	SANDBOX_ALLOW,
	SANDBOX_DENY,
};
static const char *const sandbox_mode_table[] = {
	[SANDBOX_OFF] = "off",
	[SANDBOX_DENY] = "deny",
	[SANDBOX_ALLOW] = "allow",
};
DEFINE_STRING_TABLE_LOOKUP(sandbox_mode, int)

enum lock_state {
	LOCK_UNSET,
	LOCK_SET,
	LOCK_PENDING,
};
static const char *const lock_state_table[] = {
	[LOCK_UNSET] = "off",
	[LOCK_SET] = "on",
	[LOCK_PENDING] = "exec",
};
DEFINE_STRING_TABLE_LOOKUP(lock_state, int)

enum abort_decision {
	ABORT_KILLALL,
	ABORT_CONTALL,
};
static const char *const abort_decision_table[] = {
	[ABORT_KILLALL] = "killall",
	[ABORT_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(abort_decision, int)

enum panic_decision {
	PANIC_KILL,
	PANIC_CONT,
	PANIC_CONTALL,
	PANIC_KILLALL,
};
static const char *const panic_decision_table[] = {
	[PANIC_KILL] = "kill",
	[PANIC_CONT] = "cont",
	[PANIC_CONTALL] = "contall",
	[PANIC_KILLALL] = "killall",
};
DEFINE_STRING_TABLE_LOOKUP(panic_decision, int)

enum violation_decision {
	VIOLATION_DENY,
	VIOLATION_KILL,
	VIOLATION_KILLALL,
	VIOLATION_CONT,
	VIOLATION_CONTALL,
};
static const char *const violation_decision_table[] = {
	[VIOLATION_DENY] = "deny",
	[VIOLATION_KILL] = "kill",
	[VIOLATION_KILLALL] = "killall",
	[VIOLATION_CONT] = "cont",
	[VIOLATION_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(violation_decision, int)

enum magic_op {
	MAGIC_OP_SET,
	MAGIC_OP_APPEND,
	MAGIC_OP_REMOVE,
	MAGIC_OP_QUERY,
	MAGIC_OP_EXEC,
};

enum magic_type {
	MAGIC_TYPE_NONE,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_INTEGER,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,
	MAGIC_TYPE_COMMAND,

	MAGIC_TYPE_INVALID,
};

enum magic_key {
	MAGIC_KEY_NONE,

	MAGIC_KEY_VERSION,

	MAGIC_KEY_CORE,

	MAGIC_KEY_CORE_MATCH,
	MAGIC_KEY_CORE_MATCH_CASE_SENSITIVE,
	MAGIC_KEY_CORE_MATCH_NO_WILDCARD,

	MAGIC_KEY_CORE_SANDBOX,
	MAGIC_KEY_CORE_SANDBOX_EXEC,
	MAGIC_KEY_CORE_SANDBOX_READ,
	MAGIC_KEY_CORE_SANDBOX_WRITE,
	MAGIC_KEY_CORE_SANDBOX_NETWORK,

	MAGIC_KEY_CORE_RESTRICT,
	MAGIC_KEY_CORE_RESTRICT_FILE_CONTROL,
	MAGIC_KEY_CORE_RESTRICT_SHARED_MEMORY_WRITABLE,

	MAGIC_KEY_CORE_WHITELIST,
	MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES,
	MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND,
	MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES,

	MAGIC_KEY_CORE_ABORT,
	MAGIC_KEY_CORE_ABORT_DECISION,

	MAGIC_KEY_CORE_PANIC,
	MAGIC_KEY_CORE_PANIC_DECISION,
	MAGIC_KEY_CORE_PANIC_EXIT_CODE,

	MAGIC_KEY_CORE_VIOLATION,
	MAGIC_KEY_CORE_VIOLATION_DECISION,
	MAGIC_KEY_CORE_VIOLATION_EXIT_CODE,
	MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL,
	MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE,

	MAGIC_KEY_CORE_TRACE,
	MAGIC_KEY_CORE_TRACE_FOLLOW_FORK,
	MAGIC_KEY_CORE_TRACE_EXIT_KILL,
	MAGIC_KEY_CORE_TRACE_MAGIC_LOCK,
	MAGIC_KEY_CORE_TRACE_INTERRUPT,
	MAGIC_KEY_CORE_TRACE_USE_SECCOMP,
	MAGIC_KEY_CORE_TRACE_USE_SEIZE,
	MAGIC_KEY_CORE_TRACE_USE_TOOLONG_HACK,

	MAGIC_KEY_LOG,
	MAGIC_KEY_LOG_FILE,
	MAGIC_KEY_LOG_LEVEL,
	MAGIC_KEY_LOG_CONSOLE_FD,
	MAGIC_KEY_LOG_CONSOLE_LEVEL,

	MAGIC_KEY_EXEC,
	MAGIC_KEY_EXEC_KILL_IF_MATCH,
	MAGIC_KEY_EXEC_RESUME_IF_MATCH,

	MAGIC_KEY_WHITELIST,
	MAGIC_KEY_WHITELIST_EXEC,
	MAGIC_KEY_WHITELIST_READ,
	MAGIC_KEY_WHITELIST_WRITE,
	MAGIC_KEY_WHITELIST_NETWORK,
	MAGIC_KEY_WHITELIST_NETWORK_BIND,
	MAGIC_KEY_WHITELIST_NETWORK_CONNECT,

	MAGIC_KEY_BLACKLIST,
	MAGIC_KEY_BLACKLIST_EXEC,
	MAGIC_KEY_BLACKLIST_READ,
	MAGIC_KEY_BLACKLIST_WRITE,
	MAGIC_KEY_BLACKLIST_NETWORK,
	MAGIC_KEY_BLACKLIST_NETWORK_BIND,
	MAGIC_KEY_BLACKLIST_NETWORK_CONNECT,

	MAGIC_KEY_FILTER,
	MAGIC_KEY_FILTER_EXEC,
	MAGIC_KEY_FILTER_READ,
	MAGIC_KEY_FILTER_WRITE,
	MAGIC_KEY_FILTER_NETWORK,

	MAGIC_KEY_CMD,
	MAGIC_KEY_CMD_EXEC,

	MAGIC_KEY_INVALID,
};

enum magic_ret {
	MAGIC_RET_NOOP = 1,
	MAGIC_RET_OK,
	MAGIC_RET_TRUE,
	MAGIC_RET_FALSE,
	MAGIC_RET_ERROR_0,
	MAGIC_RET_NOT_SUPPORTED,
	MAGIC_RET_INVALID_KEY,
	MAGIC_RET_INVALID_TYPE,
	MAGIC_RET_INVALID_VALUE,
	MAGIC_RET_INVALID_QUERY,
	MAGIC_RET_INVALID_COMMAND,
	MAGIC_RET_INVALID_OPERATION,
	MAGIC_RET_NOPERM,
	MAGIC_RET_OOM,
	MAGIC_RET_PROCESS_TERMINATED,
};

#define MAGIC_BOOL(b)	((b) ? MAGIC_RET_TRUE : MAGIC_RET_FALSE)
#define MAGIC_ERROR(r)	((r) < 0 || (r) >= MAGIC_RET_ERROR_0)

enum syd_stat {
	SYD_STAT_NONE = 0, /* no stat() information necessary */
	SYD_STAT_LSTAT = 1, /* call lstat() instead of stat() */
	SYD_STAT_NOEXIST = 2, /* EEXIST */
	SYD_STAT_ISDIR = 4, /* ENOTDIR */
	SYD_STAT_NOTDIR = 8, /* EISDIR */
	SYD_STAT_NOFOLLOW = 16, /* ELOOP */
	SYD_STAT_EMPTYDIR = 32, /* ENOTDIR or ENOTEMPTY */
};

enum sys_access_mode {
	ACCESS_0,
	ACCESS_WHITELIST,
	ACCESS_BLACKLIST
};
static const char *const sys_access_mode_table[] = {
	[ACCESS_0]         = "0",
	[ACCESS_WHITELIST] = "whitelist",
	[ACCESS_BLACKLIST] = "blacklist"
};
DEFINE_STRING_TABLE_LOOKUP(sys_access_mode, int)

enum syd_step {
	SYD_STEP_NOT_SET,	/**< Special value indicating to use default. */
	SYD_STEP_SYSCALL,	/**< Step with pink_trace_syscall() */
	SYD_STEP_RESUME,	/**< Step with pink_trace_resume() */
};

typedef struct {
	enum sandbox_mode sandbox_exec;
	enum sandbox_mode sandbox_read;
	enum sandbox_mode sandbox_write;
	enum sandbox_mode sandbox_network;

	enum lock_state magic_lock;

	aclq_t acl_exec;
	aclq_t acl_read;
	aclq_t acl_write;
	aclq_t acl_network_bind;
	aclq_t acl_network_connect;
} sandbox_t;

/* process information */
typedef struct syd_process {
	/* Process/Thread ID */
	pid_t pid;

	/* Parent process ID */
	pid_t ppid;

	/* Clone process ID */
	pid_t cpid;

	/* Process registry set */
	struct pink_regset *regset;

	/* System call ABI */
	short abi;

	/* SYD_* flags */
	short flags;

	/* Stepping method */
	enum syd_step trace_step;

	/* Last system call */
	unsigned long sysnum;

	/* Last system call name */
	const char *sysname;

	/* Arguments of last system call */
	long args[PINK_MAX_ARGS];

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;

	/* Last (socket) subcall */
	long subcall;

	/* Denied system call will return this value */
	long retval;

	/* clone(2) flags used to spawn *this* thread */
	unsigned long clone_flags;

	/* Last clone(2) flags (used to spawn a *new* thread) */
	unsigned long new_clone_flags;

	/* Per-thread shared data */
	struct syd_process_shared {
		struct syd_process_shared_clone_thread {
			/* Process name:
			 * - Read from /proc/$pid/comm for initial process
			 * - Updated after successful execve()
			 */
			char *comm;
#define			P_COMM(p) ((p)->shm.clone_thread->comm)

			/* Per-process sandbox */
			sandbox_t *box;
#define			P_BOX(p) ((p)->shm.clone_thread->box)

			/* Reference count */
			unsigned refcnt;
#define			P_CLONE_THREAD_REFCNT(p) ((p)->shm.clone_thread->refcnt)
#define			P_CLONE_THREAD_RETAIN(p) ((p)->shm.clone_thread->refcnt++)
#define			P_CLONE_THREAD_RELEASE(p) \
			do { \
				(p)->shm.clone_thread->refcnt--; \
				if ((p)->shm.clone_thread->refcnt == 0) { \
					if ((p)->shm.clone_thread->comm) { \
						free((p)->shm.clone_thread->comm); \
					} \
					if ((p)->shm.clone_thread->box) { \
						free_sandbox((p)->shm.clone_thread->box); \
					} \
					free((p)->shm.clone_thread); \
					(p)->shm.clone_thread = NULL; \
				} \
			} while (0)
		} *clone_thread;

		/* Shared items when CLONE_FS is set. */
		struct syd_process_shared_clone_fs {
			/* Current working directory */
			char *cwd;
#define			P_CWD(p) ((p)->shm.clone_fs->cwd)

			/* Reference count */
			unsigned refcnt;
#define			P_CLONE_FS_REFCNT(p) ((p)->shm.clone_fs->refcnt)
#define			P_CLONE_FS_RETAIN(p) ((p)->shm.clone_fs->refcnt++)
#define			P_CLONE_FS_RELEASE(p) \
			do { \
				(p)->shm.clone_fs->refcnt--; \
				if ((p)->shm.clone_fs->refcnt == 0) { \
					if ((p)->shm.clone_fs->cwd) { \
						free((p)->shm.clone_fs->cwd); \
					} \
					free((p)->shm.clone_fs); \
					(p)->shm.clone_fs = NULL; \
				} \
			} while (0)
		} *clone_fs;

		/* Shared items when CLONE_FILES is set. */
		struct syd_process_shared_clone_files {
			/*
			 * Last bind(2) address with port argument zero
			 */
			struct sockinfo *savebind;
#define			P_SAVEBIND(p) ((p)->shm.clone_files->savebind)

			/*
			 * File descriptor mappings for savebind
			 */
			struct sockmap *sockmap;
#define			P_SOCKMAP(p) ((p)->shm.clone_files->sockmap)

			/* Reference count */
			unsigned refcnt;
#define			P_CLONE_FILES_REFCNT(p) ((p)->shm.clone_files->refcnt)
#define			P_CLONE_FILES_RETAIN(p) ((p)->shm.clone_files->refcnt++)
#define			P_CLONE_FILES_RELEASE(p) \
			do { \
				(p)->shm.clone_files->refcnt--; \
				if ((p)->shm.clone_files->refcnt == 0) { \
					if ((p)->shm.clone_files->savebind) { \
						free_sockinfo((p)->shm.clone_files->savebind); \
					} \
					if ((p)->shm.clone_files->sockmap) { \
						sockmap_destroy(&(p)->shm.clone_files->sockmap); \
						free((p)->shm.clone_files->sockmap); \
					} \
					free((p)->shm.clone_files); \
					(p)->shm.clone_files = NULL; \
				} \
			} while (0)
		} *clone_files;
	} shm;

	/* Process hash table via sydbox->proctab */
	UT_hash_handle hh;
} syd_process_t;

typedef struct {
	/* magic access to core.*  */
	bool magic_core_allow;

	/* Per-process sandboxing data */
	sandbox_t box_static;

	/* Non-inherited, "global" configuration data */
	bool restrict_file_control;
	bool restrict_shared_memory_writable;

	bool whitelist_per_process_directories;
	bool whitelist_successful_bind;
	bool whitelist_unsupported_socket_families;

	enum abort_decision abort_decision;

	enum panic_decision panic_decision;
	int panic_exit_code;

	enum violation_decision violation_decision;
	int violation_exit_code;
	bool violation_raise_fail;
	bool violation_raise_safe;

	bool follow_fork;
	bool exit_kill;
	bool use_seccomp;
	bool use_seize;
	bool use_toolong_hack;

	char *log_file;

	aclq_t exec_kill_if_match;
	aclq_t exec_resume_if_match;

	aclq_t filter_exec;
	aclq_t filter_read;
	aclq_t filter_write;
	aclq_t filter_network;

	aclq_t acl_network_connect_auto;
} config_t;

typedef struct {
	syd_process_t *proctab;

	syd_process_t *current_clone_proc;

	int trace_options;
	enum syd_step trace_step;

	bool wait_execve;
	int exit_code;

	/* This is true if an access violation has occured, false otherwise. */
	bool violation;

	/* Program invocation name (for the child) */
	char *program_invocation_name;

	/* Global configuration */
	config_t config;
} sydbox_t;

typedef int (*sysfunc_t) (syd_process_t *current);
typedef int (*sysfilter_t) (int arch, uint32_t sysnum);

typedef struct {
	const char *name;
	long no; /* Used only if `name' is NULL.
		  * May be used to implement virtual system calls.
		  */
	sysfunc_t enter;
	sysfunc_t exit;

	/* Apply a simple seccomp filter (bpf-only, no ptrace) */
	sysfilter_t filter;
	/*
	 * Are ".enter" and ".exit" members ptrace fallbacks when seccomp
	 * support is not available or do they have to be called anyway?
	 */
	bool ptrace_fallback;
} sysentry_t;

typedef struct {
	/* Argument index */
	unsigned arg_index;

	/* `at' suffixed function */
	bool at_func;

	/* NULL argument does not cause -EFAULT (only valid for `at_func') */
	bool null_ok;
	/* Mode for realpath_mode() */
	unsigned rmode;
	/* Stat mode */
	enum syd_stat syd_mode;

	/* Decode socketcall() into subcall */
	bool decode_socketcall;

	/* Safe system call, deny silently (w/o raising access violation) */
	bool safe;
	/* Deny errno */
	int deny_errno;

	/* Access control mode (whitelist, blacklist) */
	enum sys_access_mode access_mode;
	/* Access control lists (per-process, global) */
	aclq_t *access_list;
	aclq_t *access_list_global;
	/* Access filter lists (only global) */
	aclq_t *access_filter;

	/* Pointer to the data to be returned */
	int *ret_fd;
	char **ret_abspath;
	struct stat *ret_statbuf;
	struct pink_sockaddr **ret_addr;

	/* Cached data (to be reused by another sandboxing (read,write etc.) */
	const char *cache_abspath;
	const struct stat *cache_statbuf;
} sysinfo_t;

/* Global variables */
extern sydbox_t *sydbox;

#define entering(p) (!((p)->flags & SYD_IN_SYSCALL))
#define exiting(p) ((p)->flags & SYD_IN_SYSCALL)
#define sysdeny(p) ((p)->flags & SYD_DENY_SYSCALL)
#define sydchild(p) ((p)->flags & SYD_SYDBOX_CHILD)
#define hasparent(p) ((p)->ppid >= 0)

#define sandbox_allow(p, box) (!!(P_BOX(p)->sandbox_ ## box == SANDBOX_ALLOW))
#define sandbox_deny(p, box) (!!(P_BOX(p)->sandbox_ ## box == SANDBOX_DENY))
#define sandbox_off(p, box) (!!(P_BOX(p)->sandbox_ ## box == SANDBOX_OFF))

#define sandbox_allow_exec(p) (sandbox_allow((p), exec))
#define sandbox_allow_read(p) (sandbox_allow((p), read))
#define sandbox_allow_write(p) (sandbox_allow((p), write))
#define sandbox_allow_network(p) (sandbox_allow((p), network))
#define sandbox_allow_file(p) (sandbox_allow_exec((p)) && sandbox_allow_read((p)) && sandbox_allow_write((p)))

#define sandbox_off_exec(p) (sandbox_off((p), exec))
#define sandbox_off_read(p) (sandbox_off((p), read))
#define sandbox_off_write(p) (sandbox_off((p), write))
#define sandbox_off_network(p) (sandbox_off((p), network))
#define sandbox_off_file(p) (sandbox_off_exec((p)) && sandbox_off_read((p)) && sandbox_off_write((p)))

#define sandbox_deny_exec(p) (sandbox_deny((p), exec))
#define sandbox_deny_read(p) (sandbox_deny((p), read))
#define sandbox_deny_write(p) (sandbox_deny((p), write))
#define sandbox_deny_network(p) (sandbox_deny((p), network))
#define sandbox_deny_file(p) (sandbox_deny_exec((p)) && sandbox_deny_read((p)) && sandbox_deny_write((p)))

#define process_count() HASH_COUNT(sydbox->proctab)
#define process_iter(p, tmp) HASH_ITER(hh, sydbox->proctab, (p), (tmp))
#define process_add(p) HASH_ADD(hh, sydbox->proctab, pid, sizeof(pid_t), (p))
#define process_remove(p) HASH_DEL(sydbox->proctab, (p))

/* Global functions */
int syd_trace_step(syd_process_t *current, int sig);
int syd_trace_listen(syd_process_t *current);
int syd_trace_detach(syd_process_t *current, int sig);
int syd_trace_kill(syd_process_t *current, int sig);
int syd_trace_setup(syd_process_t *current);
int syd_trace_geteventmsg(syd_process_t *current, unsigned long *data);
int syd_regset_fill(syd_process_t *current);
int syd_read_syscall(syd_process_t *current, long *sysnum);
int syd_read_retval(syd_process_t *current, long *retval, int *error);
int syd_read_argument(syd_process_t *current, unsigned arg_index, long *argval);
int syd_read_argument_int(syd_process_t *current, unsigned arg_index, int *argval);
ssize_t syd_read_string(syd_process_t *current, long addr, char *dest, size_t len);
int syd_write_syscall(syd_process_t *current, long sysnum);
int syd_write_retval(syd_process_t *current, long retval, int error);
int syd_read_socket_argument(syd_process_t *current, bool decode_socketcall,
			     unsigned arg_index, unsigned long *argval);
int syd_read_socket_subcall(syd_process_t *current, bool decode_socketcall,
			    long *subcall);
int syd_read_socket_address(syd_process_t *current, bool decode_socketcall,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr);

void reset_process(syd_process_t *p);
void free_process(syd_process_t *p);
void remove_process(syd_process_t *p);

static inline syd_process_t *lookup_process(pid_t pid)
{
	syd_process_t *process;

	HASH_FIND(hh, sydbox->proctab, &pid, sizeof(pid_t), process);
	return process;
}

void cont_all(void);
void abort_all(int fatal_sig);
int deny(syd_process_t *current, int err_no);
int restore(syd_process_t *current);
int panic(syd_process_t *current);
int violation(syd_process_t *current, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 2, 3)));

void config_init(void);
void config_done(void);
void config_parse_file(const char *filename) PINK_GCC_ATTR((nonnull(1)));
void config_parse_spec(const char *filename) PINK_GCC_ATTR((nonnull(1)));

void callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		     unsigned rmode, char **res);
int box_check_path(syd_process_t *current, sysinfo_t *info);
int box_check_socket(syd_process_t *current, sysinfo_t *info);

static inline sandbox_t *box_current(syd_process_t *current)
{
	return current ? P_BOX(current) : &sydbox->config.box_static;
}

static inline void init_sandbox(sandbox_t *box)
{
	box->sandbox_exec = SANDBOX_OFF;
	box->sandbox_read = SANDBOX_OFF;
	box->sandbox_write = SANDBOX_OFF;
	box->sandbox_network = SANDBOX_OFF;

	box->magic_lock = LOCK_UNSET;

	ACLQ_INIT(&box->acl_exec);
	ACLQ_INIT(&box->acl_read);
	ACLQ_INIT(&box->acl_write);
	ACLQ_INIT(&box->acl_network_bind);
	ACLQ_INIT(&box->acl_network_connect);
}

static inline void copy_sandbox(sandbox_t *box_dest, sandbox_t *box_src)
{
	struct acl_node *node, *newnode;

	if (!box_src)
		return;

	assert(box_dest);

	box_dest->sandbox_exec = box_src->sandbox_exec;
	box_dest->sandbox_read = box_src->sandbox_read;
	box_dest->sandbox_write = box_src->sandbox_write;
	box_dest->sandbox_network = box_src->sandbox_network;

	box_dest->magic_lock = box_src->magic_lock;

	ACLQ_COPY(node, &box_src->acl_exec, &box_dest->acl_exec, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_read, &box_dest->acl_read, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_write, &box_dest->acl_write, newnode, xstrdup);
	ACLQ_COPY(node, &box_src->acl_network_bind, &box_dest->acl_network_bind, newnode, sockmatch_xdup);
	ACLQ_COPY(node, &box_src->acl_network_connect, &box_dest->acl_network_connect, newnode, sockmatch_xdup);
}

static inline void reset_sandbox(sandbox_t *box)
{
	struct acl_node *node;

	ACLQ_RESET(node, &box->acl_exec, free);
	ACLQ_RESET(node, &box->acl_read, free);
	ACLQ_RESET(node, &box->acl_write, free);
	ACLQ_RESET(node, &box->acl_network_bind, free_sockmatch);
	ACLQ_RESET(node, &box->acl_network_connect, free_sockmatch);
}

static inline int new_sandbox(sandbox_t **box_ptr)
{
	sandbox_t *box;

	box = malloc(sizeof(sandbox_t));
	if (!box)
		return -errno;
	init_sandbox(box);

	*box_ptr = box;
	return 0;
}

static inline void free_sandbox(sandbox_t *box)
{
	reset_sandbox(box);
	free(box);
}

void systable_init(void);
void systable_free(void);
void systable_add_full(long no, short abi, const char *name,
		       sysfunc_t fenter, sysfunc_t fexit);
void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit);
const sysentry_t *systable_lookup(long no, short abi);

size_t syscall_entries_max(void);
void sysinit(void);
int sysinit_seccomp(void);
int sysenter(syd_process_t *current);
int sysexit(syd_process_t *current);

enum magic_ret magic_check_call(int rval);
const char *magic_strerror(int error);
const char *magic_strkey(enum magic_key key);
unsigned magic_key_type(enum magic_key key);
unsigned magic_key_parent(enum magic_key key);
unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len);
int magic_cast(syd_process_t *current, enum magic_op op, enum magic_key key,
	       const void *val);
int magic_cast_string(syd_process_t *current, const char *magic, int prefix);

int magic_set_panic_exit_code(const void *val, syd_process_t *current);
int magic_set_violation_exit_code(const void *val, syd_process_t *current);
int magic_set_violation_raise_fail(const void *val, syd_process_t *current);
int magic_query_violation_raise_fail(syd_process_t *current);
int magic_set_violation_raise_safe(const void *val, syd_process_t *current);
int magic_query_violation_raise_safe(syd_process_t *current);
int magic_set_trace_follow_fork(const void *val, syd_process_t *current);
int magic_query_trace_follow_fork(syd_process_t *current);
int magic_set_trace_exit_kill(const void *val, syd_process_t *current);
int magic_query_trace_exit_kill(syd_process_t *current);
int magic_set_trace_use_seccomp(const void *val, syd_process_t *current);
int magic_query_trace_use_seccomp(syd_process_t *current);
int magic_set_trace_use_seize(const void *val, syd_process_t *current);
int magic_query_trace_use_seize(syd_process_t *current);
int magic_set_trace_use_toolong_hack(const void *val, syd_process_t *current);
int magic_query_trace_use_toolong_hack(syd_process_t *current);
int magic_set_restrict_fcntl(const void *val, syd_process_t *current);
int magic_query_restrict_fcntl(syd_process_t *current);
int magic_set_restrict_shm_wr(const void *val, syd_process_t *current);
int magic_query_restrict_shm_wr(syd_process_t *current);
int magic_set_whitelist_ppd(const void *val, syd_process_t *current);
int magic_query_whitelist_ppd(syd_process_t *current);
int magic_set_whitelist_sb(const void *val, syd_process_t *current);
int magic_query_whitelist_sb(syd_process_t *current);
int magic_set_whitelist_usf(const void *val, syd_process_t *current);
int magic_query_whitelist_usf(syd_process_t *current);
int magic_append_whitelist_exec(const void *val, syd_process_t *current);
int magic_remove_whitelist_exec(const void *val, syd_process_t *current);
int magic_append_whitelist_read(const void *val, syd_process_t *current);
int magic_remove_whitelist_read(const void *val, syd_process_t *current);
int magic_append_whitelist_write(const void *val, syd_process_t *current);
int magic_remove_whitelist_write(const void *val, syd_process_t *current);
int magic_append_blacklist_exec(const void *val, syd_process_t *current);
int magic_remove_blacklist_exec(const void *val, syd_process_t *current);
int magic_append_blacklist_read(const void *val, syd_process_t *current);
int magic_remove_blacklist_read(const void *val, syd_process_t *current);
int magic_append_blacklist_write(const void *val, syd_process_t *current);
int magic_remove_blacklist_write(const void *val, syd_process_t *current);
int magic_append_filter_exec(const void *val, syd_process_t *current);
int magic_remove_filter_exec(const void *val, syd_process_t *current);
int magic_append_filter_read(const void *val, syd_process_t *current);
int magic_remove_filter_read(const void *val, syd_process_t *current);
int magic_append_filter_write(const void *val, syd_process_t *current);
int magic_remove_filter_write(const void *val, syd_process_t *current);
int magic_append_whitelist_network_bind(const void *val, syd_process_t *current);
int magic_remove_whitelist_network_bind(const void *val, syd_process_t *current);
int magic_append_whitelist_network_connect(const void *val, syd_process_t *current);
int magic_remove_whitelist_network_connect(const void *val, syd_process_t *current);
int magic_append_blacklist_network_bind(const void *val, syd_process_t *current);
int magic_remove_blacklist_network_bind(const void *val, syd_process_t *current);
int magic_append_blacklist_network_connect(const void *val, syd_process_t *current);
int magic_remove_blacklist_network_connect(const void *val, syd_process_t *current);
int magic_append_filter_network(const void *val, syd_process_t *current);
int magic_remove_filter_network(const void *val, syd_process_t *current);
int magic_set_abort_decision(const void *val, syd_process_t *current);
int magic_set_panic_decision(const void *val, syd_process_t *current);
int magic_set_violation_decision(const void *val, syd_process_t *current);
int magic_set_trace_magic_lock(const void *val, syd_process_t *current);
int magic_set_log_file(const void *val, syd_process_t *current);
int magic_set_log_level(const void *val, syd_process_t *current);
int magic_set_log_console_fd(const void *val, syd_process_t *current);
int magic_set_log_console_level(const void *val, syd_process_t *current);
int magic_query_sandbox_exec(syd_process_t *current);
int magic_query_sandbox_read(syd_process_t *current);
int magic_query_sandbox_write(syd_process_t *current);
int magic_query_sandbox_network(syd_process_t *current);
int magic_set_sandbox_exec(const void *val, syd_process_t *current);
int magic_set_sandbox_read(const void *val, syd_process_t *current);
int magic_set_sandbox_write(const void *val, syd_process_t *current);
int magic_set_sandbox_network(const void *val, syd_process_t *current);
int magic_append_exec_kill_if_match(const void *val, syd_process_t *current);
int magic_remove_exec_kill_if_match(const void *val, syd_process_t *current);
int magic_append_exec_resume_if_match(const void *val, syd_process_t *current);
int magic_remove_exec_resume_if_match(const void *val, syd_process_t *current);
int magic_query_match_case_sensitive(syd_process_t *current);
int magic_set_match_case_sensitive(const void *val, syd_process_t *current);
int magic_set_match_no_wildcard(const void *val, syd_process_t *current);

int magic_cmd_exec(const void *val, syd_process_t *current);

static inline void init_sysinfo(sysinfo_t *info)
{
	memset(info, 0, sizeof(sysinfo_t));
}

int filter_open(int arch, uint32_t sysnum);
int filter_openat(int arch, uint32_t sysnum);
int filter_fcntl(int arch, uint32_t sysnum);
int filter_mmap(int arch, uint32_t sysnum);
int sys_fallback_mmap(syd_process_t *current);

int sys_access(syd_process_t *current);
int sys_faccessat(syd_process_t *current);

int sys_chmod(syd_process_t *current);
int sys_fchmodat(syd_process_t *current);
int sys_chown(syd_process_t *current);
int sys_lchown(syd_process_t *current);
int sys_fchownat(syd_process_t *current);
int sys_open(syd_process_t *current);
int sys_openat(syd_process_t *current);
int sys_creat(syd_process_t *current);
int sys_close(syd_process_t *current);
int sysx_close(syd_process_t *current);
int sys_mkdir(syd_process_t *current);
int sys_mkdirat(syd_process_t *current);
int sys_mknod(syd_process_t *current);
int sys_mknodat(syd_process_t *current);
int sys_rmdir(syd_process_t *current);
int sys_truncate(syd_process_t *current);
int sys_mount(syd_process_t *current);
int sys_umount(syd_process_t *current);
int sys_umount2(syd_process_t *current);
int sys_utime(syd_process_t *current);
int sys_utimes(syd_process_t *current);
int sys_utimensat(syd_process_t *current);
int sys_futimesat(syd_process_t *current);
int sys_unlink(syd_process_t *current);
int sys_unlinkat(syd_process_t *current);
int sys_link(syd_process_t *current);
int sys_linkat(syd_process_t *current);
int sys_rename(syd_process_t *current);
int sys_renameat(syd_process_t *current);
int sys_symlink(syd_process_t *current);
int sys_symlinkat(syd_process_t *current);
int sys_listxattr(syd_process_t *current);
int sys_llistxattr(syd_process_t *current);
int sys_setxattr(syd_process_t *current);
int sys_lsetxattr(syd_process_t *current);
int sys_removexattr(syd_process_t *current);
int sys_lremovexattr(syd_process_t *current);

int sys_dup(syd_process_t *current);
int sys_dup3(syd_process_t *current);
int sys_fcntl(syd_process_t *current);

int sys_clone(syd_process_t *current);
int sys_execve(syd_process_t *current);
int sys_stat(syd_process_t *current);

int sys_socketcall(syd_process_t *current);
int sys_bind(syd_process_t *current);
int sys_connect(syd_process_t *current);
int sys_sendto(syd_process_t *current);
int sys_getsockname(syd_process_t *current);

int sysx_chdir(syd_process_t *current);
int sysx_dup(syd_process_t *current);
int sysx_fcntl(syd_process_t *current);
int sysx_socketcall(syd_process_t *current);
int sysx_bind(syd_process_t *current);
int sysx_getsockname(syd_process_t *current);

#endif
