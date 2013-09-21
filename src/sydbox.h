/*
 * sydbox/sydbox.h
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
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
#include <sys/queue.h>
#include <sys/types.h>
#include <limits.h>
#include <pinktrace/pink.h>
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
#define SYD_IGNORE		00004 /* process is ignored (no sandboxing) */
#define SYD_READY		00010 /* process' sandbox is initialised */
#define SYD_IN_SYSCALL		00020 /* process is in system call */
#define SYD_DENY_SYSCALL	00040 /* system call is to be denied */
#define SYD_STOP_AT_SYSEXIT	00100 /* seccomp: stop at system call exit */
#define SYD_SYDBOX_CHILD	00200 /* process is the child exec()'ed by sydbox */

#define entering(p)	(!((p)->flags & SYD_IN_SYSCALL))
#define exiting(p)	((p)->flags & SYD_IN_SYSCALL)
#define sysdeny(p)	((p)->flags & SYD_DENY_SYSCALL)
#define sydchild(p)	((p)->flags & SYD_SYDBOX_CHILD)
#define hasparent(p)	((p)->ppid >= 1)

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

#define sandbox_exec_allow(proc)	(!!((proc)->config.sandbox_exec == SANDBOX_ALLOW))
#define sandbox_exec_off(proc)		(!!((proc)->config.sandbox_exec == SANDBOX_OFF))
#define sandbox_exec_deny(proc)		(!!((proc)->config.sandbox_exec == SANDBOX_DENY))

#define sandbox_read_allow(proc)	(!!((proc)->config.sandbox_read == SANDBOX_ALLOW))
#define sandbox_read_off(proc)		(!!((proc)->config.sandbox_read == SANDBOX_OFF))
#define sandbox_read_deny(proc)		(!!((proc)->config.sandbox_read == SANDBOX_DENY))

#define sandbox_write_allow(proc)	(!!((proc)->config.sandbox_write == SANDBOX_ALLOW))
#define sandbox_write_off(proc)		(!!((proc)->config.sandbox_write == SANDBOX_OFF))
#define sandbox_write_deny(proc)	(!!((proc)->config.sandbox_write == SANDBOX_DENY))

#define sandbox_file_off(proc)		(sandbox_exec_off((proc)) && \
					 sandbox_read_off((proc)) && \
					 sandbox_write_off((proc)))

#define sandbox_network_allow(proc)	(!!((proc)->config.sandbox_network == SANDBOX_ALLOW))
#define sandbox_network_off(proc)	(!!((proc)->config.sandbox_network == SANDBOX_OFF))
#define sandbox_network_deny(proc)	(!!((proc)->config.sandbox_network == SANDBOX_DENY))

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

enum trace_interrupt {
	/* don't block ignore any signals */
	TRACE_INTR_ANYWHERE        = 1,
	/* block fatal signals while decoding syscall (default) */
	TRACE_INTR_WHILE_WAIT      = 2,
	/* block fatal signals */
	TRACE_INTR_NEVER           = 3,
	/* block fatal signals and SIGTSTP (^Z) */
	TRACE_INTR_BLOCK_TSTP_TOO  = 4,
};
static const char *const trace_interrupt_table[] = {
	[TRACE_INTR_ANYWHERE] = "anywhere",
	[TRACE_INTR_WHILE_WAIT] = "while_wait",
	[TRACE_INTR_NEVER] = "never",
	[TRACE_INTR_BLOCK_TSTP_TOO] = "block_tstp_too",
};
DEFINE_STRING_TABLE_LOOKUP(trace_interrupt, int)

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
	MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL,
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
typedef struct syd_proc {
	/* Process ID */
	pid_t pid;

	/* Process registry set */
	struct pink_regset *regset;

	/* System call ABI */
	short abi;

	/* Parent process ID */
	pid_t ppid;

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

	/* Last (socket) subcall */
	long subcall;

	/* Denied system call will return this value */
	long retval;

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;

	/* Current working directory, read from /proc/$pid/cwd */
	char *cwd;

	/* Process name, read from /proc/$pid/comm for initial process and
	 * updated after successful execve() */
	char *comm;

	/* Information about the last bind address with port zero */
	struct sockinfo *savebind;

	/* fd -> sock_info_t mappings  */
	struct sockmap *sockmap;

	/* Per-process configuration */
	sandbox_t config;

	/* hash table entry */
	UT_hash_handle hh;
} syd_proc_t;

typedef struct {
	/* magic access to core.*  */
	bool magic_core_allow;

	/* Per-process sandboxing data */
	sandbox_t child;

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
	bool exit_wait_all;
	enum trace_interrupt trace_interrupt;
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
	syd_proc_t *proctab;

	int trace_options;
	enum syd_step trace_step;

	pid_t pidwait;

	bool wait_execve;
	int exit_code;

	/* This is true if an access violation has occured, false otherwise. */
	bool violation;

	/* Program invocation name (for the child) */
	char *program_invocation_name;

	/* Global configuration */
	config_t config;
} sydbox_t;

typedef int (*sysfunc_t) (syd_proc_t *current);
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
#define SYD_PROCESS_COUNT()		HASH_COUNT(sydbox->proctab)
#define SYD_PROCESS_ITER(proc, tmp)	HASH_ITER(hh, sydbox->proctab, (proc), (tmp))
#define SYD_PROCESS_ADD(proc)		HASH_ADD_INT(sydbox->proctab, pid, (proc))
#define SYD_PROCESS_REMOVE(proc)	HASH_DEL(sydbox->proctab, (proc))

/* Global functions */
int syd_trace_detach(syd_proc_t *current, int sig);
int syd_trace_kill(syd_proc_t *current, int sig);
int syd_trace_setup(syd_proc_t *current);
int syd_trace_geteventmsg(syd_proc_t *current, unsigned long *data);
int syd_regset_fill(syd_proc_t *current);
int syd_read_syscall(syd_proc_t *current, long *sysnum);
int syd_read_retval(syd_proc_t *current, long *retval, int *error);
int syd_read_argument(syd_proc_t *current, unsigned arg_index, long *argval);
int syd_read_argument_int(syd_proc_t *current, unsigned arg_index, int *argval);
ssize_t syd_read_string(syd_proc_t *current, long addr, char *dest, size_t len);
int syd_write_syscall(syd_proc_t *current, long sysnum);
int syd_write_retval(syd_proc_t *current, long retval, int error);
int syd_read_socket_argument(syd_proc_t *current, bool decode_socketcall,
			     unsigned arg_index, unsigned long *argval);
int syd_read_socket_subcall(syd_proc_t *current, bool decode_socketcall,
			    long *subcall);
int syd_read_socket_address(syd_proc_t *current, bool decode_socketcall,
			    unsigned arg_index, int *fd,
			    struct pink_sockaddr *sockaddr);

void clear_proc(syd_proc_t *p);
void ignore_proc(syd_proc_t *p);
void remove_proc(syd_proc_t *p);
static inline syd_proc_t *lookup_proc(pid_t pid)
{
	syd_proc_t *p;
	HASH_FIND_INT(sydbox->proctab, &pid, p);
	return p;
}

void cont_all(void);
void abort_all(int fatal_sig);
int deny(syd_proc_t *current, int err_no);
int restore(syd_proc_t *current);
int panic(syd_proc_t *current);
int violation(syd_proc_t *current, const char *fmt, ...)
	PINK_GCC_ATTR((format (printf, 2, 3)));

void config_init(void);
void config_done(void);
void config_parse_file(const char *filename) PINK_GCC_ATTR((nonnull(1)));
void config_parse_spec(const char *filename) PINK_GCC_ATTR((nonnull(1)));

void callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid,
		     unsigned rmode, char **res);
int box_check_path(syd_proc_t *current, sysinfo_t *info);
int box_check_socket(syd_proc_t *current, sysinfo_t *info);

static inline sandbox_t *box_current(syd_proc_t *current)
{
	return current ? &current->config : &sydbox->config.child;
}

static inline void free_sandbox(sandbox_t *box)
{
	struct acl_node *node;

	ACLQ_FREE(node, &box->acl_exec, free);
	ACLQ_FREE(node, &box->acl_read, free);
	ACLQ_FREE(node, &box->acl_write, free);
	ACLQ_FREE(node, &box->acl_network_bind, free_sockmatch);
	ACLQ_FREE(node, &box->acl_network_connect, free_sockmatch);
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
int sysenter(syd_proc_t *current);
int sysexit(syd_proc_t *current);

enum magic_ret magic_check_call(int rval);
const char *magic_strerror(int error);
const char *magic_strkey(enum magic_key key);
unsigned magic_key_type(enum magic_key key);
unsigned magic_key_parent(enum magic_key key);
unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len);
int magic_cast(syd_proc_t *current, enum magic_op op, enum magic_key key,
	       const void *val);
int magic_cast_string(syd_proc_t *current, const char *magic, int prefix);

int magic_set_panic_exit_code(const void *val, syd_proc_t *current);
int magic_set_violation_exit_code(const void *val, syd_proc_t *current);
int magic_set_violation_raise_fail(const void *val, syd_proc_t *current);
int magic_query_violation_raise_fail(syd_proc_t *current);
int magic_set_violation_raise_safe(const void *val, syd_proc_t *current);
int magic_query_violation_raise_safe(syd_proc_t *current);
int magic_set_trace_follow_fork(const void *val, syd_proc_t *current);
int magic_query_trace_follow_fork(syd_proc_t *current);
int magic_set_trace_exit_kill(const void *val, syd_proc_t *current);
int magic_query_trace_exit_kill(syd_proc_t *current);
int magic_set_trace_exit_wait_all(const void *val, syd_proc_t *current);
int magic_query_trace_exit_wait_all(syd_proc_t *current);
int magic_set_trace_interrupt(const void *val, syd_proc_t *current);
int magic_set_trace_use_seccomp(const void *val, syd_proc_t *current);
int magic_query_trace_use_seccomp(syd_proc_t *current);
int magic_set_trace_use_seize(const void *val, syd_proc_t *current);
int magic_query_trace_use_seize(syd_proc_t *current);
int magic_set_trace_use_toolong_hack(const void *val, syd_proc_t *current);
int magic_query_trace_use_toolong_hack(syd_proc_t *current);
int magic_set_restrict_fcntl(const void *val, syd_proc_t *current);
int magic_query_restrict_fcntl(syd_proc_t *current);
int magic_set_restrict_shm_wr(const void *val, syd_proc_t *current);
int magic_query_restrict_shm_wr(syd_proc_t *current);
int magic_set_whitelist_ppd(const void *val, syd_proc_t *current);
int magic_query_whitelist_ppd(syd_proc_t *current);
int magic_set_whitelist_sb(const void *val, syd_proc_t *current);
int magic_query_whitelist_sb(syd_proc_t *current);
int magic_set_whitelist_usf(const void *val, syd_proc_t *current);
int magic_query_whitelist_usf(syd_proc_t *current);
int magic_append_whitelist_exec(const void *val, syd_proc_t *current);
int magic_remove_whitelist_exec(const void *val, syd_proc_t *current);
int magic_append_whitelist_read(const void *val, syd_proc_t *current);
int magic_remove_whitelist_read(const void *val, syd_proc_t *current);
int magic_append_whitelist_write(const void *val, syd_proc_t *current);
int magic_remove_whitelist_write(const void *val, syd_proc_t *current);
int magic_append_blacklist_exec(const void *val, syd_proc_t *current);
int magic_remove_blacklist_exec(const void *val, syd_proc_t *current);
int magic_append_blacklist_read(const void *val, syd_proc_t *current);
int magic_remove_blacklist_read(const void *val, syd_proc_t *current);
int magic_append_blacklist_write(const void *val, syd_proc_t *current);
int magic_remove_blacklist_write(const void *val, syd_proc_t *current);
int magic_append_filter_exec(const void *val, syd_proc_t *current);
int magic_remove_filter_exec(const void *val, syd_proc_t *current);
int magic_append_filter_read(const void *val, syd_proc_t *current);
int magic_remove_filter_read(const void *val, syd_proc_t *current);
int magic_append_filter_write(const void *val, syd_proc_t *current);
int magic_remove_filter_write(const void *val, syd_proc_t *current);
int magic_append_whitelist_network_bind(const void *val, syd_proc_t *current);
int magic_remove_whitelist_network_bind(const void *val, syd_proc_t *current);
int magic_append_whitelist_network_connect(const void *val, syd_proc_t *current);
int magic_remove_whitelist_network_connect(const void *val, syd_proc_t *current);
int magic_append_blacklist_network_bind(const void *val, syd_proc_t *current);
int magic_remove_blacklist_network_bind(const void *val, syd_proc_t *current);
int magic_append_blacklist_network_connect(const void *val, syd_proc_t *current);
int magic_remove_blacklist_network_connect(const void *val, syd_proc_t *current);
int magic_append_filter_network(const void *val, syd_proc_t *current);
int magic_remove_filter_network(const void *val, syd_proc_t *current);
int magic_set_abort_decision(const void *val, syd_proc_t *current);
int magic_set_panic_decision(const void *val, syd_proc_t *current);
int magic_set_violation_decision(const void *val, syd_proc_t *current);
int magic_set_trace_magic_lock(const void *val, syd_proc_t *current);
int magic_set_log_file(const void *val, syd_proc_t *current);
int magic_set_log_level(const void *val, syd_proc_t *current);
int magic_set_log_console_fd(const void *val, syd_proc_t *current);
int magic_set_log_console_level(const void *val, syd_proc_t *current);
int magic_query_sandbox_exec(syd_proc_t *current);
int magic_query_sandbox_read(syd_proc_t *current);
int magic_query_sandbox_write(syd_proc_t *current);
int magic_query_sandbox_network(syd_proc_t *current);
int magic_set_sandbox_exec(const void *val, syd_proc_t *current);
int magic_set_sandbox_read(const void *val, syd_proc_t *current);
int magic_set_sandbox_write(const void *val, syd_proc_t *current);
int magic_set_sandbox_network(const void *val, syd_proc_t *current);
int magic_append_exec_kill_if_match(const void *val, syd_proc_t *current);
int magic_remove_exec_kill_if_match(const void *val, syd_proc_t *current);
int magic_append_exec_resume_if_match(const void *val, syd_proc_t *current);
int magic_remove_exec_resume_if_match(const void *val, syd_proc_t *current);
int magic_query_match_case_sensitive(syd_proc_t *current);
int magic_set_match_case_sensitive(const void *val, syd_proc_t *current);
int magic_set_match_no_wildcard(const void *val, syd_proc_t *current);

int magic_cmd_exec(const void *val, syd_proc_t *current);

static inline void init_sysinfo(sysinfo_t *info)
{
	memset(info, 0, sizeof(sysinfo_t));
}

int filter_open(int arch, uint32_t sysnum);
int filter_openat(int arch, uint32_t sysnum);
int filter_fcntl(int arch, uint32_t sysnum);
int filter_mmap(int arch, uint32_t sysnum);
int sys_fallback_mmap(syd_proc_t *current);

int sys_access(syd_proc_t *current);
int sys_faccessat(syd_proc_t *current);

int sys_chmod(syd_proc_t *current);
int sys_fchmodat(syd_proc_t *current);
int sys_chown(syd_proc_t *current);
int sys_lchown(syd_proc_t *current);
int sys_fchownat(syd_proc_t *current);
int sys_open(syd_proc_t *current);
int sys_openat(syd_proc_t *current);
int sys_creat(syd_proc_t *current);
int sys_close(syd_proc_t *current);
int sysx_close(syd_proc_t *current);
int sys_mkdir(syd_proc_t *current);
int sys_mkdirat(syd_proc_t *current);
int sys_mknod(syd_proc_t *current);
int sys_mknodat(syd_proc_t *current);
int sys_rmdir(syd_proc_t *current);
int sys_truncate(syd_proc_t *current);
int sys_mount(syd_proc_t *current);
int sys_umount(syd_proc_t *current);
int sys_umount2(syd_proc_t *current);
int sys_utime(syd_proc_t *current);
int sys_utimes(syd_proc_t *current);
int sys_utimensat(syd_proc_t *current);
int sys_futimesat(syd_proc_t *current);
int sys_unlink(syd_proc_t *current);
int sys_unlinkat(syd_proc_t *current);
int sys_link(syd_proc_t *current);
int sys_linkat(syd_proc_t *current);
int sys_rename(syd_proc_t *current);
int sys_renameat(syd_proc_t *current);
int sys_symlink(syd_proc_t *current);
int sys_symlinkat(syd_proc_t *current);
int sys_listxattr(syd_proc_t *current);
int sys_llistxattr(syd_proc_t *current);
int sys_setxattr(syd_proc_t *current);
int sys_lsetxattr(syd_proc_t *current);
int sys_removexattr(syd_proc_t *current);
int sys_lremovexattr(syd_proc_t *current);

int sys_dup(syd_proc_t *current);
int sys_dup3(syd_proc_t *current);
int sys_fcntl(syd_proc_t *current);

int sys_fork(syd_proc_t *current);
int sys_execve(syd_proc_t *current);
int sys_stat(syd_proc_t *current);

int sys_socketcall(syd_proc_t *current);
int sys_bind(syd_proc_t *current);
int sys_connect(syd_proc_t *current);
int sys_sendto(syd_proc_t *current);
int sys_getsockname(syd_proc_t *current);

int sysx_chdir(syd_proc_t *current);
int sysx_dup(syd_proc_t *current);
int sysx_fcntl(syd_proc_t *current);
int sysx_socketcall(syd_proc_t *current);
int sysx_bind(syd_proc_t *current);
int sysx_getsockname(syd_proc_t *current);

#endif
