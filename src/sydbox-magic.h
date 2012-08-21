/*
 * sydbox/sydbox-magic.h
 *
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef SYDBOX_MAGIC_H
#define SYDBOX_MAGIC_H 1

#include <pinktrace/easy/pink.h>
#include "strtable.h"

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

#define sandbox_exec_allow(data)	(!!((data)->config.sandbox_exec == SANDBOX_ALLOW))
#define sandbox_exec_off(data)		(!!((data)->config.sandbox_exec == SANDBOX_OFF))
#define sandbox_exec_deny(data)		(!!((data)->config.sandbox_exec == SANDBOX_DENY))

#define sandbox_read_allow(data)	(!!((data)->config.sandbox_read == SANDBOX_ALLOW))
#define sandbox_read_off(data)		(!!((data)->config.sandbox_read == SANDBOX_OFF))
#define sandbox_read_deny(data)		(!!((data)->config.sandbox_read == SANDBOX_DENY))

#define sandbox_write_allow(data)	(!!((data)->config.sandbox_write == SANDBOX_ALLOW))
#define sandbox_write_off(data)		(!!((data)->config.sandbox_write == SANDBOX_OFF))
#define sandbox_write_deny(data)	(!!((data)->config.sandbox_write == SANDBOX_DENY))

#define sandbox_network_allow(data)	(!!((data)->config.sandbox_network == SANDBOX_ALLOW))
#define sandbox_network_off(data)	(!!((data)->config.sandbox_network == SANDBOX_OFF))
#define sandbox_network_deny(data)	(!!((data)->config.sandbox_network == SANDBOX_DENY))

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

static const char *const trace_interrupt_table[] = {
	[PINK_EASY_INTR_ANYWHERE] = "anywhere",
	[PINK_EASY_INTR_WHILE_WAIT] = "while_wait",
	[PINK_EASY_INTR_NEVER] = "never",
	[PINK_EASY_INTR_BLOCK_TSTP_TOO] = "block_tstp_too",
};
DEFINE_STRING_TABLE_LOOKUP(trace_interrupt, int)

#define MAGIC_QUERY_TRUE	1
#define MAGIC_QUERY_FALSE	2

enum magic_type {
	MAGIC_TYPE_NONE,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_INTEGER,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,

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
	MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL,
	MAGIC_KEY_CORE_TRACE_MAGIC_LOCK,
	MAGIC_KEY_CORE_TRACE_INTERRUPT,
	MAGIC_KEY_CORE_TRACE_USE_SECCOMP,

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

	MAGIC_KEY_INVALID,
};

#define MAGIC_ERROR_SUCCESS		( 0)
#define MAGIC_ERROR_NOT_SUPPORTED	(-1)
#define MAGIC_ERROR_INVALID_KEY		(-2)
#define MAGIC_ERROR_INVALID_TYPE	(-3)
#define MAGIC_ERROR_INVALID_VALUE	(-4)
#define MAGIC_ERROR_INVALID_QUERY	(-5)
#define MAGIC_ERROR_INVALID_OPERATION	(-6)
#define MAGIC_ERROR_NOPERM		(-7)
#define MAGIC_ERROR_OOM			(-8)

extern int magic_set_panic_exit_code(const void *val, struct pink_easy_process *current);
extern int magic_set_violation_exit_code(const void *val, struct pink_easy_process *current);
extern int magic_set_violation_raise_fail(const void *val, struct pink_easy_process *current);
extern int magic_query_violation_raise_fail(struct pink_easy_process *current);
extern int magic_set_violation_raise_safe(const void *val, struct pink_easy_process *current);
extern int magic_query_violation_raise_safe(struct pink_easy_process *current);
extern int magic_set_trace_follow_fork(const void *val, struct pink_easy_process *current);
extern int magic_query_trace_follow_fork(struct pink_easy_process *current);
extern int magic_set_trace_exit_wait_all(const void *val, struct pink_easy_process *current);
extern int magic_query_trace_exit_wait_all(struct pink_easy_process *current);
extern int magic_set_trace_interrupt(const void *val, struct pink_easy_process *current);
extern int magic_set_trace_use_seccomp(const void *val, struct pink_easy_process *current);
extern int magic_query_trace_use_seccomp(struct pink_easy_process *current);
extern int magic_set_whitelist_ppd(const void *val, struct pink_easy_process *current);
extern int magic_query_whitelist_ppd(struct pink_easy_process *current);
extern int magic_set_whitelist_sb(const void *val, struct pink_easy_process *current);
extern int magic_query_whitelist_sb(struct pink_easy_process *current);
extern int magic_set_whitelist_usf(const void *val, struct pink_easy_process *current);
extern int magic_query_whitelist_usf(struct pink_easy_process *current);
extern int magic_set_whitelist_exec(const void *val, struct pink_easy_process *current);
extern int magic_set_whitelist_read(const void *val, struct pink_easy_process *current);
extern int magic_set_whitelist_write(const void *val, struct pink_easy_process *current);
extern int magic_set_blacklist_exec(const void *val, struct pink_easy_process *current);
extern int magic_set_blacklist_read(const void *val, struct pink_easy_process *current);
extern int magic_set_blacklist_write(const void *val, struct pink_easy_process *current);
extern int magic_set_filter_exec(const void *val, struct pink_easy_process *current);
extern int magic_set_filter_read(const void *val, struct pink_easy_process *current);
extern int magic_set_filter_write(const void *val, struct pink_easy_process *current);
extern int magic_set_whitelist_network_bind(const void *val, struct pink_easy_process *current);
extern int magic_set_whitelist_network_connect(const void *val, struct pink_easy_process *current);
extern int magic_set_blacklist_network_bind(const void *val, struct pink_easy_process *current);
extern int magic_set_blacklist_network_connect(const void *val, struct pink_easy_process *current);
extern int magic_set_filter_network(const void *val, struct pink_easy_process *current);
extern int magic_set_abort_decision(const void *val, struct pink_easy_process *current);
extern int magic_set_panic_decision(const void *val, struct pink_easy_process *current);
extern int magic_set_violation_decision(const void *val, struct pink_easy_process *current);
extern int magic_set_trace_magic_lock(const void *val, struct pink_easy_process *current);
extern int magic_set_log_file(const void *val, struct pink_easy_process *current);
extern int magic_set_log_level(const void *val, struct pink_easy_process *current);
extern int magic_set_log_console_fd(const void *val, struct pink_easy_process *current);
extern int magic_set_log_console_level(const void *val, struct pink_easy_process *current);
extern int magic_query_sandbox_exec(struct pink_easy_process *current);
extern int magic_query_sandbox_read(struct pink_easy_process *current);
extern int magic_query_sandbox_write(struct pink_easy_process *current);
extern int magic_query_sandbox_network(struct pink_easy_process *current);
extern int magic_set_sandbox_exec(const void *val, struct pink_easy_process *current);
extern int magic_set_sandbox_read(const void *val, struct pink_easy_process *current);
extern int magic_set_sandbox_write(const void *val, struct pink_easy_process *current);
extern int magic_set_sandbox_network(const void *val, struct pink_easy_process *current);
extern int magic_set_exec_kill_if_match(const void *val, struct pink_easy_process *current);
extern int magic_set_exec_resume_if_match(const void *val, struct pink_easy_process *current);
extern int magic_query_match_case_sensitive(struct pink_easy_process *current);
extern int magic_set_match_case_sensitive(const void *val, struct pink_easy_process *current);
extern int magic_set_match_no_wildcard(const void *val, struct pink_easy_process *current);

#endif
