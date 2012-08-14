/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sydbox-defs.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "util.h"

struct key {
	const char *name;
	const char *lname;
	unsigned parent;
	enum magic_type type;
	int (*set) (const void *val, struct pink_easy_process *current);
	int (*query) (struct pink_easy_process *current);
};

static const struct key key_table[] = {
	[MAGIC_KEY_NONE] =
		{
			.lname  = "(none)",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_VERSION] =
		{
			.name = STRINGIFY(SYDBOX_VERSION_MAJOR),
			.lname = STRINGIFY(SYDBOX_VERSION_MAJOR),
			.parent = MAGIC_KEY_NONE,
			.type = MAGIC_TYPE_NONE,
		},

	[MAGIC_KEY_CORE] =
		{
			.name   = "core",
			.lname  = "core",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_MATCH] =
		{
			.name   = "match",
			.lname  = "core.match",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_SANDBOX] =
		{
			.name   = "sandbox",
			.lname  = "core.sandbox",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_WHITELIST] =
		{
			.name   = "whitelist",
			.lname  = "core.whitelist",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_ABORT] =
		{
			.name   = "abort",
			.lname  = "core.abort",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_PANIC] =
		{
			.name   = "panic",
			.lname  = "core.panic",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_VIOLATION] =
		{
			.name   = "violation",
			.lname  = "core.violation",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_TRACE] =
		{
			.name   = "trace",
			.lname  = "core.trace",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_LOG] =
		{
			.name   = "log",
			.lname  = "log",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_EXEC] =
		{
			.name   = "exec",
			.lname  = "exec",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_FILTER] =
		{
			.name   = "filter",
			.lname  = "filter",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_WHITELIST] =
		{
			.name   = "whitelist",
			.lname  = "whitelist",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_WHITELIST_NETWORK] =
		{
			.name   = "network",
			.lname  = "whitelist.network",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_BLACKLIST] =
		{
			.name   = "blacklist",
			.lname  = "blacklist",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_BLACKLIST_NETWORK] =
		{
			.name   = "network",
			.lname  = "blacklist.network",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_CORE_MATCH_CASE_SENSITIVE] =
		{
			.name   = "case_sensitive",
			.lname  = "core.match.case_sensitive",
			.parent = MAGIC_KEY_CORE_MATCH,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_match_case_sensitive,
			.query  = magic_query_match_case_sensitive,
		},
	[MAGIC_KEY_CORE_MATCH_NO_WILDCARD] =
		{
			.name   = "no_wildcard",
			.lname  = "core.match.no_wildcard",
			.parent = MAGIC_KEY_CORE_MATCH,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_match_no_wildcard,
		},

	[MAGIC_KEY_CORE_SANDBOX_EXEC] =
		{
			.name   = "exec",
			.lname  = "core.sandbox.exec",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_sandbox_exec,
			.query  = magic_query_sandbox_exec,
		},
	[MAGIC_KEY_CORE_SANDBOX_READ] =
		{
			.name   = "read",
			.lname  = "core.sandbox.read",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_sandbox_read,
			.query  = magic_query_sandbox_read,
		},
	[MAGIC_KEY_CORE_SANDBOX_WRITE] =
		{
			.name   = "write",
			.lname  = "core.sandbox.write",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_sandbox_write,
			.query  = magic_query_sandbox_write,
		},
	[MAGIC_KEY_CORE_SANDBOX_NETWORK] =
		{
			.name   = "network",
			.lname  = "core.sandbox.network",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_sandbox_network,
			.query  = magic_query_sandbox_network,
		},

	[MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES] =
		{
			.name   = "per_process_directories",
			.lname  = "core.whitelist.per_process_directories",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_whitelist_ppd,
			.query  = magic_query_whitelist_ppd,
		},
	[MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND] =
		{
			.name   = "successful_bind",
			.lname  = "core.whitelist.successful_bind",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_whitelist_sb,
			.query  = magic_query_whitelist_sb,
		},
	[MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES] =
		{
			.name   = "unsupported_socket_families",
			.lname  = "core.whitelist.unsupported_socket_families",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_whitelist_usf,
			.query  = magic_query_whitelist_usf,
		},

	[MAGIC_KEY_CORE_ABORT_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.abort.decision",
			.parent = MAGIC_KEY_CORE_ABORT,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_abort_decision,
		},

	[MAGIC_KEY_CORE_PANIC_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.panic.decision",
			.parent = MAGIC_KEY_CORE_PANIC,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_panic_decision,
		},
	[MAGIC_KEY_CORE_PANIC_EXIT_CODE] =
		{
			.name   = "exit_code",
			.lname  = "core.panic.exit_code",
			.parent = MAGIC_KEY_CORE_PANIC,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = magic_set_panic_exit_code,
		},

	[MAGIC_KEY_CORE_VIOLATION_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.violation.decision",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_violation_decision,
		},
	[MAGIC_KEY_CORE_VIOLATION_EXIT_CODE] =
		{
			.name   = "exit_code",
			.lname  = "core.violation.exit_code",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = magic_set_violation_exit_code,
		},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL] =
		{
			.name   = "raise_fail",
			.lname  = "core.violation.raise_fail",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_violation_raise_fail,
			.query  = magic_query_violation_raise_fail,
		},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE] =
		{
			.name   = "raise_safe",
			.lname  = "core.violation.raise_safe",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_violation_raise_safe,
			.query  = magic_query_violation_raise_safe,
		},

	[MAGIC_KEY_CORE_TRACE_FOLLOW_FORK] =
		{
			.name   = "follow_fork",
			.lname  = "core.trace.follow_fork",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_trace_follow_fork,
			.query  = magic_query_trace_follow_fork
		},
	[MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL] =
		{
			.name   = "exit_wait_all",
			.lname  = "core.trace.exit_wait_all",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_trace_exit_wait_all,
			.query  = magic_query_trace_exit_wait_all,
		},
	[MAGIC_KEY_CORE_TRACE_MAGIC_LOCK] =
		{
			.name   = "magic_lock",
			.lname  = "core.trace.magic_lock",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_trace_magic_lock,
		},
	[MAGIC_KEY_CORE_TRACE_INTERRUPT] =
		{
			.name   = "interrupt",
			.lname  = "core.trace.interrupt",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_trace_interrupt,
		},
	[MAGIC_KEY_CORE_TRACE_USE_SECCOMP] =
		{
			.name   = "use_seccomp",
			.lname  = "core.trace.use_seccomp",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = magic_set_trace_use_seccomp,
			.query  = magic_query_trace_use_seccomp,
		},

	[MAGIC_KEY_LOG_FILE] =
		{
			.name   = "file",
			.lname  = "log.file",
			.parent = MAGIC_KEY_LOG,
			.type   = MAGIC_TYPE_STRING,
			.set    = magic_set_log_file,
		},
	[MAGIC_KEY_LOG_LEVEL] =
		{
			.name   = "level",
			.lname  = "log.level",
			.parent = MAGIC_KEY_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = magic_set_log_level,
		},
	[MAGIC_KEY_LOG_CONSOLE_FD] =
		{
			.name   = "console_fd",
			.lname  = "log.console_fd",
			.parent = MAGIC_KEY_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = magic_set_log_console_fd,
		},
	[MAGIC_KEY_LOG_CONSOLE_LEVEL] =
		{
			.name   = "console_level",
			.lname  = "log.console_level",
			.parent = MAGIC_KEY_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = magic_set_log_console_level,
		},

	[MAGIC_KEY_EXEC_KILL_IF_MATCH] =
		{
			.name   = "kill_if_match",
			.lname  = "exec.kill_if_match",
			.parent = MAGIC_KEY_EXEC,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_exec_kill_if_match,
		},
	[MAGIC_KEY_EXEC_RESUME_IF_MATCH] =
		{
			.name   = "resume_if_match",
			.lname  = "exec.resume_if_match",
			.parent = MAGIC_KEY_EXEC,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_exec_resume_if_match,
		},

	[MAGIC_KEY_WHITELIST_EXEC] =
		{
			.name   = "exec",
			.lname  = "whitelist.exec",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_whitelist_exec,
		},
	[MAGIC_KEY_WHITELIST_READ] =
		{
			.name   = "read",
			.lname  = "whitelist.read",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_whitelist_read,
		},
	[MAGIC_KEY_WHITELIST_WRITE] =
		{
			.name   = "write",
			.lname  = "whitelist.write",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_whitelist_write,
		},
	[MAGIC_KEY_WHITELIST_NETWORK_BIND] =
		{
			.name   = "bind",
			.lname  = "whitelist.network.bind",
			.parent = MAGIC_KEY_WHITELIST_NETWORK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_whitelist_network_bind,
		},
	[MAGIC_KEY_WHITELIST_NETWORK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "whitelist.network.connect",
			.parent = MAGIC_KEY_WHITELIST_NETWORK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_whitelist_network_connect,
		},

	[MAGIC_KEY_BLACKLIST_EXEC] =
		{
			.name   = "exec",
			.lname  = "blacklist.exec",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_blacklist_exec,
		},
	[MAGIC_KEY_BLACKLIST_READ] =
		{
			.name   = "read",
			.lname  = "blacklist.read",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_blacklist_read,
		},
	[MAGIC_KEY_BLACKLIST_WRITE] =
		{
			.name   = "write",
			.lname  = "blacklist.write",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_blacklist_write,
		},
	[MAGIC_KEY_BLACKLIST_NETWORK_BIND] =
		{
			.name   = "bind",
			.lname  = "blacklist.network.bind",
			.parent = MAGIC_KEY_BLACKLIST_NETWORK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_blacklist_network_bind,
		},
	[MAGIC_KEY_BLACKLIST_NETWORK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "blacklist.network.connect",
			.parent = MAGIC_KEY_BLACKLIST_NETWORK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_blacklist_network_connect,
		},

	[MAGIC_KEY_FILTER_EXEC] =
		{
			.name   = "exec",
			.lname  = "filter.exec",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_filter_exec,
		},
	[MAGIC_KEY_FILTER_READ] =
		{
			.name   = "read",
			.lname  = "filter.read",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_filter_read,
		},
	[MAGIC_KEY_FILTER_WRITE] =
		{
			.name   = "write",
			.lname  = "filter.write",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_filter_write,
		},
	[MAGIC_KEY_FILTER_NETWORK] =
		{
			.name   = "network",
			.lname  = "filter.network",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = magic_set_filter_network,
		},

	[MAGIC_KEY_INVALID] =
		{
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_NONE,
		},
};

const char *magic_strerror(int error)
{
	switch (error) {
	case MAGIC_ERROR_SUCCESS:
		return "Success";
	case MAGIC_ERROR_NOT_SUPPORTED:
		return "Not supported";
	case MAGIC_ERROR_INVALID_KEY:
		return "Invalid key";
	case MAGIC_ERROR_INVALID_TYPE:
		return "Invalid type";
	case MAGIC_ERROR_INVALID_VALUE:
		return "Invalid value";
	case MAGIC_ERROR_INVALID_QUERY:
		return "Invalid query";
	case MAGIC_ERROR_INVALID_OPERATION:
		return "Invalid operation";
	case MAGIC_ERROR_NOPERM:
		return "No permission";
	case MAGIC_ERROR_OOM:
		return "Out of memory";
	default:
		return "Unknown error";
	}
}

const char *magic_strkey(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? "invalid" : key_table[key].lname;
}

unsigned magic_key_parent(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_KEY_INVALID : key_table[key].parent;
}

unsigned magic_key_type(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_TYPE_NONE : key_table[key].type;
}

unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len)
{
	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_KEY_INVALID;

	for (unsigned i = 1; i < MAGIC_KEY_INVALID; i++) {
		if (key == key_table[i].parent) {
			if (len < 0) {
				if (streq(nkey, key_table[i].name))
					return i;
			}
			else {
				if (!strncmp(nkey, key_table[i].name, len))
					return i;
			}
		}
	}

	return MAGIC_KEY_INVALID;
}

int magic_cast(struct pink_easy_process *current, enum magic_key key, enum magic_type type, const void *val)
{
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_ERROR_INVALID_KEY;

	entry = key_table[key];
	if (entry.type != type)
		return MAGIC_ERROR_INVALID_TYPE;

	if (sydbox->config.core_disallow) {
		enum magic_key k = entry.parent;
		do {
			if (k == MAGIC_KEY_CORE)
				return MAGIC_ERROR_NOPERM;
			k = key_table[k].parent;
		} while (k != MAGIC_KEY_NONE);
	}

	return entry.set(val, current);
}

static int magic_query(struct pink_easy_process *current, enum magic_key key)
{
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_ERROR_INVALID_KEY;
	entry = key_table[key];

	return entry.query ? entry.query(current) : MAGIC_ERROR_INVALID_QUERY;
}

static inline enum magic_key magic_next_key(const char *magic, enum magic_key key)
{
	int r;

	for (r = MAGIC_KEY_NONE + 1; r < MAGIC_KEY_INVALID; r++) {
		struct key k = key_table[r];

		if (k.parent == key && k.name && startswith(magic, k.name))
			return r;
	}

	return MAGIC_KEY_INVALID;
}

int magic_cast_string(struct pink_easy_process *current, const char *magic, int prefix)
{
	bool query = false, bval;
	int r, ival;
	enum magic_key key;
	const char *cmd;
	struct key entry;

	if (prefix) {
		if (!startswith(magic, SYDBOX_MAGIC_PREFIX)) {
			/* No magic */
			return 0;
		}

		cmd = magic + sizeof(SYDBOX_MAGIC_PREFIX) - 1;
		if (!*cmd) {
			/* Magic without command */
			return 1;
		}
		else if (*cmd != '/') {
			/* No magic, e.g. /dev/sydboxFOO */
			return 0;
		}
		else
			++cmd; /* Skip the '/' */
	}
	else
		cmd = magic;

	/* Figure out the magic command */
	for (key = MAGIC_KEY_NONE;;) {
		key = magic_next_key(cmd, key);
		if (key == MAGIC_KEY_INVALID) /* Invalid key */
			return MAGIC_ERROR_INVALID_KEY;

		cmd += strlen(key_table[key].name);
		switch (*cmd) {
		case '/':
			if (key_table[key].type != MAGIC_TYPE_OBJECT)
				return MAGIC_ERROR_INVALID_KEY;
			++cmd;
			continue;
		case SYDBOX_MAGIC_ADD_CHAR:
		case SYDBOX_MAGIC_REMOVE_CHAR:
			if (key_table[key].type != MAGIC_TYPE_STRING_ARRAY)
				return MAGIC_ERROR_INVALID_OPERATION;
			/* Don't skip the magic separator character for string
			 * arrays so that the magic callback can distinguish
			 * between add and remove operations.
			 */
			break;
		case SYDBOX_MAGIC_QUERY_CHAR:
			if (key_table[key].query == NULL)
				return MAGIC_ERROR_INVALID_QUERY;
			query = true;
			/* fall through */
		case SYDBOX_MAGIC_SEP_CHAR:
			++cmd;
			break;
		case 0:
			if (key_table[key].type == MAGIC_TYPE_NONE) {
				/* Special path, i.e /dev/sydbox/${version_major} */
				return 1;
			}
			/* fall through */
		default:
			return MAGIC_ERROR_INVALID_KEY;
		}
		break;
	}

	entry = key_table[key];
	if (query) {
		r = magic_query(current, key);
		return r < 0 ? r : r == 0 ? MAGIC_QUERY_FALSE : MAGIC_QUERY_TRUE;
	}

	switch (entry.type) {
	case MAGIC_TYPE_BOOLEAN:
		if ((r = parse_boolean(cmd, &bval)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((r = magic_cast(current, key, MAGIC_TYPE_BOOLEAN, BOOL_TO_PTR(bval))) < 0)
			return r;
		break;
	case MAGIC_TYPE_INTEGER:
		if ((r = safe_atoi(cmd, &ival)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((r = magic_cast(current, key, MAGIC_TYPE_INTEGER, INT_TO_PTR(ival))) < 0)
			return r;
		break;
	case MAGIC_TYPE_STRING_ARRAY:
	case MAGIC_TYPE_STRING:
		if ((r = magic_cast(current, key, entry.type, cmd)) < 0)
			return r;
		break;
	default:
		break;
	}

	return 1;
}
