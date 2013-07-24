/*
 * sydbox/magic-acl.c
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
 */

#include "sydbox.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pinktrace/pink.h>

#include "acl-queue.h"
#include "macro.h"
#include "log.h"

static int magic_edit_acl(int (*edit_func)(enum acl_action, const char *, aclq_t *),
			  enum acl_action action, const char *val, aclq_t *acl)
{
	enum magic_ret r;

	r = magic_errno(edit_func(action, (const char *)val, acl));
	if (r == MAGIC_RET_NOT_SUPPORTED) {
		log_magic("ignore unsupported magic value `%s'", val);
		r = MAGIC_RET_OK;
	}
	return r;
}

int magic_append_whitelist_exec(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_exec);
}

int magic_remove_whitelist_exec(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_exec);
}

int magic_append_blacklist_exec(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_exec);
}

int magic_remove_blacklist_exec(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_exec);
}

int magic_append_filter_exec(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_exec);
}

int magic_remove_filter_exec(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_exec);
}

int magic_append_whitelist_read(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_read);
}

int magic_remove_whitelist_read(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_read);
}

int magic_append_blacklist_read(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_read);
}

int magic_remove_blacklist_read(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_read);
}

int magic_append_filter_read(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_read);
}

int magic_remove_filter_read(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_read);
}

int magic_append_whitelist_write(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_write);
}

int magic_remove_whitelist_write(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_write);
}

int magic_append_blacklist_write(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_write);
}

int magic_remove_blacklist_write(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_write);
}

int magic_append_filter_network(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_network);
}

int magic_append_filter_write(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_write);
}

int magic_remove_filter_write(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_write);
}

int magic_append_whitelist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_network_bind);
}

int magic_remove_whitelist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_network_bind);
}

int magic_append_whitelist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_network_connect);
}

int magic_remove_whitelist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_WHITELIST, val,
			      &box->acl_network_connect);
}

int magic_append_blacklist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_network_bind);
}

int magic_remove_blacklist_network_bind(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_network_bind);
}

int magic_append_blacklist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_append_sockmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_network_connect);
}

int magic_remove_blacklist_network_connect(const void *val, syd_proc_t *current)
{
	sandbox_t *box = box_current(current);
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_BLACKLIST, val,
			      &box->acl_network_connect);
}

int magic_remove_filter_network(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_sockmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.filter_network);
}

int magic_append_exec_kill_if_match(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.exec_kill_if_match);
}

int magic_remove_exec_kill_if_match(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.exec_kill_if_match);
}

int magic_append_exec_resume_if_match(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_append_pathmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.exec_resume_if_match);
}

int magic_remove_exec_resume_if_match(const void *val, syd_proc_t *current)
{
	return magic_edit_acl(acl_remove_pathmatch, ACL_ACTION_NONE, val,
			      &sydbox->config.exec_resume_if_match);
}
