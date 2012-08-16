/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Based in part upon gnulib which is:
 *   Copyright (C) 1996-2012 Free Software Foundation, Inc.
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef CANONICALIZE_H
#define CANONICALIZE_H 1

#define CAN_MODE_MASK (CAN_EXISTING | CAN_ALL_BUT_LAST | CAN_MISSING)

typedef enum {
	/* All components must exist. */
	CAN_EXISTING = 0,

	/* All components excluding last one must exist. */
	CAN_ALL_BUT_LAST = 1,

	/* No requirements on components existence. */
	CAN_MISSING = 2,

	/* Don't expand symlinks. */
	CAN_NOLINKS = 4
} can_mode_t;

int canonicalize_filename_mode(const char *name, can_mode_t mode, char **path);

#endif /* !CANONICALIZE_H */
