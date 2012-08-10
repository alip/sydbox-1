/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
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

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"

int magic_set_trace_interrupt(const void *val, struct pink_easy_process *current)
{
	int intr;
	const char *str = val;

	if ((intr = trace_interrupt_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	sydbox->config.trace_interrupt = (enum pink_easy_intr)intr;
	return 0;
}
