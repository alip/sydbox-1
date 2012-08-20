/*
 * sydbox/pathdecode.h
 *
 * Copyright (c) 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v2
 */

#ifndef PATHDECODE_H
#define PATHDECODE_H 1

#include <pinktrace/easy/pink.h>

extern int path_decode(struct pink_easy_process *current, unsigned arg_index,
		       char **buf);
extern int path_prefix(struct pink_easy_process *current, unsigned arg_index,
		       char **buf);

#endif
