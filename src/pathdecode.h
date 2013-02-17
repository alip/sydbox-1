/*
 * sydbox/pathdecode.h
 *
 * Copyright (c) 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef PATHDECODE_H
#define PATHDECODE_H 1

#include "sydbox.h"

int path_decode(syd_proc_t *current, unsigned arg_index, char **buf);
int path_prefix(syd_proc_t *current, unsigned arg_index, char **buf);

#endif
