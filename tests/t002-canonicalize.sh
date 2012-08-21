#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='test pathname canonicalization'
. ./test-lib.sh

test_expect_success SYMLINKS setup-symlinks '
    ln -sf self self
    ln -sf loop0 loop1
    ln -sf loop1 loop0
'

test_expect_success SYMLINKS 'deny stat($self-symlink) with ELOOP' '
    sydbox -- emily stat -e ELOOP self
'

test_expect_success SYMLINKS 'deny stat($circular-symlink) with ELOOP' '
    sydbox -- emily stat -e ELOOP loop0
'

test_expect_success SYMLINKS 'deny stat(${circular-symlink}/foo) with ELOOP' '
    sydbox -- emily stat -e ELOOP loop0/foo
'

test_expect_success SYMLINKS 'allow lstat($circular-symlink)' '
    sydbox -- emily stat -e ERRNO_0 -n loop0
'

test_expect_success SYMLINKS 'deny lstat(${circular-symlink}/foo) with ELOOP' '
    sydbox -- emily stat -e ELOOP -n loop0/foo
'

test_done
