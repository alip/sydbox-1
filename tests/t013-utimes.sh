#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox utimes(2)'
. ./test-lib.sh
prog=t013_utimes

# No allow tests because of possible noatime, nomtime mount options

test_expect_success setup '
    rm -f file-non-existant
    touch file0 &&
    touch file1
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1
'

test_expect_success 'deny utimes()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog file0
'

test_expect_success 'deny utimes()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog file-non-existant
'

test_expect_success 'deny utimes() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-file1
'

test_expect_success 'deny utimes() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-dangling
'

test_done
