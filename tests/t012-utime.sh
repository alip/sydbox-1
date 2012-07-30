#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox utime(2)'
. ./test-lib.sh

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

test_expect_success 'deny utime(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily utime
'

test_expect_success 'deny utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime file0
'

test_expect_success 'deny utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime file-non-existant
'

test_expect_success 'deny utime() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime symlink-file1
'

test_expect_success 'deny utime() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime symlink-dangling
'

test_done
