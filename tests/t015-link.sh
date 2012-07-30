#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox link(2)'
. ./test-lib.sh

test_expect_success setup '
    mkdir dir0 &&
    touch dir0/file0
'

test_expect_success 'deny link(NULL, NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily link
'

test_expect_success 'deny link()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/dir0/**" \
        -- emily link dir0/file0 file1-non-existant &&
    test_path_is_missing file1-non-existant
'

test_expect_success 'allow link()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily link dir0/file0 file2 &&
    test_path_is_file file2
'

test_done
