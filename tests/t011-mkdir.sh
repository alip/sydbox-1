#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox mkdir(2)'
. ./test-lib.sh

test_expect_success 'deny mkdir(NULL) with EFAULT' '
    sydbox -- emily mkdir -e EFAULT
'

test_expect_success 'deny mkdir()' '
    rm -rf nodir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily mkdir -e EPERM nodir.$test_count &&
    test_path_is_missing nodir.$test_count
'

test_expect_success 'deny mkdir() for existant directory' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily mkdir -e EEXIST dir.$test_count
'

test_expect_success 'whitelist mkdir()' '
    rm -rf nodir.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily mkdir -e ERRNO_0 nodir.$test_count &&
    test_path_is_dir nodir.$test_count
'

test_done
