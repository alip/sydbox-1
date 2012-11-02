#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='sandbox rmdir(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_failure 'deny rmdir(NULL) with EFAULT' '
    sydbox -- emily rmdir -e EFAULT
'

test_expect_failure 'deny rmdir()' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM dir.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_failure 'deny rmdir() for non-existant directory' '
    rm -fr nodir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM nodir.$test_count
'

test_expect_failure 'whitelist rmdir()' '
    mkdir dir.$test_count &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e ERRNO_0 dir.$test_count &&
    test_path_is_missing dir.$test_count
'

test_expect_failure 'blacklist rmdir()' '
    mkdir dir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM dir.$test_count &&
    test_path_is_dir dir.$test_count
'

test_expect_failure 'blacklist rmdir() for non-existant directory' '
    rm -fr nodir.$test_count &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM nodir.$test_count
'

test_done
