#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mknod(2)'
. ./test-lib.sh

test_expect_success FIFOS setup '
    mknod fifo1 p
'

test_expect_success 'deny mknod(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily mknod
'

test_expect_success FIFOS 'deny mknod()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily mknod fifo0-non-existant &&
    test_path_is_missing fifo0-non-existant
'

test_expect_success FIFOS 'deny mknod() for existant fifo' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- emily mknod fifo1
'

test_expect_success FIFOS 'allow mknod()' '
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily mknod fifo2-non-existant &&
    test_path_is_fifo fifo2-non-existant
'

test_done
