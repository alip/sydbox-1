#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mkdir(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t006_mkdir

test_expect_success setup '
    mkdir dir2 &&
    mkdir dir3
'

test_expect_success 'deny mkdir()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog dir0-non-existant &&
    test_path_is_missing dir0-non-existant
'

test_expect_success ATTACH 'attach & deny mkdir()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog dir1-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing dir1-non-existant
'

test_expect_success 'deny mkdir() for existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog dir2
'

test_expect_success ATTACH 'attach & deny mkdir() for existant directory' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog dir3
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP 'deny mkdir() for existant directory outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -- $prog "$d"
    )
'

test_expect_success ATTACH,MKTEMP,TODO 'attach & deny mkdir() for existant directory outside' '
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny mkdir() for symlink outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        ln -sf "$d" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny mkdir() for symlink outside' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog symlink1-outside
    ) &
    pid=$!
    d="$(mkstemp -d)"
    test_path_is_dir "$d" &&
    ln -sf "$d" symlink1-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success 'allow mkdir()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog dir6-non-existant &&
    test_path_is_dir dir6-non-existant
'

test_expect_success ATTACH 'attach & allow mkdir()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog dir7-non-existant
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_dir dir7-non-existant
'

test_expect_success MKTEMP 'allow mkdir() for non-existant directory outside' '
    (
        d="$(mkstemp --dry-run)"
        test -n "$d" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $prog "$d" &&
        test_path_is_dir "$d"
    ) || return 1
'

test_expect_success MKTEMP,TODO 'attach & allow mkdir() for non-existant directory outside' '
'

test_done
