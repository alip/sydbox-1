#!/bin/sh
# Copyright 2013, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the very basics of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'compatible long options with sydbox-0' '
    sydbox --help &&
    sydbox --version &&
    sydfmt --help &&
    sydfmt --version
'

SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS"
export SYDBOX_TEST_OPTIONS

test_expect_success 'return success if tracee returns success' '
    sydbox -- syd_true
'

test_expect_success 'return success if tracee returns success (STATIC)' '
    sydbox -- syd_true_static
'

test_expect_success_foreach_option 'return success if tracee returns success' '
    sydbox -- syd_true
'

test_expect_success_foreach_option 'return success if tracee returns success (STATIC)' '
    sydbox -- syd_true_static
'

test_expect_success 'return failure if tracee returns failure' '
    test_expect_code 1 sydbox -- syd_false
'

test_expect_success 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 sydbox -- syd_false_static
'

test_expect_success_foreach_option 'return failure if tracee returns failure' '
    test_expect_code 1 sydbox -- syd_false
'

test_expect_success_foreach_option 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 sydbox -- syd_false_static
'

test_expect_success 'return success if initial tracee returns success (FORK)' '
    sydbox -- syd_true_fork 256
'

test_expect_success 'return success if initial tracee returns success (STATIC|FORK)' '
    sydbox -- syd_true_fork_static 256
'

test_expect_success_foreach_option 'return success if initial tracee returns success (FORK)' '
    sydbox -- syd_true_fork 256
'

test_expect_success_foreach_option 'return success if initial tracee returns success (STATIC|FORK)' '
    sydbox -- syd_true_fork_static 256
'

test_expect_success 'return success if initial tracee returns success (PTHREAD)' '
    sydbox -- syd_true_pthread 256
'

test_expect_success_foreach_option 'return success if initial tracee returns success (PTHREAD)' '
    sydbox -- syd_true_pthread 256
'

test_expect_success 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 sydbox -- syd_false_fork 256
'

test_expect_success 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 sydbox -- syd_false_fork_static 256
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 sydbox -- syd_false_fork 256
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 sydbox -- syd_false_fork_static 256
'

test_expect_success 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 sydbox -- syd_false_pthread 256
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 sydbox -- syd_false_pthread 256
'

#test_expect_success_foreach_option 'return success if initial tracee returns success' '
#    sydbox -- "$SHELL_PATH" <<EOF
#for i in 1 2 3 4 5 6 7
#do
#    ( sleep 1 ; exit $i ) &
#done
#    exit 0
#EOF
#'
#
#test_expect_success_foreach_option 'return error if tracee returns error' '
#    test_expect_code 7 sydbox -- "$SHELL_PATH" -c "exit 7"
#'
#
#test_expect_success_foreach_option 'return success if initial tracee returns error' '
#    test_expect_code 7 sydbox -- "$SHELL_PATH" <<EOF
#for i in 1 2 3 4 5 6 7
#do
#    ( sleep 1 ; exit 0 ) &
#done
#    exit 7
#EOF
#'
#
#test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated' '
#    sigint=2 &&
#    retval=$(expr 128 + $sigint) &&
#    test_expect_code "$retval" sydbox -- "$SHELL_PATH" -c "kill -$sigint \$$"
#'
#
#test_expect_success_foreach_option 'magic /dev/sydbox API is 1' '
#    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox" &&
#    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/1" &&
#    test_expect_code 1 sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/0"
#'
#
#test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works' '
#    sydbox -- "$SHELL_PATH" && <<EOF
#test -e /dev/sydbox/core/sandbox/write"?"
#test $? -eq 1 && exit 0
#EOF
#    sydbox -- "$SHELL_PATH" <<EOF
#test -e /dev/sydbox/core/sandbox/write:deny &&
#test -e /dev/sydbox/core/sandbox/write"?"
#EOF
#'
#
#test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works with -m switch' '
#    sydbox -m core/sandbox/write:deny -- "$SHELL_PATH" <<EOF
#test -e /dev/sydbox/core/sandbox/write"?"
#EOF
#'
#
#test_expect_success_foreach_option 'magic core/violation/exit_code:0 works' '
#    f="no-$(unique_file)" &&
#    rm -f "$f" &&
#    test_must_violate sydbox \
#        -m core/sandbox/write:deny \
#        -- "$SHELL_PATH" && <<EOF
#: > "$f"
#EOF
#    test_path_is_missing "$f"
#'
#
#test_expect_success_foreach_option 'magic core/violation/raise_fail:1 works' '
#    f="no-$(unique_file)" &&
#    d="$(unique_dir)" &&
#    mkdir "$d" &&
#    test_must_violate sydbox \
#        -m core/violation/raise_fail:1 \
#        -m core/sandbox/write:deny \
#        -- "$SHELL_PATH" && <<EOF
#: > "$d"/"$f"
#EOF
#    test_path_is_missing "$d"/"$f"
#'
#
#test_expect_success_foreach_option 'magic core/violation/raise_safe:1 works' '
#    f="$(unique_file)" &&
#    : > "$f" &&
#    test_must_violate sydbox \
#        -m core/violation/raise_safe:1 \
#        -m core/sandbox/write:deny \
#        -- emily access -e EACCES -w "$f"
#'

test_done
