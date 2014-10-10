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

test_expect_success_foreach_option 'return success if tracee returns success' '
    sydbox -- syd-true
'

test_expect_success_foreach_option 'return success if tracee returns success (STATIC)' '
    sydbox -- syd-true-static
'

test_expect_success_foreach_option 'return success if initial tracee returns success (FORK)' '
    sydbox -- syd-true-fork 256
'

test_expect_success_foreach_option 'return success if initial tracee returns success (STATIC|FORK)' '
    sydbox -- syd-true-fork-static 256
'

test_expect_success_foreach_option 'return success if initial tracee returns success (PTHREAD)' '
    sydbox -- syd-true-pthread 32
'

test_expect_success_foreach_option 'return failure if tracee returns failure' '
    test_expect_code 1 sydbox -- syd-false
'

test_expect_success_foreach_option 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 sydbox -- syd-false-static
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork 256
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork-static 256
'

test_expect_success_foreach_option 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 sydbox -- syd-false-pthread 32
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated' '
    test_expect_code 130 sydbox -- syd-abort 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort 15 # SIGTERM
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated (STATIC)' '
    test_expect_code 130 sydbox -- syd-abort-static 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-static 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-static 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-static 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-static 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-static 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-static 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-static 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-static 15 # SIGTERM
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated (FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork 256 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork 256 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork 256 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork 256 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork 256 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork 256 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork 256 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork 256 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork 256 15 # SIGTERM
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated (STATIC|FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork-static 256 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork-static 256 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork-static 256 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork-static 256 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork-static 256 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork-static 256 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork-static 256 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork-static 256 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork-static 256 15 # SIGTERM
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated (PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread 8 15 # SIGTERM
'

test_expect_success_foreach_option 'return 128 + $SIGNUM if tracee is terminated (STATIC|PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread-static 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread-static 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread-static 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread-static 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread-static 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread-static 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread-static 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread-static 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread-static 8 15 # SIGTERM
'

test_expect_success_foreach_option 'magic /dev/sydbox API is 1' '
    sydbox -- sh -c "test -e /dev/sydbox" &&
    sydbox -- sh -c "test -e /dev/sydbox/1" &&
    test_expect_code 1 sydbox -- sh -c "test -e /dev/sydbox/0"
'

test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works' '
    sydbox -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF &&
    sydbox -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success_foreach_option 'magic /dev/sydbox boolean checking works with -m switch' '
    sydbox -m core/sandbox/write:deny -- sh <<-\EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

#test_expect_success_foreach_option 'magic core/violation/exit_code:0 works' '
#    f="no-$(unique_file)" &&
#    rm -f "$f" &&
#    test_must_violate sydbox \
#        -m core/sandbox/write:deny \
#        -- sh && <<EOF
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
#        -- sh && <<EOF
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
