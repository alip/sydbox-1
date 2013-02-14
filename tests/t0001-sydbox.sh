#!/bin/sh
#!/bin/sh
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='test the very basics of sydbox'
. ./test-lib.sh

test_expect_success 'return success if child returns success' '
    sydbox -- "$SHELL_PATH" -c "exit 0"
'

test_expect_success 'return error if child returns error' '
    sydbox -- "$SHELL_PATH" -c "exit 1"
    test $? -eq 1
'

test_expect_success 'compatible long options with sydbox-0' '
    sydbox --help &&
    sydbox --version &&
    sydfmt --help &&
    sydfmt --version
'

test_expect_success 'magic /dev/sydbox API is 1' '
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox" &&
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/1" &&
    sydbox -- "$SHELL_PATH" -c "test -e /dev/sydbox/0 || exit 0"
'

test_expect_success 'magic /dev/sydbox boolean checking works' '
    sydbox -- "$SHELL_PATH" && <<EOF
test -e /dev/sydbox/core/sandbox/write"?"
test $? -eq 1 && exit 0
EOF
    sydbox -- "$SHELL_PATH" <<EOF
test -e /dev/sydbox/core/sandbox/write:deny &&
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success 'magic /dev/sydbox boolean checking works with -m switch' '
    sydbox -m core/sandbox/write:deny -- "$SHELL_PATH" <<EOF
test -e /dev/sydbox/core/sandbox/write"?"
EOF
'

test_expect_success 'magic core/violation/exit_code:0 works' '
    f="no-$(unique_file)" &&
    rm -f "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- "$SHELL_PATH" && <<EOF
: > "$f"
EOF
    test_path_is_missing "$f"
'

test_expect_success 'magic core/violation/raise_fail:1 works' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/violation/raise_fail:1 \
        -m core/sandbox/write:deny \
        -- "$SHELL_PATH" && <<EOF
: > "$d"/"$f"
EOF
    test_path_is_missing "$d"/"$f"
'

test_expect_success 'magic core/violation/raise_safe:1 works' '
    f="$(unique_file)" &&
    : > "$f" &&
    test_must_violate sydbox \
        -m core/violation/raise_safe:1 \
        -m core/sandbox/write:deny \
        -- emily access -e EACCES -w "$f"
'

test_done
