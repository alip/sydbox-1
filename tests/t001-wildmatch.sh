#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v3 or later

test_description='check wildmatch'
. ./test-lib.sh

# The test script will output its own plan
test_external_has_tap=1

test_external_without_stderr WILDMATCH 'matching filenames or pathnames' \
    "${TEST_DIRECTORY}"/wildtest "${TEST_DIRECTORY}"/wildtest.txt

test_done
