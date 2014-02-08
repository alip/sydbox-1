#!/usr/bin/env bash

echo >&2 ">>> HOST ${HOSTNAME} <<<"
set -x
uname -a
zgrep SECCOMP /proc/config.gz
zgrep CONFIG_CROSS_MEMORY_ATTACH /proc/config.gz

cat ./config.log

make V=1 all
r=$?
[[ $r -ne 0 ]] && exit $r
make V=1 check
r=$?
r=1
if [[ $r -ne 0 ]]; then
    cat tests/test-suite.log
    while read -r -d $'\0' dir; do
        bname=$(basename "$dir")
        tname="${bname##trash directory.}"
        echo >&2 ">>> FAIL $tname"
        find "${dir}" -exec stat '{}' \;
        cat tests/"${tname}".log
    done < <(find tests -name 'trash*' -print0)
fi
exit $r
