#! /bin/bash

script=$0
srcdir=$(dirname ${script})

test -f "${srcdir}/configure.ac" || exit 1
pushd "${srcdir}" >/dev/null
autoreconf --force --install     || exit 1
popd >/dev/null

defaults=(--sysconfdir=/etc --sbindir=/sbin --localstatedir=/var)

"${srcdir}/configure" "${@:-${defaults[@]}}"

