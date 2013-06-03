#! /bin/bash

script=$0
srcdir=$(dirname ${script})

test -f "${srcdir}/configure.ac" || exit 1
pushd "${srcdir}" >/dev/null
autoreconf --force --install     || exit 1
popd >/dev/null

case "$(uname -m)" in
	x86_64|s390x|ppc64|powerpc64) _lib=lib64 ;;
	*) _lib=lib ;;
esac

export CFLAGS="${CFLAGS:- -O1 -g -D_FORTIFY_SOURCE=2 -fstack-protector -Wall -Wextra -Wno-missing-field-initializers}"
defaults=(--sysconfdir=/etc --prefix=/usr --libdir=/usr/${_lib} --libexecdir=/usr/${_lib} --datadir=/usr/share --localstatedir=/var)

"${srcdir}/configure" "${@:-${defaults[@]}}"

