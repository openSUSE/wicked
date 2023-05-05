#! /bin/bash

script=$0
srcdir=$(dirname ${script})

debug='-g -O1 -D_FORTIFY_SOURCE=2'
werror=''
args=()
while test $# -gt 0 ; do
	case $1 in
	-debug0) debug='-g -O0'   ;;
	-Werror) werror='-Werror' ;;
	*)       args+=("$1")     ;;
	esac
	shift
done

test -f "${srcdir}/configure.ac" || exit 1
pushd "${srcdir}" >/dev/null
autoreconf --force --install     || exit 1
popd >/dev/null

statedir=$(rpm -E '%{!_rundir:/var}' 2>/dev/null)
_lib=$(rpm -E '%_lib' 2>/dev/null)
test -n "$_lib" || case "$(uname -m)" in
	x86_64|s390x|ppc64|powerpc64) _lib=lib64 ;;
	*) _lib=lib ;;
esac

export CFLAGS="${CFLAGS:--std=gnu89 ${debug} -fstack-protector -Wall -Wextra -Wno-unused-parameter ${werror}}"

prefix=/usr
defaults=(
	--enable-silent-rules
	--sysconfdir=/etc
	--prefix="${prefix}"
	--libdir="${prefix}/${_lib}"
	--libexecdir="${prefix}/lib"
	--datadir="${prefix}/share"
	--localstatedir="${statedir}"
)

"${srcdir}/configure" "${defaults[@]}" "${args[@]}"

