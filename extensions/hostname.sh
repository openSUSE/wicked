#!/bin/bash

hostnamedir=@wicked_statedir@/extension/hostname
defaulthostname=/etc/hostname

type=""
family=""
ifname=""

shopt -s nullglob
cmd=$1; shift

while [ $# -gt 0 ]
do
	case $1 in
	-t) shift ; type=$1 ;;
	-f) shift ; family=$1 ;;
	-i) shift ; ifname=$1 ;;
	--) shift ; break ;;
	-*) echo "unknown option '$1'" >&2 ; exit 1 ;;
	 *) break ;;
	esac
	shift
done

get_default_hostname()
{
	local h
	test -s "$defaulthostname" && \
	read -t 1 h < "$defaulthostname" 2>/dev/null && \
	echo "${h%%.*}"
}

get_current_hostname()
{
	local h=`/bin/hostname 2>/dev/null`
	echo "${h%%.*}"
}

case $cmd in
backup)
	: # /etc/hostname is not modified by `hostname`, so no need for explicit backup.
;;

restore)
	# Remove any hostname files.
	rm -f "${hostnamedir}/hostname."* 2>/dev/null

	# Restore hostname to original.
	rc=0
	if test -s "$defaulthostname" ; then
		def_hostname=`get_default_hostname`
		curr_hostname=`get_current_hostname`
		if test "X${def_hostname}" != "X" -a "X${curr_hostname}" != "X${def_hostname}" ; then
			/bin/hostname "${def_hostname}" ; rc=$?

			rcsyslog reload &>/dev/null
		fi
	fi
	exit $rc
;;

install)
	found=""
	hostname_arg="${1%%.*}"
	hostname_cur=`get_current_hostname`
	hostnamefile="hostname.${ifname}.${type}.${family}"

	# Check if hostname cache file exists and is up-to-date
	for f in "${hostnamedir}/hostname."* ; do
		test -f "$f" || continue
		read -t 1 h < "$f" 2>/dev/null
		h="${h%%.*}"
		if test "X$h" != "X$hostname_cur" ; then
			rm -f "$f"
		else
			found=$f
			break
		fi
	done

	rc=0
	if test "$found" = "" -o -e "${hostnamedir}/${hostnamefile}" ; then
		# We've either not found any files, so we're first, or we're
		# processing an update from the first lease which controls hostname.
		if test "X${hostname_arg}" != "X" -a "X${hostname_cur}" != "X${hostname_arg}" ; then
			# Only update the hostname it differs from the system.
			/bin/hostname "${hostname_arg}" 2>/dev/null ; rc=$?

			rcsyslog reload &>/dev/null
		fi

		# Store regardless of whether hostname differs from the system.
		echo "${hostname_arg}" > "${hostnamedir}/${hostnamefile}" 2>/dev/null
	fi
	exit $rc
;;

remove)
	hostnamefile="hostname.${ifname}.${type}.${family}"

	rc=0
	# First check if remove request is for correct lease/file.
	if test -e "${hostnamedir}/${hostnamefile}" ; then
		# Remove the requested file first.
		rm -f "${hostnamedir}/hostname.${ifname}.${type}.${family}" 2>/dev/null

		# Restore original hostname.
		if test -s "$defaulthostname" ; then
			def_hostname=`get_default_hostname`
			curr_hostname=`get_current_hostname`
			if test "X${def_hostname}" != "X" -a "X${curr_hostname}" != "X${def_hostname}" ; then
				/bin/hostname "${def_hostname}" ; rc=$?

				rcsyslog reload &>/dev/null
			fi
		fi
	fi
	exit $rc
;;

*)
	echo "$0: command '$cmd' not supported" >&2
	exit 1
;;
esac
