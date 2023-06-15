#!/bin/bash
#
# Copyright (C) 2012, Olaf Kirch <okir@suse.de>
# Copyright (C) 2012-2022 SUSE LLC
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License along
#       with this program; if not, see <http://www.gnu.org/licenses/>.
#
#       Authors:
#		Olaf Kirch <okir@suse.de>
#		Marius Tomaschewski <mt@suse.de>
#
# This extension scripts implements all supported interface operations
# related to firewalling.
#
# If you want to extend the functionality of this script, you first need
# the extend the schema file (firewall.xml) by adding new members to e.g. the
# fw-request types.
#
# If you want to implement additional methods, you can also add new
# <method> elements to the same schema file. However, in addition to that, you
# also need to add the necessary script actions to wicked's configuration
# file in /etc/wicked/config.xml, so that the daemon knows that it should call
# this extension script to handle these.
#

###
### remove comment chars to trace this script:
###
#exec 2>/tmp/wicked-firewall.$$.trace
#set -vx

wicked="@wicked_sbindir@/wicked"
systemctl="/usr/bin/systemctl"
firewalld_cmd="/usr/bin/firewall-cmd"
firewalld_service="firewalld.service"

shopt -s nullglob
action=$1
shift

wicked_config_get_zone()
{
	test "X$1" != "X" -a -f "$1" || return 0
	$wicked xpath --file "$1" --reference '/arguments/config' '%{?zone}' 2>/dev/null
}

firewalld_is_active()
{
	test -x "$firewalld_cmd" && \
		"$systemctl" -q is-active "$firewalld_service" &>/dev/null
}

firewalld_up()
{
	test "X$WICKED_INTERFACE_NAME" = "X" && return 1

	local ZONE=`wicked_config_get_zone "$WICKED_ARGFILE"`

	# Assign the firewalld zone permanently, this sync wicked with firewalld config files.
	"$firewalld_cmd" --permanent --zone="$ZONE" --change-interface="$WICKED_INTERFACE_NAME" &>/dev/null
	# Apply same rule to runtime config.
	"$firewalld_cmd" --zone="$ZONE" --change-interface="$WICKED_INTERFACE_NAME" &>/dev/null
}

firewalld_down()
{
	test "X$WICKED_INTERFACE_NAME" = "X" && return 1

	# Do not change firewalld settings on ifdown, neither for FIREWALL=yes
	# nor for FIREWALL=no (bsc#1201053 and bsc#1189560).
	# The problem is, that `firewall-cmd --permanent` also change ifcfg
	# files, thus it would remove the ZONE= setting from ifcfg on ifdown.
	# Changing only runtime firewall settings, trigger a unexpected
	# inconsistency between runtime+persistent config.
}

case $action in
up)
	if firewalld_is_active ;  then
		firewalld_up
	fi
;;

down)
	if firewalld_is_active ; then
		firewalld_down
	fi
;;

*)
	logger -p user.debug -t "wicked-firewall" "Unsupported script action '$action'"
;;
esac

exit 0
