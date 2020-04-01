#!/bin/bash
#
###############################################################
#                                                             #
# SÜSE Linux Products GmbH 2013                               #
#                                                             #
# Interfaces monitor for wickedd                              #
#                                                             #
# Author: Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>      #
#                                                             #
###############################################################

EXPECTED_ARGS=0

CONFIG_ORIGIN='config-origin="%{?client-state/config/origin}"'
CONFIG_UUID='config-origin="%{?client-state/config/uuid}"'
CONFIG_OWNER='owner-uid="%{?client-state/config/owner-uid}"'
PERSISTENT='persistent="%{?client-state/control/persistent}"'
USERCONTROL='usercontrol="%{?client-state/control/usercontrol}"'
# INIT_STATE='init-state="%{?client-state/stats/init-state}"'
# INIT_TIME='init-time="%{?client-state/stats/init-time}"'
# LAST_TIME='last-time="%{?client-state/stats/last-time}"'

number='^[0-9]+$'
if [[ $# -lt $EXPECTED_ARGS || ! -z "$1" && ! $1 =~ $number ]]; then
	echo "Usage: `basename $0` [interval]"
	exit 1;
fi

while :; do

	if [[ ! -z "$1"  && $1 -ne 0 ]]; then
		clear;
	fi

	wicked show-xml | wicked xpath --reference '/object/interface' "name=\"%{?name}\" ${CONFIG_ORIGIN} ${CONFIG_UUID} ${CONFIG_OWNER} ${PERSISTENT} ${USERCONTROL}" | column -t || exit;

	if [[ -z "$1"  || $1 -eq 0 ]]; then
		exit;
	fi

	sleep $1;
done
