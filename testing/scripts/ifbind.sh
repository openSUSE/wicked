#!/bin/bash

probe_pci_bus()
{
	local dev=$1 ; shift
	test -n "$dev" || return 1

	echo "Probing device $dev on pci bus"
	echo "$dev" > "/sys/bus/pci/drivers_probe"
}

probe_bus()
{
	bus=$1 ; shift
	case $bus in
		pci) probe_pci_bus "$@" ; return $? ;;
	esac
	return 1
}

probe()
{
	type=$1 ; shift
	case $type in
	bus) probe_bus "$@" ; return $? ;;
	esac
	return 1
}

call_probe()
{
	set -- $(IFS="-"; echo $"1")
	probe "$@" || {
		echo "Unable to probe $@"
		return 1
	}
	return 0
}

settle=0
case $1 in
--settle)	settle=1 ;;
esac

status=0
action=$1 ; shift
case $action in
probe)
	while [ $# -gt 0 ]; do
		arg=$1 ; shift
		call_probe "$arg" || status=$?
	done
;;
bind|up|add)
	while [ $# -gt 0 ]; do
		name=$1 ; shift
		test -f "/tmp/if${name}.devinfo" || {
			echo "Can't find devinfo for $name"
			status=1
			continue
		}

		. "/tmp/if${name}.devinfo"

		echo "add > $DEVPATH/uevent"
		echo -n add > "$DEVPATH/uevent"
		test $settle -ne 0 && udevadm settle

		if [ ! -d $DEVPATH/driver -a -d "$DRVPATH" ] ; then
			echo "$DEVICE > $DRVPATH/bind"
			echo -n "$DEVICE" > $DRVPATH/bind
		fi
		test $settle -ne 0 && udevadm settle
	done
;;
unbind|down|del)
	while [ $# -gt 0 ]; do
		name=$1 ; shift
		test -d "/sys/class/net/$name" || { status=1 ; continue; }

		DEVPATH=$(cd -P "/sys/class/net/$name/device" 2>/dev/null ; echo "$PWD")
		test -n "$DEVPATH" || { status=1 ; continue; }
		DRVPATH=$(cd -P "$DEVPATH/driver" 2>/dev/null ; echo "$PWD")
		test -n "$DRVPATH" || { status=1 ; continue; }
		DEVICE=${DEVPATH##*/}
		test -n "$DEVICE"  || { status=1 ; continue; }

		echo "echo -n '$DEVICE' > '$DRVPATH/unbind'"
		echo -n "$DEVICE" > "$DRVPATH/unbind" && {
			rm -f "/tmp/if${name}.devinfo"
			{
				echo "DEVICE='$DEVICE'"
				echo "DEVPATH='$DEVPATH'"
				echo "DRVPATH='$DRVPATH'"
			} > "/tmp/if${name}.devinfo"
		}
	done
;;
*)
	echo "Usage: $0 unbind <ifname>..."
	echo "       $0 bind   <ifname>..."
	echo "or     $0 probe  bus-pci-<id>..."
;;
esac
exit $status

