% IFCFG-BONDING(5) Wicked User Manual
% Wilken Gottwalt -- original bonding man page
% May 6, 2024

# NAME
ifcfg-bonding - Bonding interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`


# Bonding Interfaces

To setup a bonding interface you need a configuration file ifcfg-bond<X> with
the usual network settings. But you must add additional variables

`BONDING_MASTER`
:    Must be set to 'yes' to identify this interface as a bonding interface.

`BONDING_SLAVE_<X>`
:    Here you specify the interface name representing the slave network interfaces.
     Note also: Bonding slave interfaces are reserved for the bonding and are not
     usable for any another purposes (unlike e.g. interfaces used for VLANs) and
     the bonding master manages the slaves itself, e.g. it sets the MAC address
     on the slaves by default. To configure this accordingly, set BOOTPROTO=none
     in the ifcfg file of each slave interfaces to avoid any IP or link-layer
     setup on these interfaces. Wicked will apply the link settings
     (e.g. for fail_over_mode=active) at enslave time.

`BONDING_MODULE_OPTS`
:    Contains bonding options. Here you can set interface timeouts or working modes
     ('mode=active-backup' for backup mode). For additional information take a look
     into the documentation mentioned at the bottom.
     Note, that this options are not passed as parameters to the bonding kernel
     module any more, but set via sysfs interface. This variable will be renamed
     in the feature.


# EXAMPLE

Example for a bonding interface on eth0 and eth1 using the backup mode

*ifcfg-bond0*
```
STARTMODE='onboot'
BOOTPROTO='static'
IPADDR='192.168.0.1/24'
BONDING_MASTER='yes'
BONDING_SLAVE_0='eth0'
BONDING_SLAVE_1='eth1'
BONDING_MODULE_OPTS='mode=active-backup miimon=100'
```

*ifcfg-eth0*
```
STARTMODE='hotplug'
BOOTPROTO='none'
#ETHTOOL_OPTIONS='wol g'
```

*ifcfg-eth1*
```
STARTMODE='hotplug'
BOOTPROTO='none'
#ETHTOOL_OPTIONS='wol g'
```

**Note**, that the slaves are configured with BOOTPROTO='none', what avoids
link set UP and IP configuration of the slaves. Further also `STARTMODE='hotplug'`,
allowing that some (all) of the slaves are allowed to be missed at boot time.
The hotplug slaves will be added to the bond as soon as are become available
(udev BUS based persistent name rule or manual ifup bond0 is required).
Wicked waits for the slaves, but when there is no slave available
at bonding start time (boot time), the bonding creation will fail and also
wicked will report an error.

# Additional Information

For additional and more general information take a look into
http://www.linuxfoundation.org/collaborate/workgroups/networking/bonding
or
/usr/src/linux/Documentation/networking/bonding.txt.
Maybe you need to install the kernel sources to get this additional
documentation.

The configuration of routes for this kind of interface does not differ from
ordinary interfaces. See `man routes` for details.


# COPYRIGHT
Copyright (C) 2014-2024 SUSE LLC

# BUGS
Please report bugs at <http://bugs.opensuse.org>

# SEE ALSO
**`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
