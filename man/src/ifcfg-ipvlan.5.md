% IFCFG-IPVLAN(5) Wicked User Manual
% Clemens Famulla-Conrad
% November 2024

# NAME
ifcfg-ipvlan - IPVLAN interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`

# IPVLAN interface

To set up an IPVLAN interface, you need a configuration file with the `IPVLAN=yes` variable set.

An IPVLAN interface is conceptually similar to MACVLAN, see the following comparison:

  * MACVLAN operates at Layer 2 and assigns unique MAC address to each MACVLAN.\
    * Management support on most (L3+) managed switches\
    * Common DHCP support
  * IPVLAN operates at Layer 3 and shares the MAC address with the underlying interface.\
    * Supposed to be used with Advanced Router Configuration when the switches restrict
      the maximum number of mac addresses (or ACLs) per physical port.\
    * Limited SLAAC and DHCPv6 support

For detailed information, refer to the kernel documentation:
https://docs.kernel.org/networking/ipvlan.html

# OPTIONS

`IPVLAN <yes|no>`
:   This option must be set to **yes** to identify this configuration type as IPVLAN.

`IPVLAN_DEVICE`
:   Mandatory option to specify the lower (parent) interface for this IPVLAN interface.

`IPVLAN_MODE <l2|l3|l3s>`
:   Specifies the operational mode for the IPVLAN interface. For a given lower device, you can
    select one of these modes and all linked devices will operate in the same mode.

    Default: **l3**

`IPVLAN_FLAGS <bridge|private|vepa>`
:   Specifies the mode flags. Only one flag at a time is allowed. Similar to `IPVLAN_MODE` a
    given flag will be applied to all linked devices of one lower interface.

    Default: **bridge**


# EXAMPLES

Example `ifcfg-<name>` config file for an IPVLAN interface

```
STARTMODE=auto
BOOTPROTO=static
IPADDR=10.0.0.100/24

IPVLAN=yes
IPVLAN_DEVICE=eth0
IPVLAN_MODE=l3s
IPVLAN_FLAGS=bridge
```

# COPYRIGHT
Copyright (C) 2024 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
