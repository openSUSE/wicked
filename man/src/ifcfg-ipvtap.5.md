% IFCFG-IPVTAP(5) Wicked User Manual
% Clemens Famulla-Conrad
% November 2024

# NAME
ifcfg-ipvtap - IPVTAP interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`

# IPVTAP interface

To set up an IPVTAP interface, you need a configuration file with the `IPVTAP=yes`
variable set.

An IPVTAP interface is conceptually similar to MACVTAP with the same difference
between MACVLAN and IPVLAN. The IPVTAP interface operate on Layer 3 and share the same
configuration options with IPVLAN.

# OPTIONS

`IPVTAP <yes|no>`
:   This option must be set to **yes** to identify this configuration type as IPVTAP.

`IPVTAP_DEVICE`
:   Mandatory option to specify the lower (parent) interface for this IPVTAP interface.

`IPVTAP_MODE <l2|l3|l3s>`
:   Specifies the mode for the IPVTAP interface. For a given lower device, you can
    select one of these modes and all linked devices will operate in the same mode.

    Default: **l3**

`IPVTAP_FLAGS <bridge|private|vepa>`
:   Specifies the mode flags. Only one flag at a time is allowed. Similar to `IPVTAP_MODE`, a
    given flag will be applied to all linked devices of one lower interface.

    Default: **bridge**


# EXAMPLES

Example `ifcfg-<name>` config file for an IPVTAP interface

```
STARTMODE=auto
BOOTPROTO=static
IPADDR=10.0.0.100/24

IPVTAP=yes
IPVTAP_DEVICE=eth0
IPVTAP_MODE=l3s
IPVTAP_FLAGS=bridge
```

# COPYRIGHT
Copyright (C) 2024 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`ifcfg-ipvlan`** (5), **`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
