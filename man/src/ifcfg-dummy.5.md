% IFCFG-DUMMY(5) wicked | Wicked User Manual
% Karol Mroz, Clemens Famulla-Conrad
% April 30, 2024

# NAME
ifcfg-dummy - Dummy interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`


# Dummy Interfaces

To setup a dummy interface you either need a configuration file with the `DUMMY=yes`
variable set or one using a basename **ifcfg-dummyX** (e.g. ifcfg-dummy0).

`DUMMY <yes|no>`
:   This option must be set to **yes** to identify this configuration type
    as dummy, regardless of the configuration file name.

`BOOTPROTO`
:   may be set to "none" or "static". Note that "dhcp" and others are not
    supported. See also `man ifcfg` and `man routes` for details.


# EXAMPLE

Example `ifcfg-<name>` config file for a dummy interface:

```
DUMMY=yes
STARTMODE=auto
BOOTPROTO=static
IPADDR=10.0.0.100/24
```

# COPYRIGHT
Copyright (C) 2024 SUSE LLC

# BUGS
Please report bugs at <http://bugs.opensuse.org>

# SEE ALSO
**`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
