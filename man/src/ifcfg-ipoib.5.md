% IFCFG-IPOIB(5) wicked | Wicked User Manual
% Clemens Famulla-Conrad
% April 30, 2024

# NAME
ifcfg-ipoib - Infiniband interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`


# Infiniband/IPoIB Interfaces

To identify an interface configuration as Infiniband/IPoIB you either need a config file with the `IPOIB=yes`
variable set or one using a config file name `ifcfg-ibN` or `ifcfg-ibN.XXXX` (e.g. ifcfg-ib0 or ifcfg-ib0.8001).

`IPOIB <yes|no>`
:    This option must be set to **yes** to identify this configuration as
     Infiniband/IPoIB, regardless of the configuration file name.

`IPOIB_DEVICE`
:    Used to create a child-/sub-interface of the given physical Infiniband
     interface with partition key as specified in **IPOIB_PKEY** section.
     The physical infiniband interface name is also read from the ifcfg-**ibN**.XXXX
     config file name, but the `IPOIB_DEVICE` variable has precedence.

`IPOIB_PKEY`
:    Specify the partition key of the child-/sub-subinterface. The child-/sub-interface
     will be created if it does not exists. The partition key is also extracted from the
     ifcfg-ibN.**XXX** config file name, but the `IPOIB_PKEY` variable has precedence.

`IPOIB_MODE`
:    Configure the transport mode of the Infiniband interface by setting this variable
     to **connected** (CM - Connected Mode) or **datagram** (UD - Unreliable Datagram).

`IPOIB_UMCAST`
:    Configure the user-multicast permission of the Infiniband interface
     by setting this variable to **allowed** or **disallowed**.



# EXAMPLE

Examples of Infiniband/IPoIB interface config files:

**ifcfg-ib0**\
```
IPOIB=yes
STARTMODE=auto
BOOTPROTO=static
IPADDR=10.0.0.100/24
```

**ifcfg-ib0.8001**\
```
IPOIB=yes
STARTMODE=auto
BOOTPROTO=dhcp
```

**ifcfg-custom1**\
```
IPOIB=yes
IPOIB_DEVICE=ib0
IPOIB_PKEY=8002
STARTMODE=auto
BOOTPROTO=dhcp
```


# COPYRIGHT
Copyright (C) 2024 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
