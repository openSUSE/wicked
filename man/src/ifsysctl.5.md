% IFSYSCTL(5) Wicked User Manual
% Marius Tomaschewski
% October 09, 2024

# NAME
ifsysctl[-`<interface name>`] - per network interface sysctl settings

# SYNOPSIS
`/etc/sysctl.d/*.conf`

`/etc/sysctl.conf`

`/etc/sysconfig/network/ifsysctl`

`/etc/sysconfig/network/ifsysctl-<interface name>`

# DESCRIPTION

These files are intended to contain **sysctl** settings, that
should be applied when a network interface is created. This are
usually interface specific settings, like:

    net.ipv6.conf.eth0.use_tempaddr = 2

or

    net.ipv4.conf.eth0.rp_filter = 0

Settings from the global configuration files: ***/etc/sysctl.d/*.conf***,
**/etc/sysctl.conf** and **/etc/sysconfig/network/ifsysctl** are applied
for every interface created.

Settings from the **ifsysctl-<interface name>** file are applied for an
interface, when created, which has the corresponding interface name.

# SYNTAX

Wicked writes these settings directly to their corresponding **/proc/sys**
locations. It supports two separator characters for sysctl keywords: a "**.**"
in *default format* and a "**/**" in the *alternate format*. Therefore,
the syntax is basically the same as is found in the /etc/sysctl.conf file.

Interface names may contain a "**.**". In the default sysctl format using
a "**.**" as separator, that is any "**.**" in the interface name of the
keyword, has to be replaced with a "**/**". In the alternate sysctl format
with "**/**" as separator, normal interface names can be used.

*Note also*, that settings with variables in the global sysctl files will be
applied for every interface!

Further, files with variables are not compatible to the /etc/sysctl.conf file.

# EXAMPLES

Settings for "eth0" and "eth0.1" interfaces

    # using "." as separator:
    net.ipv6.conf.eth0.use_tempaddr = 2
    net.ipv6.conf.eth0/1.use_tempaddr = 2

    # using "/" as separator:
    net/ipv6/conf/eth0/use_tempaddr = 2
    net/ipv6/conf/eth0.0/use_tempaddr = 2


# COPYRIGHT
Copyright (C) 2022 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`ifup`** (8), **`ifcfg`** (5), **`sysctl`** (8)
