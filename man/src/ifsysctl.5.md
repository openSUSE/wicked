% IFSYSCTL(5) Wicked User Manual
% Marius Tomaschewski, Clemens Famulla-Conrad
% October 2024

# NAME
ifsysctl[-`<interface name>`] - per network interface sysctl settings

# SYNOPSIS

### **system sysctl** files:

    /boot/sysctl.conf-<kernelversion>
    /run/sysctl.d/*.conf
    /etc/sysctl.d/*.conf
    /usr/local/lib/sysctl.d/*.conf
    /usr/lib/sysctl.d/*.conf
    /lib/sysctl.d/*.conf
    /etc/sysctl.conf

### **wicked ifsysctl** files (deprecated):

    /etc/sysconfig/network/ifsysctl
    /etc/sysconfig/network/ifsysctl-`<interface>`

# DESCRIPTION

The settings from the **system sysctl** files are applied by `systemd-sysctl.service` at boot
as well as the per-interface settings by udev rules when the interface appears in the system.

The following configuration sets are supported by the kernel:

- **all**: common runtime behavior policy for all currently existing interfaces.
- **default**: template used to initialize the interface sysctls, when a new interface is created
- **`<interface>`**: interface specific behavior

Wicked is never applying the **all** or **default** sysctl settings to the kernel,
but considers them and the **`<interface>`** sysctl settings (with highest priority),
when parsing the `ifcfg-<interface>` files.

The ifcfg variables and the sysctl settings are used as protocol settings in the
effective wicked xml configuration, visible in the `'wicked show-config'` output.

The wicked xml interface configuration is sent by `'wicked ifup'` and `'wicked ifreload'`
to the `wickedd*` backends, which are applying the sysctl settings from the xml
configuration to the kernel on configuration changes, hotplug events and `wickedd`
service restart (e.g. on wicked package update).

Interface sysctl settings initialized by the kernel to **-1** (not applicable for this
interface) are not overwritten by **wickedd**.

# SYSCTL PITFALLS

- Each sysctl has its own specific processing in the kernel. For details, please read the kernel
  documentation `https://www.kernel.org/doc/Documentation/networking/ip-sysctl.rst`.

- Applying changes to the **all** sysctl set (e.g. using `'sysctl -w …'`) is propagated
  (in many cases) by the kernel in time of execution also to **default** and the interface
  specific sysctl of all existing interfaces.

- Enabling forwarding changes the system role from host to router. This has impact on
  several other sysctl's like the IPv6 RA processing (see accept_ra) and IPv6 autoconfiguration:

  - there is no automatic IPv6 default route configuration
  - there is no automatic IPv6 route to the prefix network
  - there are no IPv6 addresses applied by SLAAC and DHCPv6
  - the nameservers sent in the RA are not applied to resolv.conf

  The **`accept_ra = 2`** sysctl (on affected uplink interface) enables RA processing on a router.

- Wicked is considering **system sysctl** configuration and may revert temporary runtime
  changes (`'sysctl -w …'`), e.g. applied by another programs (see *DESCRIPTION*).

# SYSCTL VARIABLES

### IPv4

`net.ipv4.conf.{all,default,interface}.forwarding`
:    Enable IP forwarding changing the system role between host and router.

`net.ipv4.conf.{all,default,interface}.arp_notify`
:    Define mode for notification of address and device changes. This setting is
     also set by **SEND_GRATUITOUS_ARP**, which has precedence over sysctl (see *man ifcfg*).

### IPv6:

`net.ipv6.conf.{all,default,interface}.disable_ipv6`
:    Enable/Disable IPv6 operation.

`net.ipv6.conf.{all,default,interface}.forwarding`
:    Enable IPv6 forwarding changing the system role between host and router.
     Note: Several other sysctl's, dhcp6, auto6 and routing have functional dependency to the `forwarding` sysctl (see *SYSCTL PITFALLS*).

`net.ipv6.conf.{all,default,interface}.accept_ra`
:    Accept Router Advertisements and perform IPv6 autoconfiguration of the interface
     if **accept_ra > forwarding**.

`net.ipv6.conf.{all,default,interface}.autoconf`
:    Autoconfigure addresses using Prefix Information in Router Advertisements.

`net.ipv6.conf.{all,default,interface}.use_tempaddr`
:    Preference for Privacy Extensions (RFC3041), *ignored* for loopback interface.

`net.ipv6.conf.{all,default,interface}.accept_dad`
:    Whether to accept DAD (Duplicate Address Detection), *ignored* for loopback interface.

`net.ipv6.conf.{interface}.accept_redirects`
:    Accept Redirects. Wicked considers only interface specific settings.

`net.ipv6.conf.{all,default,interface}.addr_gen_mode`
:    Defines how link-local and managed autoconf addresses are generated.

`net.ipv6.conf.{all,default,interface}.stable_secret`
:    This IPv6 address will be used as a secret to generate IPv6 addresses for
     link-local and autoconfigured addresses.

# SYNTAX

The sysctl configuration supports two separator characters for sysctl keywords: a "**.**"
in *default format* and a "**/**" in the *alternate format*. Therefore,
the syntax is the same as is found in the */etc/sysctl.conf* file.

# EXAMPLES

Settings for "eth0" and "eth0.1" interfaces

    # using "." as separator:
    net.ipv6.conf.eth0.use_tempaddr = 2
    net.ipv6.conf.eth0/1.use_tempaddr = 2

    # using "/" as separator:
    net/ipv6/conf/eth0/use_tempaddr = 2
    net/ipv6/conf/eth0.1/use_tempaddr = 2

# COPYRIGHT
Copyright (C) 2024 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`ifup`** (8), **`ifcfg`** (5), **`sysctl`** (8), **`systemd-sysctl`** (8)
