% wicked-redfish(8) Wicked User Manual
% Marius Tomaschewski
% Apr 12, 2021

# NAME
wicked redfish - redfish network host interface configuration utilities

# SYNOPSIS
`wicked redfish [options] <action>`

# DESCRIPTION
The Redfish Network Host Interface defined by the DMTF Redfish Host Interface
Specification enables the software running on a computer system to access the
Redfish Service, which can be used to manage that computer system.

Machines supporting a Redfish Network Host Interface, provide an SMBIOS (3.0)
Management Controller Host Interface (Type 42) structure containing a Device
Description of the Network (Type 40h) Interface and "Redfish over IP" Protocol
(Type 04h) records with the configuration to use for this network interface,
visible in e.g. '`dmidecode -t 42`' output.

The Redfish Network Host Interface needs to be enabled and/or configured in
the Management Controller (BMC, firmware, ...) -- please consult the machine
vendor documentation for further details.
With enabled Redfish Network Host Interface in the Management Controller, the
SMBIOS structure and the network interface (usb, pci) are available/appear in
the system (e.g. '`hwinfo --netcard`' or '`lsusb`', '`lspci`', '`ip link show`').

The '`wicked redfish`' command implements utility actions decoding the SMBIOS
structures to configure the Network Host Interface with these settings, used
by other parts of wicked.

The automatic setup of the Redfish Network Host Interface from SMBIOS settings
with wicked is (currently) disabled by default, use the:
```
   wicked redfish enable
```
command to enable it once.

When enabled, the '`wicked ifup`', '`wicked ifreload`', '`wicked show-config`'
and related commands to setup/shutdown interfaces as well as the '`systemctl`'
(`start`, `stop`, `reload`) actions to the '`network.service`' (alias to an
enabled '`wicked.service`') will consider the Redfish Network Host Interfaces.


# OPTIONS

`--help`, `-h`
:   show short options and actions description and exit

# ACTIONS

`enable`
:   Enables the redfish network host interface setup.

    Creates an `/etc/wicked/client-redfish.xml` configuration file adding the
    '`redfish-config`' extension to the "firmware:" (netif-firmware-discovery)
    configuration source set, to decode SMBIOS as a "firmware:redfish" wicked
    interface configuration requested by/during e.g. '`wicked ifup all`' run.

`disable`
:   Disables the redfish network host interface setup.

    Deletes the `/etc/wicked/client-redfish.xml` configuration file.

## Utility actions

`show-config`
:   Decodes the SMBIOS structures with the Network Host Interface reference
    and "Redfish over IP" protocol settings as a wicked "firmware:redfish"
    configuration.

    An underlying command used by an (enabled) '`redfish-config`' extension
    providing configuration to '`wicked ifup`' and related commands.

`list-ifnames`
:   Decodes the SMBIOS structures and shows the referenced network host and
    the vlan interface name -- if vlan is defined by the redfish protocol.

`hosts-update`
:   Decodes the Redfish Service IP and Hostname from SMBIOS structure and
    updates the redfish-localhost entries in `/etc/hosts`.

    Implements the "post-up" action of the '`redfish-update`' script hook
    used in the "firmware:redfish" configuration executed at the end of
    an ifup run.

`hosts-remove`
:   Removes the redfish-localhost entries from `/etc/hosts`.

    Implements the "pre-down" action of the '`redfish-update`' script hook
    used in the "firmware:redfish" configuration executed in ifdown run.

# EXAMPLE

An Redfish Network Host Interface SMBIOS settings using DHCPv4 by dmidecode:
```
# dmidecode -t 42
Management Controller Host Interface
	Host Interface Type: Network
	Device Type: USB
		idVendor: 0x03f0
		idProduct: 0x2927
		Protocol ID: 04 (Redfish over IP)
			Service UUID: 8388efa4-6501-53a1-a1da-b6ee02cebbdf
			Host IP Assignment Type: DHCP
			Host IP Address Format: IPv4
			Redfish Service IP Discovery Type: DHCP
			Redfish Service IP Address Format: IPv4
			Redfish Service Hostname: virt152-sp
```

The network interface name (as identified in the '`hwinfo --netcard`') output is:
```
# ip link show dev usb0
11: usb0: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
    link/ether 3a:d8:86:7c:01:64 brd ff:ff:ff:ff:ff:ff
```

The network interface name(s) can be identified/resolved by wicked:
```
# wicked redfish list-ifnames
usb0
```

The Redfish Network Host Interface SMBIOS settings decoded by wicked to an interface config:
```
# wicked redfish show-config
<interface origin="firmware:redfish">
  <name>usb0</name>
  <scripts>
    <post-up>
      <script>wicked:redfish-update</script>
    </post-up>
    <pre-down>
      <script>wicked:redfish-update</script>
    </pre-down>
  </scripts>
  <ipv4>
    <enabled>true</enabled>
  </ipv4>
  <ipv4:dhcp>
    <enabled>true</enabled>
    <update/>
  </ipv4:dhcp>
</interface>
```

Once the Redfish Network Host Interface setup with wicked has been enabled with:
```
# wicked redfish enable
```

The '`wicked show-config`' command contains the (same as above) wicked configuration
for the `usb0` interface and commands setting up interfaces are considering it:
```
# wicked ifreload all
usb0            device-ready
usb0            up
# wicked ifstatus usb0
usb0            up
      link:     #11, state up, mtu 1500
      type:     ethernet, hwaddr 3a:d8:86:7c:01:64
      config:   firmware:redfish
      leases:   ipv4 dhcp granted
      addr:     ipv4 16.1.15.2/30 [dhcp]
# grep redfish-localhost /etc/hosts
16.1.15.1	redfish-localhost virt152-sp
```

After disabling of the Redfish Network Host Interface setup with wicked, the
'`wicked show-config`' command stops to show the interface configuration and the
commands to setup interfaces will (shut it down if still active and) stop to
consider it in interface setup:
```
# wicked redfish disable
# wicked ifreload all
usb0            device-ready
# grep redfish-localhost /etc/hosts
# wicked ifstatus usb0
usb0            device-unconfigured
      link:     #11, state down, mtu 1500
      type:     ethernet, hwaddr 3a:d8:86:7c:01:64
# ip link show dev usb0
11: usb0: <BROADCAST,MULTICAST> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
    link/ether 3a:d8:86:7c:01:64 brd ff:ff:ff:ff:ff:ff
# wicked ifreload all
wicked: ifreload: no configuration changes to reload
```

# NOTES
The implementation is based on the following specifications:

- DMTF DSP0134, System Management BIOS Reference Specification (SMBIOS), Version 3.5.0
  - https://www.dmtf.org/standards/smbios, https://www.dmtf.org/dsp/DSP0134
- DMTF DSP0270, Redfish Host Interface Specification, Version 1.3.0
  - https://www.dmtf.org/standards/redfish, https://www.dmtf.org/dsp/DSP0270

and covers decoding of the (raw) SMBIOS Type 42 structures from sysfs
files (`/sys/firmware/dmi/tables/smbios_entry_point` and `DMI`) with:

 - Network Host Interface (40h) Device Description Data for:
   - USB Network Interface
   - PCI/PCIe Network Interface
   - USB Network Interface v2
 - Multiple Redfish over IP Protocol records with
   - Static, DHCP, AutoConfigure
   Assignment/Discovery Types for IPv4 and IPv6
 - Merge of multiple SMBIOS structures for the same device

Not yet implemented are:

 - "Preferred IP" Address in AutoConfigure
 - PCI/PCIe Network Interface v2
 - Credential Bootstrapping

# COPYRIGHT
Copyright (C) 2022 SUSE LLC

# BUGS
Please report bugs as described at http://bugs.opensuse.org

# SEE ALSO
**`wicked`**(8), **`wicked-config`**(5)
