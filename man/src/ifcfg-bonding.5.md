% IFCFG-BONDING(5) wicked | Wicked User Manual
% Wilken Gottwalt (original bonding man page)
  Pawel Wieczorkiewicz
  Marius Tomaschewski
  Clemens Famulla-Conrad
% May 30, 2024

# NAME
ifcfg-bonding - Bonding interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`


# Bonding Interfaces

To setup a bonding interface you need an configuration file ifcfg-<ifname> with
the following bond specific variables:

`BONDING_MASTER`
:    Must be set to 'yes' to identify the configuration as for a bonding interface.

`BONDING_SLAVE_<X>`
:    Here you specify the interface name representing the port network interfaces.
     Supported are Ethernet **or** Infiniband(-Child) interfaces.

     The Bonding master takes over the control of these port interfaces, which
     are not usable for another purposes, especially not for an L3 (IP) setup.
     It propagates several settings to the ports, e.g. it sets the MAC address
     (not on Infiniband) and MTU. Also if there is a vlan on top of the bond,
     it offloads the vlan setup to the ports.

     Without a dedicated `ifcfg-<port>` configuration file, the auto generated
     port configuration is:

         STARTMODE=hotplug
         BOOTPROTO=none

     The use of `STARTMODE=hotplug` for the ports ensures, that wicked does not
     wait for the ports while setup, but only for the bonding master, which
     calculates it's own carrier state from the carrier on the ports using own
     (configurable) logic and signals it's carrier when a sufficient number of
     ports is available (default: min_links=1).

     **Note**: It's strongly recommended to change the udev rule to match the
     ports by Bus-ID (`KERNELS=="…"`) in order to assign a persistent name via
     `/etc/udev/rules.d/70-persistent-net.rules` (can be done in YaST2) as the
     bonding master usually sets the same MAC address on all it's ports.

     The use of `BOOTPROTO=none` disables IPv6 on the port interfaces via
     sysctl (and IPv4 in wicked) to ensures that no L3 / IP setup (from
     `ifcfg-<port>` config) is applied to the ports.

`BONDING_MODULE_OPTS`
:   Contains bonding options to configure the aggregation mode, port link
    monitoring and another options.

    Note, that this options are not passed as parameters to the bonding kernel
    module any more, but configured by wicked via the `rtnetlink` interface.

    Bonding of Infiniband(-Child) port interfaces requires `mode=active-backup`
    mode along with the `fail_over_mac=active` option.

    The following options are currently implemented in wicked.

    - Link aggregation operation mode:

        - **mode**=[`balance-rr`(0) | `active-backup`(1) | `balance-xor`(2) | `broadcast`(3) | `802.3ad`(4) | `balance-tlb`(5) | `balance-alb`(6)]

            The `active-backup`, `balance-tlb` and `balance-alb` modes do not
            require any special switch support. The `802.3ad` mode requires
            dynamic (lacp) and the `balance-xor`, `balance-rr`, `broadcast`
            a static link aggregation group/LAG switch configuration.

    - Port monitoring:

        It is critical to configure link monitoring by specifying either the
        **miimon** or the **arp_interval** and **arp_ip_target** options.
        ARP monitoring should not be used in conjunction with miimon.
        Otherwise serious network degradation will occur during link failures
        and wicked rejects such configuration as insufficient and unsupported.

        - Netif Carrier/MII link monitoring (*all modes*):

            - **miimon**=[msec]: enables the monitoring using specified interval\
                - **use_carrier**=[**1**|0]: 0 reverts from netif-carrier to MII/ethtool\
                - **updelay**=[msec]: link-up detection delay\
                - **downdelay**=[msec]: link-down detection delay

        - ARP link monitoring (*active-backup*, *balance-rr*, *balance-xor*, *broadcast*):

            - **arp_interval**=[msec]: enables the monitoring using specified interval\
            - **arp_ip_target**=[x.x.x.x[,...]]: comma-separated IPv4 address to monitor\
            - **arp_validate**=[**`none`** | `active` | `backup` | `all` | `filter` | `filter_active` | `filter_backup`]: reply validation and filtering (*active-backup*)\
                - **arp_all_targets**=[`any` | `all`] link-up consideration (*active-backup*)

    - Primary port configuration (*active-backup*, *balance-alb*, *balance-tlb*):

        - **primary**=[ifname]: interface name of the primary/preferred port\
        - **primary_reselect**=[**`always`**|`better`|`failure`]: primary reselection policy\
        - **active_slave**=[ifname]: volatile runtime option enforcing active port change

    - *active-backup* mode specific settings:

        - **fail_over_mac**=[**`none`** | `active` | `follow`]: MAC address on failover\
        - **num_grat_arp**,**num_unsol_na**=[0..255]: peer notification count

    - Transmit balancing settings:

      - **xmit_hash_policy**=[**`layer2`** | `layer2+3` | `layer3+4` | `encap2+3` | `encap3+4`]: XOR hash type (*802.3ad*, *balance-xor*, *balance-tlb*, *balance-alb*)\
      - **tlb_dynamic_lb**=[`0`|**`1`**]: enable flow shuffling in favor of hash distribution\
      - **lp_interval**=[sec]: learning packets to port peer switch sending interval

    - *802.3ad* mode specific settings:

        - **lacp_rate**=[**`slow`**|fast]: LACPDU packet transmission rate\
        - **ad_select**=[**`stable`** | `bandwidth` | `count`]: aggregation selection logic\
        - **ad_user_port_key**=[1..1023]: custom port-key\
        - **ad_actor_sys_prio**=[1..65535]: custom system priority\
        - **ad_actor_system**=[hwaddr]: actor mac address for LACPDU exchanges.\
        - **min_links**=[uint]: number of required port links

    - Other options:

      - **resend_igmp**=[0..255]: membership reports after failover, default 1 (*balance-rr*, *active-backup*, *balance-tlb* and *balance-alb*)\
      - **packets_per_slave**=[0..65535]: packets to transmit before move (*balance-rr*)\
      - **all_slaves_active**=[**`0`**|`1`]: deliver duplicate frames on inactive ports (*all modes*)

# Additional Information

For additional and more general information take a look into the kernel
documentation at \
`https://www.kernel.org/doc/Documentation/networking/bonding.rst`.

# EXAMPLE

Example for a bonding configuration on eth0 and eth1 ports using the
`active-backup` mode:

**ifcfg-bond0**\
```
STARTMODE='auto'
BOOTPROTO='static'
IPADDR='192.168.0.1/24'
BONDING_MASTER='yes'
BONDING_SLAVE_0='eth0'
BONDING_SLAVE_1='eth1'
BONDING_MODULE_OPTS='mode=active-backup miimon=100'
#MTU='9000'
#LLADDR='7a:b9:14:00:d6:ed'
```

The optional port configurations *may* set e.g. ethtool options:

**ifcfg-eth0**\
```
STARTMODE='hotplug'
BOOTPROTO='none'
ETHTOOL_OPTIONS='wol g'
```

**ifcfg-eth1**\
```
STARTMODE='hotplug'
BOOTPROTO='none'
ETHTOOL_OPTIONS='wol g'
```

# COPYRIGHT
Copyright (C) 2014-2024 SUSE LLC

# BUGS
Please report bugs at %PACKAGE_BUGREPORT%

# SEE ALSO
**`routes`** (5), **`ifcfg`** (5), **`wicked`** (8)
