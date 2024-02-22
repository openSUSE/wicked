% IFCFG-TEAM(5) Wicked User Manual
% Pawel Wieczorkiewicz -- original wireless man page, Clemens Famulla-Conrad
% January 29, 2024

# NAME
ifcfg-team - interface team configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`


# Team Interfaces

To setup a team interface you need a configuration file ifcfg-team&lt;X&gt; with
the usual network settings. But you must add additional variables

`TEAM_RUNNER`
:    must be set to one of the following types to identify this interface as
     a team interface:

    **broadcast** -- Team device transmits packets via all its ports.

    **roundrobin** -- Team device transmits packets via all its ports with
    round-robin method.

    **activebackup** -- Team device monitors ports' link changes and uses
    port with active link to transmit packets.

    **loadbalance** -- Team device transmits packets via all its ports
    performing load balancing (passive or active) with a use of hash functions.
    For passive load balancing only BPF hash function is used. For active load
    balancing runner finds best balance by moving hashes between available
    ports.

    **lacp** -- Implements 802.3ad LACP protocol.


# ACTIVE-BACKUP RUNNER SPECIFIC OPTIONS

`TEAM_AB_HWADDR_POLICY`
:   Determines the hardware addresses assignment for team device instance and
    its ports. This assignment is performed during team device instance creation
    and also for each new port added to the existing instance.
    The followingi modes are available:

    **same_all** -- All ports will always have the same hardware address as the
    associated team device.

    **by_active** -- Team device adopts the hardware address of the currently
    active port. This is useful when the port device is not able to change
    its hardware address.

    **only_active** -- Only the active port adopts the hardware address of the
    team device. The others have their own.

    Default: **same_all**


# LOAD BALANCE RUNNER SPECIFIC OPTIONS

`TEAM_LB_TX_HASH`
:   A list of string elements separated by a comma "`,`"
    which should be used for packet Tx hash computation.
    The following elements are available:

    **eth** -- Uses source and destination MAC addresses.

    **vlan** -- Uses VLAN id.

    **ipv4** -- Uses source and destination IPv4 addresses.

    **ipv6** -- Uses source and destination IPv6 addresses.

    **ip** -- Uses source and destination IPv4 and IPv6 addresses.

    **l3** -- Uses source and destination IPv4 and IPv6 addresses.

    **tcp** -- Uses source and destination TCP ports.

    **udp** -- Uses source and destination UDP ports.

    **sctp** -- Uses source and destination SCTP ports.

    **l4** -- Uses source and destination TCP and UDP and SCTP ports.

`TEAM_LB_TX_BALANCER_NAME`
:   Name of active Tx balancer. Currently only supported value is **basic**.

`TEAM_LB_TX_BALANCER_INTERVAL`
:   Rebalancing interval. To be specified in tenths of a second.

    Default: 50


# LACP RUNNER SPECIFIC OPTIONS

`TEAM_LACP_ACTIVE`
:   Active mode enables sending LACPDU frames through configured link
    periodically.

    Default: **true**

`TEAM_LACP_SYS_PRIO`
:   System priority, value can be 0 - 65535.

    Default: **255**

`TEAM_LACP_FAST_RATE`
:   Fast rate asks link partner to transmit LACPDU frames once per second.
    Otherwise they are sent every 30 seconds.

    Default: **true**

`TEAM_LACP_MIN_PORTS`
:   Minimum number of active ports required to assert carrier in master device.
    Value can be 1 - 255.

    Default: **0**

`TEAM_LACP_SELECT_POLICY`
:   The policy of how the aggregators will be selected. The following are
    available:

    **lacp_prio** -- Aggregator with highest priority according to LACP
    standard will be selected. Aggregator priority is affected by per-port
    option "lacp_prio".

    **lacp_prio_stable** -- Same as previous one, except do not replace
    selected aggregator if it is still usable.

    **bandwidth** -- Select aggregator with highest total bandwidth.

    **count** -- Select aggregator with highest number of ports.

    **port_options** -- Aggregator with highest priority according to per-port
    options **prio** and **sticky** will be selected. This means that the
    aggregator containing the port with the highest priority will be selected
    unless at least one of the ports in the currently selected aggregator is
    sticky.

    Default: **lacp_prio**

`TEAM_LACP_TX_HASH`
:   Same as for loadbalancer runner. Please refer to the section above.

`TEAM_LACP_TX_BALANCER`
:   Same as for loadbalancer runner. Please refer to the section above.

`TEAM_LACP_TX_BALANCER_INTERVAL`
:   Same as for loadbalancer runner. Please refer to the section above.


# LINK WATCH OPTIONS

`TEAM_LW_NAME[SUFFIX]`
:   Declares the type name of link watch (with the specified unique watch
    suffix). To declare several link watches, append the same suffix to all
    variables of one watch. The following types are available:

    **ethtool** -- Uses Libteam lib to get port ethtool state changes.

    **arp_ping** -- ARP requests are sent through a port. If an ARP reply is
    received, the link is considered to be up.

    **nsna_ping** -- Similar to the previous, except that it uses IPv6 Neighbor
    Solicitation / Neighbor Advertisement mechanism.


# ETHTOOL LINK WATCH SPECIFIC OPTIONS

`TEAM_LW_ETHTOOL_DELAY_UP[SUFFIX]`
:   Delay between the link coming up and the runner being notified about it
    (in milliseconds).

    Default: **0**

`TEAM_LW_ETHTOOL_DELAY_DOWN[SUFFIX]`
:   Delay between the link going down and the runner being notified about it
    (in milliseconds).

    Default: **0**


# ARP PING LINK WATCH SPECIFIC OPTIONS

`TEAM_LW_ARP_PING_SOURCE_HOST[SUFFIX]`
:   Hostname or IP address used in ARP request as source address.

    Default: **0.0.0.0**

`TEAM_LW_ARP_PING_TARGET_HOST[SUFFIX]`
:   Hostname or IP address used in ARP request as destination address.

`TEAM_LW_ARP_PING_INTERVAL[SUFFIX]`
:   Interval between ARP requests being sent (in milliseconds).

`TEAM_LW_ARP_PING_INIT_WAIT[SUFFIX]`
:   Delay between link watch initialization and the first ARP request being
    sent (in milliseconds).

    Default: **0**

`TEAM_LW_ARP_PING_VALIDATE_ACTIVE[SUFFIX]`
:   Validate received ARP packets on active ports. Otherwise all incoming ARP
    packets will be considered as a good reply.

    Default: **false**

`TEAM_LW_ARP_PING_VALIDATE_INACTIVE[SUFFIX]`
:   Validate received ARP packets on inactive ports. Otherwise all incoming ARP
    packets will be considered as a good reply.

    Default: **false**

`TEAM_LW_ARP_PING_SEND_ALWAYS[SUFFIX]`
:   Allow sending ARP requests on inactive ports.

    Default: **false**

`TEAM_LW_ARP_PING_MISSED_MAX[SUFFIX]`
:   Maximum number of missed ARP replies. If this number is exceeded, link is
    reported as down.

    Default: **3**


# NS/NA PING LINK WATCH SPECIFIC OPTIONS

`TEAM_LW_NSNA_PING_TARGET_HOST[SUFFIX]`
:   Hostname or IPv6 address used in NS packet as target address.

`TEAM_LW_NSNA_PING_INTERVAL[SUFFIX]`
:   Interval between sending NS packets (in milliseconds).

`TEAM_LW_NSNA_PING_INIT_WAIT[SUFFIX]`
:   Delay between link watch initialization and the first NS packet being sent
    (in milliseconds).

`TEAM_LW_NSNA_PING_MISSED_MAX[SUFFIX]`
:   Maximum number of missed NA reply packets. If this number is exceeded, link
    is reported as down.

    Default: **3**


# TEAM PORT SPECIFIC OPTIONS

`TEAM_PORT_DEVICE[SUFFIX]`
:   Port device name. This option must not be empty for a given port.

`TEAM_PORT_QUEUE_ID[SUFFIX]`
:   ID of queue which this port should be mapped to.

    Default: **None**


`TEAM_PORT_STICKY[SUFFIX]`
:   Marks an activebackup runner port as sticky, to not deselect it, if another
    port with a higher priority or better parameters becomes available.

    Default: **false**


`TEAM_PORT_PRIO[SUFFIX]`
:   Port priority in activebackup runner. The higher number means higher
    priority.

    Default: **0**


`TEAM_PORT_LACP_PRIO[SUFFIX]`
:   Port priority according to LACP standard. The lower number means higher
    priority.

    Default: **0**


`TEAM_PORT_LACP_KEY[SUFFIX]`
:   Port key according to LACP standard. It is only possible to aggregate ports
    with the same key.

    Default: **0**


# EXAMPLE

Example for a teaming interface on eth0 and eth1 using the backup mode

```
   STARTMODE=auto
   BOOTPROTO=static
   #IPADDR=...

   TEAM_RUNNER="loadbalance"
   TEAM_LB_TX_HASH="ipv4,ipv6,eth,vlan"
   TEAM_LB_TX_BALANCER_NAME="basic"
   TEAM_LB_TX_BALANCER_INTERVAL="100"

   TEAM_PORT_DEVICE_1="eth1"
   TEAM_PORT_DEVICE_2="eth2"

   TEAM_LW_NAME="ethtool"
   TEAM_LW_ETHTOOL_DELAY_UP="10"
   TEAM_LW_ETHTOOL_DELAY_DOWN="10"
   # optionally, further watches, e.g:
   TEAM_LW_NAME_1="nsna_ping"
   TEAM_LW_NSNA_PING_INTERVAL_1="100"
   TEAM_LW_NSNA_PING_MISSED_MAX_1="30"
   TEAM_LW_NSNA_PING_TARGET_HOST_1="fe80::1"
```

# Additional Information

For additional and more general information take a look into
<https://github.com/jpirko/libteam/wiki> or *teamd.conf*(5).

The configuration of routes for this kind of interface does not differ from
ordinary interfaces. See *man routes* for details.


# COPYRIGHT
Copyright (C) 2015-2022 SUSE LLC

# BUGS
Please report bugs at <http://bugs.opensuse.org>

# SEE ALSO
**`teamd.conf`** (5), **`ifcfg`** (5), **`wicked`** (8), **`teamd`** (8),
**`teamdctl`** (8)
