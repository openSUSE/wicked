% IFCFG-WIRELESS(5) Wicked User Manual
% Joachim Gleissner -- original wireless man page, Pawel Wieczorkiewicz, Clemens Famulla-Conrad
% May 19, 2021

# NAME
ifcfg-wireless - wireless LAN network interface configuration

# SYNOPSIS
`/etc/sysconfig/network/ifcfg-*`

# GENERAL
Wireless networks need some additional configuration data compared to ethernet
ones. Therefore additional variables for ifcfg files were introduced. Some
wireless variables are not applicable to a single wireless network but are
global to the interface. The description of the variable points this out.

# OPTIONS

## Mandatory options:

`WIRELESS_ESSID <string>`
:   Set the SSID/ESSID (Network Name) The ESSID is used to identify cells which
    are part of the same virtual network.
    The format allow the following escape sequences:

      * `\x[0-9A-Fa-F]{2}`: define one byte as hex (`\x0A` for new line)
      * `\[0-9]{1,3}`: define one byte in oktal (`\012` for new line)
      * `\t`: translated to tab (`\x09`)
      * `\n`: translated to new line (`\x0A`)
      * `\r`: translated to carriage return (`\x0D`)
      * `\e`: translated to ESC (`\x1B`)
      * `\\`: become single `\`
      * `\"`: become single `"`

## Global wireless options:

`WIRELESS <bool>`
:   Enable or disable wireless for this configuration. If not given
    wireless will be enabled, if one of **WIRELESS_ESSID**,
    **WIRELESS_AP_SCANMODE** or **WIRELESS_WPA_DRIVER** is given.

`WIRELESS_AP_SCANMODE <0|1|2>`
:   Defines which SSID scan mode should be used. Mode 0 means the driver
    performs the scan. Mode 1 means wpa_supplicant takes care of scanning. Mode
    2 is basically the same as mode 0 but the access point gets chosen by
    security policy and SSID. This mode does not support multiple network
    settings. Default is "1" for most drivers. This variable can have no suffix.
    This set the wpa_supplicant variable `ap_scan`.

`WIRELESS_WPA_DRIVER <string>`
:   This variable allows to override the wpa driver name that should be used by
    the wpa_supplicant. Default is "nl80211,wext".

## Wireless network configuration options:

`WIRELESS_AUTH_MODE <OPEN|SHARED|PSK|EAP>`
:   Sets authentication mode. The mode depends on the protection technology
    being used. **shared** key authentication makes it easier for a potential
    attacker to break into your network. Unless you have specific needs for
    shared key authentication, use the **open** mode. As WEP has been proved
    insecure, WPA (Wi-Fi Protected Access) was defined to close its security
    wholes. In case you want to use  WPA-PSK (WPA preshared key authentication,
    aka WPA "Home"), set this to **psk**. In case you want to use WPA-EAP
    (WPA with Exensible Authentication Protocol, aka WPA "Enterprise"),
    set this to **eap**. WPA authentication modes are only possible
    when WIRELESS_MODE is set to managed.

`WIRELESS_MODE <MANAGED|AD-HOC|MASTER>`
:   Set the operating mode of the device, which depends on the network topology.
    Set to ad-hoc for network composed of only one cell and without Access Point,
    managed for network composed of many cells, with roaming or with an Access
    Point, master if you want your system act as an Access Point or
    synchronisation master. Default is **managed**..

`WIRELESS_AP <address>`
:   In environments with multiple Access points you may want to define the one
    to connect to by entering its MAC address. Format is 6x2 hex digits,
    separated by colons, eg 01:02:03:04:05:06.

`WIRELESS_PRIORITY <num>`
:   This variable only makes sense used in conjunction with multiple networks.
    If you want to prefer one configured network for over another, set the
    respective WIRELESS_PRIORITY variable (means, with the same suffix) to a
    higher value (integer only).

`WIRELESS_CHANNEL <num>`
:   With this variable you can define the channel being used. This is only
    applicable to ad-hoc and master operating modes. Channels are usually
    numbered starting at 1, and you may use iwpriv(8) to get the total number of
    channels and list the available frequencies. Depending on regulations, some
    frequencies/channels may not be available.

`WIRELESS_KEY_[0123] <string|hex>`
:   You can define up to 4 WEP encryption keys. You can use WEP with open and
    sharedkey authentication. The key can be entered in as ASCII string, where
    char represent one byte of the key, thus the length must match 5, 13 or 16.
    Or you can specify the key in hex digits.

    Note: for backward compatibility a prefix "h:" or characters like "-" or
    ":" get removed from the hexstring.

    Examples:
```
    WIRELESS_KEY_0="01020304ff"
    WIRELESS_KEY_0-"s:hello"
```

`WIRELESS_DEFAULT_KEY <num>`
:   Sets the default WEP key. The default key is used to encrypt outgoing
    packets, incoming ones are decrypted with the key number specified in the
    packet. This defaults to 0.

`WIRELESS_WPA_PROTO <WPA|RSN>`
:   Using this variable you can specify the WPA protocol to be used. Valid
    values are WPA and RSN (aka WPA2). Multiple values are allowed. Default is
    both.

`WIRELESS_WPA_PSK <string|hex>`
:   When using WPA-PSK authentication, you need to specify your pre shared key
    here. The key is used for authentication and encryption purposes. You can
    enter it in hex digits (needs to be exactly 64 digits long) or as passphrase
    getting hashed (8 to 63 ASCII characters long).

`WIRELESS_CIPHER_PAIRWISE <TKIP|CCMP>`
:   WPA modes support two different encryption systems, TKIP and CCMP. This
    variable defines which to use for unicast communication. Default is to allow
    both. In case you want to restrict it to one protocol, set this variable.

`WIRELESS_CIPHER_GROUP <TKIP|CCMP|WEP104|WEP40>`
:   WPA modes support two different encryption systems, TKIP and CCMP. This
    variable defines which to use for broad-/multicast communication. Default is
    to allow both. In case you want to restrict it to one protocol, set this
    variable.

`WIRELESS_EAP_MODE <TLS|PEAP|TTLS|...>`
:   Use this variable to specify the outer WPA-EAP authentication methods.

`WIRELESS_EAP_AUTH <PAP|CHAP|MSCHAP|MSCHAPv2|...>`
:   Use this variable to specify the inner WPA-EAP authentication methods.

`WIRELESS_WPA_IDENTITY <string>`
:   Identity string for WPA-EAP as configured on the RADIUS server.

`WIRELESS_WPA_PASSWORD <string>`
:   Needs to be set in conjunction with WPA-EAP. Set to your password as
    configured on the RADIUS server.

`WIRELESS_WPA_ANONID <name>`
:   Sets anonymous identity. Default is "anonymous". The anonymous identity is
    used with WPA-EAP protocols that support different tunnelled identities
    (e.g., TTLS).

`WIRELESS_PEAP_VERSION <0|1>`
:   When using WPA-EAP with PEAP authentication, you can use this variable to
    force which PEAP version (0 or 1) to be used. Default is to allow both.

`WIRELESS_PEAP_LABEL <string>`
:   When set to 1 the new label: "client PEAP encryption" can be enforced to be
    used during key derivation with version PEAPv1 or newer. Most existing
    PEAPv1 implementation tend to use the old label, "client EAP encryption",
    which is the default value for wpa_supplicant. Default value is 0.

`WIRELESS_CA_CERT <string>`
:   CA certificate for Interworking network selection. The file path can be
    specified relative to the ifcfg file or absolute.

`WIRELESS_CLIENT_CERT <string>`
:   File path to client certificate file (PEM/DER). It is used with WPA-EAP
    where a client certificate/private key is used for authentication (EAP-TLS).

`WIRELESS_CLIENT_KEY <string>`
:   File path to client private key file (PEM/DER/PFX). If the key is encryped,
    specify the **WIRELESS_CLIENT_KEY_PASSWORD**.

`WIRELESS_HIDDEN_SSID <NO|YES>`
:   Set to "yes" if you try to connect to a hidden network. The probe request
    frames will be specific to the configured ESSID.

`WIRELESS_FRAG <num>`
:   Maximum EAP fragment size in bytes (default 1398).
    This value limits the fragment size for EAP methods that support
    fragmentation (e.g., EAP-TLS and EAP-PEAP). This value should be set
    small enough to make the EAP messages fit in MTU of the network
    interface used for EAPOL. The default value is suitable for most
    cases.

`WIRELESS_PMF <disabled|optional|required>`
:   Whether **P**rotected **M**anagement **F**rames are enabled or not.
    Default is **disabled**.

# EXAMPLE

Some examples of different configuration types supported at the moment:

## Common parameters
```
    BOOTPROTO='dhcp'
    NAME='PRO/Wireless 4965 AG or AGN [Kedron] Network Connection'
    STARTMODE='auto'
```

## Global wireless parameters
```
    WIRELESS_AP_SCANMODE='1'
    WIRELESS_WPA_DRIVER='nl80211,wext'
```

## Scan only wireless configuration
```
    STARTMODE='manual'
    BOOTPROTO='none'
    WIRELESS='yes'
```

## Open network configuration
```
    WIRELESS_MODE='Managed'
    WIRELESS_ESSID='example_ssid'
```

## WPA-PSK network configuration
```
    WIRELESS_MODE='Managed'
    WIRELESS_ESSID='example_ssid'
    WIRELESS_WPA_PSK='example_passwd'
```

## WPA-EAP/PEAP/MSCHAPv2 network configuration
```
    WIRELESS_MODE='Managed'
    WIRELESS_ESSID='example_ssid'
    WIRELESS_EAP_MODE='PEAP'
    WIRELESS_EAP_AUTH='MSCHAPv2'
    WIRELESS_WPA_IDENTITY='bob'
    WIRELESS_WPA_PASSWORD='example_password'
    WIRELESS_CA_CERT='/path/to/my/ca_cert.pem'
```
## WPA-EAP/TTLS/PAP network configuration**
```
    WIRELESS_MODE='Managed'
    WIRELESS_ESSID='example_ssid'
    WIRELESS_EAP_MODE='TTLS'
    WIRELESS_EAP_AUTH='PAP'
    WIRELESS_WPA_IDENTITY='bob'
    WIRELESS_WPA_PASSWORD='example_passwd'
    WIRELESS_CA_CERT='/path/to/my/ca_cert.pem'
```

## WPA-EAP/TLS network configuration
```
    WIRELESS_MODE='Managed'
    WIRELESS_ESSID='example_ssid'
    WIRELESS_EAP_MODE='TLS'
    WIRELESS_WPA_IDENTITY='bob'
    WIRELESS_CLIENT_CERT='/path/to/my/client.crt'
    WIRELESS_CA_CERT='/path/to/my/ca_cert.pem'
```

## WEP network configuration
```
    WIRELESS_MODE='Managed'
    WIRELESS_AUTH_MODE='shared'
    WIRELESS_KEY_0="s:hallo"
    WIRELESS_KEY_1="01020304050607080900010203"
```

## Multiple network configuration
```
    WIRELESS_ESSID='example_open_ssid'

    WIRELESS_ESSID_1='super_secure'
    WIRELESS_PRIORITY_1='10'
    WIRELESS_EAP_MODE_1='TLS'
    WIRELESS_WPA_IDENTITY_1='bob'
    WIRELESS_CA_CERT_1='/path/to/my/ca_cert.pem'
    WIRELESS_CLIENT_CERT_1='/path/to/my/client.crt'
    WIRELESS_CLIENT_KEY_1='/path/to/my/client.key'

    WIRELESS_ESSID_2='example_psk_ssid'
    WIRELESS_WPA_PSK_2='example_passwd'

    WIRELESS_ESSID_3='home_wifi_5G'
    WIRELESS_WPA_PSK_3='example_passwd'
    WIRELESS_PRIORITY_3='5'
    WIRELESS_WPA_PROTO_3='RSN'
    WIRELESS_CIPHER_PAIRWISE_3='CCMP'
    WIRELESS_CIPHER_GROUP_3='TKIP,CCMP'
```

# COPYRIGHT
Copyright (C) 2014-2022 SUSE LLC

# BUGS
Please report bugs as described at http://bugs.opensuse.org

# SEE ALSO
**`routes`**(5), **`ifcfg`**(5), **`wicked`**(8)
