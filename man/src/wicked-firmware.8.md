% wicked-firmware(8) Wicked User Manual
% Marius Tomaschewski
% Feb 28, 2023

# NAME
wicked firmware - manage netif-firmware-discovery extensions

# SYNOPSIS
`wicked firmware [options] <action> …`

# DESCRIPTION

# OPTIONS

`--help`, `-h`
:   show brief options and actions description and exit

# ACTIONS

`interfaces [options] [firmware name…|all]`
:   Shows all or specified firmware extension names and the interfaces names they configure.

    Options:

    `--format`, `-F` `<txt|xml>`
    :   Show the firmware interfaces as `xml` or (default) `txt` table.

    Example output:
    ```
    # wicked firmware interfaces
    nbft            eth0 eth0.42
    redfish         usb0
    ```
    ```
    # wicked firmware interfaces -F xml
    <interfaces>
      <firmware name="nbft">
        <interface>eth0</interface>
        <interface>eth0.42</interface>
      </firmware>
      <firmware name="redfish">
        <interface>usb0</interface>
      </firmware>
    </interfaces>
    ```

`extensions [options] [firmware name…|all]`
:   Shows all or specified firmware extension names and their enabled/disabled status.

    Options:

    `--format`, `-F` `<txt|xml>`
    :   Show the firmware extensions as `xml` override config or (default) `txt` table.

    `--expand`, `-E`
    :   Expand xml to a complete firmware discovery extension definition.

    Example output:

    ```
    # wicked firmware extensions
    ibft            enabled
    nbft            enabled
    redfish         disabled
    ```
    ```
    # wicked firmware extensions -F xml redfish
    <config>
      <netif-firmware-discovery name="redfish" enabled="false"/>
    </config>
    ```
    ```
    # wicked firmware extensions -F xml -E ibft
    <config>
      <netif-firmware-discovery name="ibft">
        <script name="show-config" command="%wicked_extensionsdir%/ibft"/>
        <script name="list-ifnames" command="%wicked_extensionsdir%/ibft -l"/>
      </netif-firmware-discovery>
    </config>
    ```

`disable [options] <firmware name… |all>`
:   Disables the specified firmware extension(s)

    Creates an xml override in the `%wicked_configdir%/client-firmware.xml`
    file disabling the specified firmware extension(s) defined in the
    `%wicked_configdir%/client.xml` file or it's includes.

    Options:

    `--format`, `-F` `<txt|xml>`
    :   Show the modified firmware extension overrides in requested format.

    `--show`, `-S`
    :   Show the modified firmware extensions on stdandard output only (dry run).

`enable [options] <firmware name… |all>`
:   Enables the specified firmware extension(s)

    Creates an xml override in the `%wicked_configdir%/client-firmware.xml`
    file enabling the specified firmware extension(s) defined in the
    `%wicked_configdir%/client.xml` file or it's includes.

    Options:

    `--format`, `-F` `<txt|xml>`
    :   Show the modified firmware extension overrides in requested format.

    `--show`, `-S`
    :   Show the modified firmware extensions on stdandard output only (dry run).

`revert [options] <firmware name… |all>`
:   Reverts the enable-state override for specified firmware extension(s).

    Reverts the enabled/disabled status to it's default defined in the
    `%wicked_configdir%/client.xml` file or it's includes by removing
    the specified firmware extension override from the
    `%wicked_configdir%/client-firmware.xml` config file.

    Options:

    `--format`, `-F` `<txt|xml>`
    :   Show the reverted firmware extension overrides in requested format.

    `--show`, `-S`
    :   Show the reverted firmware extensions on stdandard output only (dry run).


# COPYRIGHT
Copyright (C) 2023 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`wicked`**(8), **`wicked-redfish`**(8), **`wicked-config`**(5)
