% templatepp.gawk(1) Wicked User Manual
% Marius Tomaschewski
% 2026

# NAME
templatepp.gawk - a minimal *.in template preprocessor

# SYNOPSIS
`gawk -f templatepp.gawk -- [options]`

`templatepp.gawk -- [options]`

# DESCRIPTION

Reads a template from standard input (or the `-i` file), resolves the
variable references and conditional blocks it contains, and writes the
result to standard output (or the `-o` file).

Two expansions are performed:

`@NAME@` and `%NAME%`
:   Replaced with the value given by a `-V NAME=VALUE` option. Both forms
    are accepted: `*.in` templates use the autoconf-style `@NAME@`, while
    `*.md` sources use `%NAME%` (pandoc mangles a bare `@` to `[at]`).

`#if NAME` / `#else` / `#endif`
:   Kept or dropped depending on the `-C NAME` block conditional. Blocks
    may be nested.

Because `-i`, `-o`, `-C`, `-V` and `-h` clash with gawk's own options, the
templatepp.gawk options must be separated from gawk with `--`.

# OPTIONS

`-V` `NAME=VALUE`
:   Set variable `NAME`; replaces `@NAME@` and `%NAME%` with `VALUE`.
    May be given more than once.

`-C` `NAME`[`=0`|`=1`]
:   Set the `#if NAME` block conditional `NAME` (default `1`). May be
    given more than once.

`-i` `FILE`
:   Read the template from `FILE` (default: standard input).

`-o` `FILE`
:   Write the result to `FILE` (default: standard output).

`--help`, `-h`
:   Print a brief usage summary on standard output and exit.

# EXIT STATUS

`0`
:   Success (also for `--help`).

`2`
:   Usage error, e.g. an unknown option or a malformed `-V`/`-C` argument.

# EXAMPLES

Render a manual page template, enabling the `system` conditional:

```
gawk -f templatepp.gawk -- \
    -V wicked_configdir=/usr/etc/wicked -C system \
    -i wicked-config.5.in -o wicked-config.5
```

# COPYRIGHT
Copyright (C) 2026 SUSE LLC

# BUGS
Please report bugs as described at <%PACKAGE_BUGREPORT%>

# SEE ALSO
**`wicked-config`**(5)
