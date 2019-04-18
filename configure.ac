#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.63])
AC_INIT([wicked], esyscmd([tr -d '\n' < VERSION]),
	[http://bugs.opensuse.org], [wicked],
	[https://github.com/openSUSE/wicked])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip subdir-objects])

#
# Note: We consider libwicked as an internal helper library,
# rather than a general purporse library with rock solid ABI.
# The program/package version and the library version do not
# correspond 1:1 with each other, the version is encoded.
# We intentionally break binary compatibility at minor level.
#
set -- ${VERSION//./ }
MAJ=$(($1))
MIN=$(($2))
REV=$(($3))
# optional fix/patch level
FIX=0

# Calculate package (soname version) suffix for the spec file.
AC_SUBST(LIBWICKED_PACKAGE_SUFFIX, "-${MAJ}-${MIN}")
AC_SUBST(LIBWICKED_LTLINK_VERSION, "-release ${MAJ} -version-number ${MIN}:${REV}:${FIX}")

#AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/config.c])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/usr])

# Whether to enable lldp support (experimental)
AC_ARG_ENABLE([lldp],
	      [AS_HELP_STRING([--enable-lldp],
	       [enable lldp support (experimental)])],,
	      [enable_lldp=no])
if test "x$enable_lldp" = "xyes" ; then
	AC_DEFINE([NI_ENABLE_LLDP], [], [Enable lldp support])
fi

# Whether to use rfc4361 dhcp4 client-id by default
AC_ARG_ENABLE([dhcp4-rfc4361-cid],
	      [AS_HELP_STRING([--disable-dhcp4-rfc4361-cid],
	       [disable to not use rfc4361 DHCPv4 client-id by default])],,
	      [enable_dhcp4_rfc4361_cid=yes])
if test "x$enable_dhcp4_rfc4361_cid" = "xyes" ; then
	AC_DEFINE([NI_DHCP4_RFC4361_CID], [1], [Enable to use rfc4361 DHCPv4 client-id by default])
fi

# Whether to enable nanny use
AC_ARG_ENABLE([nanny-use],
	      [AS_HELP_STRING([--disable-nanny-use],
	       [disable use of nanny as policy daemon])],,
	      [enable_nanny_use=true])
if test "x$enable_nanny_use" = "xno" ; then
    use_nanny="false"
else
    use_nanny="true"
fi
AC_SUBST(use_nanny)

# Whether to disable teamd support
AC_ARG_ENABLE([teamd],
	      [AS_HELP_STRING([--disable-teamd],
	       [disable teamd support])],,
	      [enable_teamd=true])
if test "x$enable_teamd" = "xno" ; then
    use_teamd="false"
else
    use_teamd="true"
fi
AC_SUBST(use_teamd)

# Whether to enable system-v init script installation
AC_ARG_ENABLE([systemv],
              [AS_HELP_STRING([--enable-systemv],
	      [install system-v service files])],
              [if test "$enableval" = yes; then
                 if test "$enable_systemd" = yes; then
                   AC_MSG_ERROR([[--enable-systemd and --enable-systemv are mutually exclusive]])
                 fi
               fi],
              [enable_systemv=no])

# Define system-v init script installation directory
AC_ARG_WITH([systemv-initdir], [AS_HELP_STRING([--with-systemv-initdir@<:@=DIR@:>@],
	    [system-v init scripts install directory [${sysconfdir}/init.d]])])
case $with_systemv_initdir in
	yes|no|"") with_systemv_initdir='${sysconfdir}/init.d' ;;
esac
AC_SUBST(systemv_initdir, "$with_systemv_initdir")
AM_CONDITIONAL([systemv_service], [test "x$enable_systemv" = "xyes"])

# Whether to enable system-v init script installation
AC_ARG_ENABLE([systemd],
              [AS_HELP_STRING([--enable-systemd],
	      [install system-d service files])],
              [if test "$enableval" = yes; then
                 if test "$enable_systemv" = yes; then
                   AC_MSG_ERROR([[--enable-systemd and --enable-systemv are mutually exclusive]])
                 fi
               fi],
              [if test "$enable_systemv" = yes; then
                 enable_systemd=no
               else
                 enable_systemd=yes
               fi
             ])

# Define system-d service/unit directory
AC_ARG_WITH([systemd-unitdir], [AS_HELP_STRING([--with-systemd-unitdir@<:@=DIR@:>@],
	    [system-d service/unit install directory [${prefix}/lib/systemd/system]])])
case $with_systemd_unitdir in
	yes|no|"") with_systemd_unitdir='${prefix}/lib/systemd/system' ;;
esac
AC_SUBST(systemd_unitdir, "$with_systemd_unitdir")
AM_CONDITIONAL([systemd_service], [test "x$enable_systemd" = "xyes"])


# Define /etc/dbus-1/system.d service configuration directory
AC_ARG_WITH([dbus-configdir], [AS_HELP_STRING([--with-dbus-configdir@<:@=DIR@:>@],
	    [dbus system config directory [${sysconfdir}/dbus-1/system.d]])])
case $with_dbus_configdir in
	yes|no|"") with_dbus_configdir='${sysconfdir}/dbus-1/system.d' ;;
esac
AC_SUBST(dbus_configdir,	"$with_dbus_configdir")

# Define /usr/share/dbus-1/system-services service autostart directory
# Disabled by default as it causes more throuble than it is currently
# worth, because the first request to the autostarted service is not
# processed and causes a timeout (fixme).
AC_ARG_WITH([dbus-servicedir], [AS_HELP_STRING([--with-dbus-servicedir@<:@=DIR@:>@],
	    [dbus system service directory [${datarootdir}/dbus-1/system-services]])])
case $with_dbus_servicedir in
	yes)	with_dbus_servicedir="${datarootdir}/dbus-1/system-services" ;;
	"")	with_dbus_servicedir="no"                                    ;;
esac
AC_SUBST(dbus_servicedir,	"$with_dbus_servicedir")
# Hmm... add a --enable-dbus-autostart switch here?
AM_CONDITIONAL([dbus_service], [test "x$with_dbus_servicedir" != "xno"])


# Define pkg-config data directory
AC_ARG_WITH([pkgconfigdir], [AS_HELP_STRING([--with-pkgconfigdir@<:@=DIR@:>@],
	    [pkgconfig data directory [${datarootdir}/pkgconfig]])],,
	    [with_pkgconfigdir='${datarootdir}/pkgconfig'])
AC_SUBST(pkgconfigdir,		"$with_pkgconfigdir")

# Wicked installation directories
AC_SUBST(wicked_docdir,		"${docdir}")
AC_SUBST(wicked_libdir,		"${libdir}")
AC_SUBST(wicked_sbindir,	"${sbindir}")
AC_SUBST(wicked_includedir,	"${includedir}/wicked")

# Is there any need to change this?
AC_ARG_WITH([configdir], [AS_HELP_STRING([--with-configdir@<:@=DIR@:>@],
	    [wicked config file directrory [${sysconfdir}/wicked]])],,
	    [with_configdir="${sysconfdir}/wicked"])
AC_SUBST(wicked_configdir,	"$with_configdir")

# Schema files are read-only
AC_ARG_WITH([schemadir], [AS_HELP_STRING([--with-schemadir@<:@=DIR@:>@],
	    [wicked schema directory [${datadir}/${PACKAGE_NAME}/schema]])],,
	    [with_schemadir="${datadir}/${PACKAGE_NAME}/schema"])
AC_SUBST(wicked_schemadir,	"$with_schemadir")

# User editable extension scripts -> config seems OK
AC_ARG_WITH([extensionsdir], [AS_HELP_STRING([--with-extensionsdir@<:@=DIR@:>@],
	    [wicked extensions directory [${wicked_configdir}/extensions]])],,
	    [with_extensionsdir="${wicked_configdir}/extensions"])
AC_SUBST(wicked_extensionsdir,	"$with_extensionsdir")

AC_ARG_WITH([storedir], [AS_HELP_STRING([--with-storedir@<:@=DIR@:>@],
	    [wicked persistent store directory [${localstatedir}/lib/wicked]])],,
	    [with_storedir="${localstatedir}/lib/wicked"])
AC_SUBST(wicked_storedir,  "$with_storedir")

AC_ARG_WITH([statedir], [AS_HELP_STRING([--with-statedir@<:@=DIR@:>@],
	    [wicked runtime state directory [${localstatedir}/run/wicked]])],,
	    [with_statedir="${localstatedir}/run/wicked"])
AC_SUBST(wicked_statedir,  "$with_statedir")

AC_ARG_WITH([piddir], [AS_HELP_STRING([--with-piddir@<:@=DIR@:>@],
	    [wicked pid file directory [${wicked_statedir}]])],,
	    [with_piddir="${wicked_statedir}"])
AC_SUBST(wicked_piddir,  "$with_piddir")

AC_ARG_WITH([supplicantdir], [AS_HELP_STRING([--with-supplicantdir@<:@=DIR@:>@],
	    [wicked supplicant directory [${libexecdir}/${PACKAGE_NAME}/bin]])],,
	    [with_supplicantdir="${libexecdir}/${PACKAGE_NAME}/bin"])
AC_SUBST(wicked_supplicantdir,	"$with_supplicantdir")

AC_ARG_WITH([compat], [AS_HELP_STRING([--with-compat@<:@=TYPE@:>@],
	    [install wicked compatibility scripts/config])],,
	    [with_compat="detect"])
test "X$with_compat" = "Xdetect" -a -f /etc/SuSE-release   && with_compat=suse
test "X$with_compat" = "Xdetect"                           && with_compat=auto
case $with_compat in
suse|redhat|auto)
	AC_SUBST(wicked_compat,	"$with_compat")
	test "x$with_compat" != "xsuse" && \
	AC_MSG_WARN([unsupported compatibility mode "$with_compat"])
;;
""|no)	;;
*)	AC_MSG_ERROR([invalid compatibility mode "$with_compat"]) ;;
esac
AM_CONDITIONAL([wicked_compat_auto],	[test "X$with_compat" = "Xauto"])
AM_CONDITIONAL([wicked_compat_suse],	[test "X$with_compat" = "Xsuse"])
AM_CONDITIONAL([wicked_compat_redhat],	[test "X$with_compat" = "Xredhat"])

# suse sysconfig fillup template directory
AC_ARG_WITH([fillup-templatesdir], [AS_HELP_STRING([--with-fillup-templatesdir@<:@=DIR@:>@],
	    [sysconfig fillup template directory [${localstatedir}/adm/fillup-templates]])],,
	    [with_fillup_templatesdir="${localstatedir}/adm/fillup-templates"])
AC_SUBST(fillup_templatesdir,	"$with_fillup_templatesdir")

AC_ARG_ENABLE([relro], [AS_HELP_STRING([--disable-relro],
			  [do not link binaries with full relro (relocation read-only) hardening])],
	    [if test "$enableval" = yes ; then
	       AC_SUBST(LDFLAGS,	["-Wl,-z,relro,-z,now $LDFLAGS"])
	     fi],
	    [AC_SUBST(LDFLAGS,	["-Wl,-z,relro,-z,now $LDFLAGS"])])

# Enable system extensions (e.g. _GNU_SOURCE)
AC_USE_SYSTEM_EXTENSIONS

# Do not build static libraries by default
AC_DISABLE_STATIC

# Checks for programs.
AC_LANG([C])
AC_PROG_CC
AC_PROG_CPP
AC_PROG_AWK
AC_PATH_PROG(INSTALL, install)
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen], [LIBDL_LIBS="-ldl"],[
	AC_MSG_ERROR(["Unable to find libdl"])
])
AC_SUBST(LIBDL_LIBS)
AC_CHECK_LIB([anl], [getaddrinfo_a], [LIBANL_LIBS="-lanl"],[
	AC_MSG_ERROR(["Unable to find libanl"])
])
AC_SUBST(LIBANL_LIBS)

# Checks for libgcrypt and it's minimal version;
# libgcrypt-1.5.0 as on SLE-11-SP3 is sufficient.
REQUIRE_LIBGCRYPT="1.5.0"
AM_PATH_LIBGCRYPT([$REQUIRE_LIBGCRYPT],,[
	AC_MSG_ERROR([Unable to find sufficient libgcrypt version])
])
AC_SUBST(REQUIRE_LIBGCRYPT)

# Checks for pkg-config modules.
PKG_CHECK_MODULES(LIBNL, [libnl-3.0 libnl-route-3.0])
PKG_CHECK_MODULES(LIBDBUS, [dbus-1])

# Check for systemd modules.
if test "X$enable_systemd" = Xyes; then
	PKG_CHECK_MODULES(LIBSYSTEMD, [libsystemd])
	AC_CHECK_HEADERS([systemd/sd-daemon.h],[],[AC_MSG_ERROR([Cannot find sd-daemon.h header file])])
fi

# Checks for header files.
AC_CHECK_HEADER([iwlib.h],[],[AC_MSG_ERROR([Please install libiw-devel to get wireless.h])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h])
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h sys/param.h])
AC_CHECK_HEADERS([sys/socket.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADERS([linux/filter.h linux/if_packet.h netpacket/packet.h])
AC_CHECK_HEADERS([linux/dcbnl.h linux/if_link.h linux/rtnetlink.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([dup2 gethostname getpass gettimeofday inet_ntoa memmove])
AC_CHECK_FUNCS([memset mkdir rmdir sethostname socket strcasecmp strchr])
AC_CHECK_FUNCS([strcspn strdup strerror strrchr strstr strtol strtoul])
AC_CHECK_FUNCS([strtoull])

AC_CHECK_DECL([RTA_MARK], [
	       AC_DEFINE([HAVE_RTA_MARK], [],
			 [Have RTA_MARK in netlink/netlink.h])
	      ], [
		  AS_UNSET([ac_cv_have_decl_RTA_MARK])
		  AC_CHECK_DECL([RTA_MARK], [
				 AC_DEFINE([HAVE_LINUX_RTA_MARK], [],
					   [Have RTA_MARK in linux/rtnetlink.h])
				], [], [[#include <linux/rtnetlink.h>]])
	      ], [[#include <netlink/netlink.h>]])

AC_CHECK_DECL([DCB_ATTR_IEEE_MAXRATE], [
	       AC_DEFINE([HAVE_DCB_ATTR_IEEE_MAXRATE], [],
			 [Have DCB_ATTR_IEEE_MAXRATE in linux/dcbnl.h])
	      ], [], [[#include <linux/dcbnl.h>]])

AC_CHECK_DECL([IFLA_VLAN_PROTOCOL], [
	       AC_DEFINE([HAVE_IFLA_VLAN_PROTOCOL], [],
			 [Have MACVLAN_FLAG_NOPROMISC in linux/if_link.h])
	      ], [], [[#include <linux/if_link.h>]])

AC_CHECK_DECL([MACVLAN_FLAG_NOPROMISC], [
	       AC_DEFINE([HAVE_MACVLAN_FLAG_NOPROMISC], [],
			 [Have MACVLAN_FLAG_NOPROMISC in linux/if_link.h])
	      ], [], [[#include <linux/if_link.h>]])

if test "$ac_cv_header_linux_if_packet_h" = "yes" ; then
	AC_CHECK_TYPES([struct tpacket_auxdata], [], [],
		[[#include <linux/if_packet.h>]]
	)
fi

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	src/Makefile
	util/Makefile
	schema/Makefile
	client/Makefile
	client/suse/Makefile
	client/redhat/Makefile
	server/Makefile
	nanny/Makefile
	dhcp4/Makefile
	dhcp6/Makefile
	autoip4/Makefile
	man/Makefile
	etc/Makefile
	extensions/Makefile
	testing/Makefile
	doc/Makefile
	wicked.pc
	wicked.spec
])
AC_OUTPUT

