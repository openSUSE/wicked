#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.63])
AC_INIT([wicked], esyscmd([tr -d '\n' < VERSION]),
	[http://bugs.opensuse.org], [wicked],
	[http://gitorious.org/wicked])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])

# at the moment we just use the package version...
AC_SUBST(LIBWICKED_SOFILE_VERSION, ${PACKAGE_VERSION})
AC_SUBST(LIBWICKED_SONAME_VERSION, ${PACKAGE_VERSION%%.*})
AC_SUBST(LIBWICKED_LTLINK_VERSION, "-version-number ${PACKAGE_VERSION//./:}")
AC_SUBST(LIBWICKED_PACKAGE_SUFFIX, ${LIBWICKED_SONAME_VERSION//./_})

#AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/config.c])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/usr])

# Whether to enable system-v init script installation
AC_ARG_ENABLE([systemv], [AS_HELP_STRING([--enable-systemv],
	      [install system-v init scripts])],,[enable_systemv=no])

# Define system-v init script installation directory
AC_ARG_WITH([systemv-initdir], [AS_HELP_STRING([--with-systemv-initdir@<:@=DIR@:>@],
	    [system-v init scripts install directory [${sysconfdir}/init.d]])])
case $with_systemv_initdir in
	yes|no|"") with_systemv_initdir='${sysconfdir}/init.d' ;;
esac
AC_SUBST(systemv_initdir, "$with_systemv_initdir")
AM_CONDITIONAL([systemv_service], [test "x$enable_systemv" = "xyes"])

# Whether to enable system-v init script installation
AC_ARG_ENABLE([systemd], [AS_HELP_STRING([--enable-systemd],
	      [install system-d service files])],,[enable_systemd=no])

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
# Disabled by default as it causes throuble because a) the first request
# is not processed and b) dbus starts them in own cgroup under systemd.
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

# Schema files are read-only -> '${datarootdir}/wicked/schema' ?
AC_ARG_WITH([schemadir], [AS_HELP_STRING([--with-schemadir@<:@=DIR@:>@],
	    [wicked schema directory [${wicked_configdir}/schema]])],,
	    [with_schemadir="${wicked_configdir}/schema"])
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

AC_MSG_CHECKING([for libgcrypt])
if ! test -x /usr/bin/libgcrypt-config; then
	AC_MSG_ERROR([libgcrypt-config not found])
fi
LIBGCRYPT_CFLAGS=`/usr/bin/libgcrypt-config --cflags`
LIBGCRYPT_LIBS=`/usr/bin/libgcrypt-config --libs`
AC_SUBST(LIBGCRYPT_CFLAGS)
AC_SUBST(LIBGCRYPT_LIBS)
AC_MSG_RESULT([found.])

# Checks for pkg-config modules.
PKG_CHECK_MODULES(LIBNL, [libnl-1])
PKG_CHECK_MODULES(LIBDBUS, [dbus-1])

# Checks for header files.
AC_CHECK_HEADER([iwlib.h],[],[AC_MSG_ERROR([Please install libiw-devel to get wireless.h])])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h])
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h sys/param.h])
AC_CHECK_HEADERS([sys/socket.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADERS([linux/filter.h linux/if_packet.h netpacket/packet.h])

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
	server/Makefile
	nanny/Makefile
	dhcp4/Makefile
	dhcp6/Makefile
	autoip4/Makefile
	man/Makefile
	man/wicked-config.5
	man/wicked.7
	man/wicked.8
	man/wickedd.8
	etc/Makefile
	etc/client.xml
	etc/common.xml
	etc/server.xml
	etc/network-nanny.xml
	etc/init.d/wickedd
	etc/init.d/network
	etc/systemd/wicked.service
	etc/systemd/wickedd.service
	etc/systemd/wicked-dhcp4.service
	etc/systemd/wicked-dhcp6.service
	etc/systemd/wicked-autoip4.service
	etc/org.opensuse.Network.AUTO4.service
	etc/org.opensuse.Network.DHCP4.service
	etc/org.opensuse.Network.DHCP6.service
	extensions/Makefile
	testing/Makefile
	wicked.pc
	wicked.spec
])
AC_OUTPUT

