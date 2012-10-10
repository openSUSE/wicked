#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.63])
AC_INIT([wicked], esyscmd([tr -d '\n' < VERSION]),
	[feedback@suse.de], [wicked],
	[http://gitorious.org/wicked])

# at the moment we just use the package version...
AC_SUBST(LIBWICKED_SOFILE_VERSION, ${PACKAGE_VERSION})
AC_SUBST(LIBWICKED_SONAME_VERSION, ${PACKAGE_VERSION%.*})
AC_SUBST(LIBWICKED_PACKAGE_SUFFIX, ${LIBWICKED_SONAME_VERSION//./_})

AC_CONFIG_SRCDIR([src/config.c])
AC_CONFIG_HEADERS([config.h])

AC_PREFIX_DEFAULT([/usr])

# Define sys-v init script directory
AC_SUBST(sysvinitdir, '${sysconfdir}/init.d')

# Define dbus-1/system.d directory
AC_SUBST(dbus_systemdir, '${sysconfdir}/dbus-1/system.d')

# Define pkg-config data directory
AC_SUBST(pkgconfigdir, '${datarootdir}/pkgconfig')

# Allow to specify different libdir for devel library
AC_ARG_WITH([devellibdir], [AS_HELP_STRING([--with-devel-libdir@<:@=PATH@:>@],
	    [install devel library into specified directory])],,
	    [with_devellibdir='${libdir}'])
AC_SUBST(devellibdir, $with_devellibdir)

# Enable system extensions (e.g. _GNU_SOURCE)
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_AWK
AC_PATH_PROG(INSTALL, install)
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

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
	Makefile.vars
	wicked.pc
	wicked.spec
	etc/init.d/wickedd
	etc/init.d/network
])
AC_OUTPUT

