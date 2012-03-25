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

# Checks for pkg-config modules.
PKG_CHECK_MODULES(LIBNL, [libnl-1])
PKG_CHECK_MODULES(LIBDBUS, [dbus-1])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h])
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/ioctl.h sys/param.h])
AC_CHECK_HEADERS([sys/socket.h sys/time.h syslog.h unistd.h])

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

AC_CONFIG_FILES([
	Makefile.vars
	wicked.pc
	wicked.spec
])
AC_OUTPUT

