
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wickedd-dhcp6

wickedd_dhcp6_CPPFLAGS		= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_dhcp6_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)	\
				  $(LIBSYSTEMD_CFLAGS)

wickedd_dhcp6_LDFLAGS		= -rdynamic		\
				  $(LIBSYSTEMD_LIBS)
wickedd_dhcp6_LDADD		= $(top_builddir)/src/libwicked.la
wickedd_dhcp6_SOURCES		= \
	dbus-api.c		\
	main.c

noinst_HEADERS			= \
	dbus-api.h

# vim: ai
