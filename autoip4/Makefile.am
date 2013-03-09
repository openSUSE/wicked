
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= autoip4-supplicant

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

autoip4_supplicant_CFLAGS	= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
autoip4_supplicant_LDFLAGS	= -rdynamic
autoip4_supplicant_LDADD	= $(top_builddir)/src/libwicked.la
autoip4_supplicant_SOURCES	= \
	dbus-api.c	\
	device.c	\
	fsm.c		\
	main.c

EXTRA_DIST			= \
	autoip.h

# vim: ai
