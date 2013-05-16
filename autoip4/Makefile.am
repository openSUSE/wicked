
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wicked-autoip4

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wicked_autoip4_CFLAGS	= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
wicked_autoip4_LDFLAGS	= -rdynamic
wicked_autoip4_LDADD	= $(top_builddir)/src/libwicked.la
wicked_autoip4_SOURCES	= \
	dbus-api.c	\
	device.c	\
	fsm.c		\
	main.c

EXTRA_DIST			= \
	autoip.h

# vim: ai
