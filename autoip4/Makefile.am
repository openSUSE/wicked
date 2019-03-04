
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_supplicant_PROGRAMS	= wickedd-auto4

wickedd_auto4_CPPFLAGS		= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_auto4_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)	\
				  $(LIBSYSTEMD_CFLAGS)

wickedd_auto4_LDFLAGS		= -rdynamic		\
				  $(LIBSYSTEMD_LIBS)
wickedd_auto4_LDADD		= $(top_builddir)/src/libwicked.la
wickedd_auto4_SOURCES		= \
	dbus-api.c		\
	device.c		\
	fsm.c			\
	main.c

noinst_HEADERS			= \
	autoip.h

# vim: ai
