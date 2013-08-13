
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wickedd-nanny

INCLUDES			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_nanny_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)
wickedd_nanny_LDFLAGS		= -rdynamic
wickedd_nanny_LDADD		= $(top_builddir)/src/libwicked.la
wickedd_nanny_SOURCES		= \
	device.c	\
	interface.c	\
	main.c		\
	modem.c		\
	nanny.c		\
	policy.c

EXTRA_DIST			= \
	nanny.h

# vim: ai
