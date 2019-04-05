
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_sbin_PROGRAMS		= wickedd-nanny

wickedd_nanny_CPPFLAGS		= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

wickedd_nanny_CFLAGS		= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)	\
				  $(LIBSYSTEMD_CFLAGS)

wickedd_nanny_LDFLAGS		= -rdynamic		\
				  $(LIBSYSTEMD_LIBS)
wickedd_nanny_LDADD		= $(top_builddir)/src/libwicked.la
wickedd_nanny_SOURCES		= \
	device.c		\
	interface.c		\
	main.c			\
	modem.c			\
	nanny.c			\
	policy.c

noinst_HEADERS			= \
	nanny.h

# vim: ai
