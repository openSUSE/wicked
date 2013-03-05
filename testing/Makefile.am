
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= rtnl-test	\
				  xml-test	\
				  xpath-test

INCLUDES			= -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

CFLAGS				= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_FLAGS)
LDFLAGS				= $(top_builddir)/src/libwicked.la
DEPENDENCIES			= $(top_builddir)/src/libwicked.la

rtnl_test_SOURCES		= rtnl-test.c

xml_test_SOURCES		= xml-test.c
xpath_test_SOURCES		= xpath-test.c

EXTRA_DIST			= ibft xpath

# vim: ai
