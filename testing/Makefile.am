
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= rtnl-test	\
				  hex-test	\
				  xml-test	\
				  xpath-test	\
				  ifstate-test

AM_CPPFLAGS			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

AM_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

AM_LDFLAGS			= -rdynamic
LDADD				= $(top_builddir)/src/libwicked.la

rtnl_test_SOURCES		= rtnl-test.c
hex_test_SOURCES		= hex-test.c
xml_test_SOURCES		= xml-test.c
xpath_test_SOURCES		= xpath-test.c
ifstate_test_SOURCES		= ifstate-test.c

EXTRA_DIST			= ibft xpath

# vim: ai
