
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= rtnl-test		\
				  hex-test		\
				  uuid-test		\
				  xml-test		\
				  ibft-test		\
				  json-test		\
				  teamd-test		\
				  xpath-test		\
				  essid-test		\
				  cstate-test   	\
				  bitmap-test		\
				  bitmask-test		\
				  socket-mock-test 	\
				  ptr_array-test

noinst_HEADERS			= wunit.h

AM_CPPFLAGS			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

AM_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

AM_LDFLAGS			= -rdynamic
LDADD				= $(top_builddir)/src/libwicked.la

rtnl_test_SOURCES		= rtnl-test.c
hex_test_SOURCES		= hex-test.c
uuid_test_SOURCES		= uuid-test.c
xml_test_SOURCES		= xml-test.c
ibft_test_SOURCES		= ibft-test.c
json_test_SOURCES		= json-test.c
teamd_test_SOURCES		= teamd-test.c
xpath_test_SOURCES		= xpath-test.c
essid_test_SOURCES		= essid-test.c
cstate_test_SOURCES		= cstate-test.c
bitmap_test_SOURCES		= bitmap-test.c
bitmask_test_SOURCES		= bitmask-test.c
socket_mock_test_SOURCES	= socket-mock-test.c
ptr_array_test_SOURCES		= ptr_array-test.c

EXTRA_DIST			= ibft xpath		\
				  scripts/ifbind.sh	\
				  nbft nbft-test.sh

TESTS				= socket-mock-test	\
				  bitmask-test		\
				  bitmap-test		\
				  nbft-test.sh		\
				  json-test		\
				  ptr_array-test

# vim: ai
