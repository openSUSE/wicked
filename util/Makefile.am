
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= mkconst schema2html

AM_CPPFLAGS			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

mkconst_LDADD			= $(top_builddir)/src/libwicked.la
mkconst_SOURCES			= mkconst.c

schema2html_LDADD		= $(top_builddir)/src/libwicked.la
schema2html_CFLAGS		= $(LIBDBUS_CFLAGS)
schema2html_SOURCES		= schema2html.c

$(top_builddir)/src/libwicked.la:
	cd $(top_builddir)/src && $(MAKE) libwicked.la

# vim: ai
