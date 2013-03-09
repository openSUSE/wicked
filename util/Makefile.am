
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= mkconst schema2html

INCLUDES			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

mkconst_LDADD			= $(top_builddir)/src/libwicked.la
mkconst_SOURCES			= mkconst.c

schema2html_LDADD		= $(top_builddir)/src/libwicked.la
schema2html_SOURCES		= mkconst.c

$(top_builddir)/src/libwicked.la:
	cd $(top_builddir)/src && $(MAKE) libwicked.la

# vim: ai
