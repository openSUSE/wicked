
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

noinst_PROGRAMS			= mkconst schema2html

INCLUDES			= -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include

mkconst_LDFLAGS			= $(top_builddir)/src/libwicked.la
mkconst_DEPENDENCIES		= $(top_builddir)/src/libwicked.la
mkconst_SOURCES			= mkconst.c

schema2html_LDFLAGS		= $(top_builddir)/src/libwicked.la
schema2html_DEPENDENCIES	= $(top_builddir)/src/libwicked.la
schema2html_SOURCES		= mkconst.c

# vim: ai
