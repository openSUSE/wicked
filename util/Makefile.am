
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
EXTRA_DIST			= templatepp.gawk.1.md

dist_noinst_SCRIPTS		= templatepp.gawk

if pandoc
noinst_DATA			= templatepp.gawk.1
CLEANFILES			+= templatepp.gawk.1
templatepp.gawk.1: templatepp.gawk.1.md templatepp.gawk
	@rm -f $@ $@.tmp
	$(AM_V_GEN)$(AWK) -f $(srcdir)/templatepp.gawk --		\
		-V PACKAGE_BUGREPORT='$(PACKAGE_BUGREPORT)'		\
		-i $< -o $@.tmp
	$(AM_V_at)$(PANDOC) -s -f markdown -t man $@.tmp -o $@
	@rm -f $@.tmp
endif

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
