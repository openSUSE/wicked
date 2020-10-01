
CLEANFILES                             = *~
MAINTAINERCLEANFILES                   = Makefile.in
DISTCLEANFILES                         = $(BUILT_SOURCES)
EXTRA_DIST                             =
BUILT_SOURCES                          =

noinst_LTLIBRARIES                     = libwicked-client-dracut.la

libwicked_client_dracut_la_CPPFLAGS    = \
                                         -I$(top_srcdir)       \
                                         -I$(top_srcdir)/src   \
                                         -I$(top_srcdir)/include

libwicked_client_dracut_la_CFLAGS      = $(LIBNL_CFLAGS)       \
                                         $(LIBDBUS_CFLAGS)     \
                                         $(LIBGCRYPT_CFLAGS)

libwicked_client_dracut_la_LDFLAGS     = -rdynamic

libwicked_client_dracut_la_SOURCES     = \
                                         cmdline.c     \
                                         dracut.c

noinst_HEADERS                         = \
                                         dracut.h \
                                         cmdline.h

# vim: ai