
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(BUILT_SOURCES)

SUBDIRS				=
if wicked_compat_auto
SUBDIRS				+= suse redhat
else
if wicked_compat_suse
SUBDIRS				+= suse
endif
if wicked_compat_redhat
SUBDIRS				+= redhat
endif
endif

wicked_sbin_PROGRAMS		= wicked

wicked_CPPFLAGS			= \
				  -I$(top_srcdir)	\
				  -I$(top_srcdir)/src	\
				  -I$(top_srcdir)/include
if wicked_compat_auto
wicked_CPPFLAGS			+= -DCOMPAT_AUTO
else
if wicked_compat_suse
wicked_CPPFLAGS			+= -DCOMPAT_SUSE
endif
if wicked_compat_redhat
wicked_CPPFLAGS			+= -DCOMPAT_REDHAT
endif
endif

wicked_CFLAGS			= $(LIBNL_CFLAGS)	\
				  $(LIBDBUS_CFLAGS)	\
				  $(LIBGCRYPT_CFLAGS)

wicked_LDFLAGS			= -rdynamic
wicked_LDADD			= $(top_builddir)/src/libwicked.la
if wicked_compat_auto
wicked_LDADD			+= $(builddir)/suse/libwicked-client-suse.la
wicked_LDADD			+= $(builddir)/redhat/libwicked-client-redhat.la
else
if wicked_compat_suse
wicked_LDADD			+= $(builddir)/suse/libwicked-client-suse.la
endif
if wicked_compat_redhat
wicked_LDADD			+= $(builddir)/redhat/libwicked-client-redhat.la
endif
endif

wicked_SOURCES			= \
	arputil.c		\
	ethtool.c		\
	compat.c		\
	duid.c			\
	iaid.c			\
	ifup.c			\
	ifdown.c		\
	ifcheck.c		\
	ifreload.c		\
	ifstatus.c		\
	read-config.c		\
	main.c			\
	nanny.c			\
	reachable.c		\
	tester.c

noinst_HEADERS			= \
	ifup.h			\
	ifdown.h		\
	ifcheck.h		\
	ifreload.h		\
	ifstatus.h		\
	main.h			\
	reachable.h		\
	read-config.h		\
	wicked-client.h

install-data-local:
	$(MKDIR_P) "$(DESTDIR)$(wicked_configdir)/ifconfig"

# vim: ai
