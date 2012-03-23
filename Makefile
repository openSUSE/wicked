#
# Include autoconf variables
#
-include Makefile.vars

# Hmm.. devellibdir=/usr/%_lib libdir=/%_lib
devellibdir		= ${exec_prefix}${libdir}

wickedconfigdir		= ${sysconfdir}/wicked
wickedpiddir		= ${localstatedir}/run/wicked

# ---------------------------------------------------------------

CFLAGS	= -Wall -Werror -g -O2 -D_GNU_SOURCE -I. -Iinclude -Isrc \
	  $(CFLAGS_DBUS)
CFLAGS_DBUS := $(shell pkg-config --cflags dbus-1)

APPS	= wicked wickedd \
	  dhcp4-supplicant autoip4-supplicant
UTILS	= mkconst
APPBINS	= $(addprefix $(BIN)/,$(APPS) $(UTILS))
TGTLIBS	= $(LIBNAME).so

DIST_DIRNAME    = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
DIST_ARCHIVE	= $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.bz2

LIBNAME		= libwicked
LIBSONAME=$(LIBNAME).so.$(LIBWICKED_SONAME_VERSION)
LIBSOFILE=$(LIBNAME).so.$(LIBWICKED_SOFILE_VERSION)
__LIBSRCS= \
	  config.c \
	  extension.c \
	  netinfo.c \
	  interface.c \
	  names.c \
	  ethernet.c \
	  vlan.c \
	  bonding.c \
	  bridge.c \
	  wireless.c \
	  openvpn.c \
	  state.c \
	  iflist.c \
	  ifconfig.c \
	  ifevent.c \
	  kernel.c \
	  address.c \
	  sysconfig.c \
	  ibft.c \
	  sysfs.c \
	  nis.c \
	  resolver.c \
	  update.c \
	  leasefile.c \
	  xml.c \
	  xml-reader.c \
	  xml-writer.c \
	  xml-schema.c \
	  xpath.c \
	  xpath-fmt.c \
	  buffer.c \
	  process.c \
	  util.c \
	  socket.c \
	  timer.c \
	  capture.c \
	  arp.c \
	  logging.c \
	  errors.c \
	  dbus-client.c \
	  dbus-message.c \
	  dbus-common.c \
	  dbus-connection.c \
	  dbus-dict.c \
	  dbus-xml.c \
	  dbus-server.c \
	  dbus-object.c \
	  dbus-errors.c \
	  dbus-objects/model.c \
	  dbus-objects/interface.c \
	  dbus-objects/ethernet.c \
	  dbus-objects/wireless.c \
	  dbus-objects/vlan.c \
	  dbus-objects/bridge.c \
	  dbus-objects/bonding.c \
	  dbus-objects/tun.c \
	  dbus-objects/openvpn.c \
	  dbus-objects/addrconf.c \
	  dbus-objects/misc.c \
	  dbus-objects/naming.c \
	  wpa-supplicant.c \
	  dhcp-lease.c
DHCP4SRCS = \
	  dhcp4/main.c \
	  dhcp4/dbus-api.c \
	  dhcp4/fsm.c \
	  dhcp4/device.c \
	  dhcp4/protocol.c
AUTO4SRCS = \
	  autoip4/main.c \
	  autoip4/dbus-api.c \
	  autoip4/device.c \
	  autoip4/fsm.c
CLIENTSRCS = \
	  client/main.c \
	  client/ifup.c \
	  client/calls.c
SERVERSRCS = \
	  server/main.c
GENFILES = \
	  schema/constants.xml

BIN	= bin
OBJ	= obj
LIBSRCS	= $(addprefix src/,$(__LIBSRCS))
LIBOBJS	= $(addprefix $(OBJ)/lib/,$(__LIBSRCS:.c=.o))
SHLIBOBJS= $(addprefix $(OBJ)/shlib/,$(__LIBSRCS:.c=.o))
DHCP4OBJS= $(addprefix $(OBJ)/,$(DHCP4SRCS:.c=.o))
AUTO4OBJS= $(addprefix $(OBJ)/,$(AUTO4SRCS:.c=.o))
CLIENTOBJS= $(addprefix $(OBJ)/,$(CLIENTSRCS:.c=.o))
SERVEROBJS= $(addprefix $(OBJ)/,$(SERVERSRCS:.c=.o))
UTILSRCS= util/mkconst.c

SOURCES= $(LIBSRCS) $(DHCP4SRCS) $(AUTO4SRCS) $(CLIENTSRCS) \
	 $(SERVERSRCS)

all: Makefile.vars $(TGTLIBS) $(APPBINS) $(GENFILES)

dist: Makefile.vars $(DIST_ARCHIVE)
	@echo "=============================================="
	@ls -1 wicked.spec $(DIST_ARCHIVE)
	@echo "=============================================="

distclean clean::
	rm -f *~ *.o libwicked.* core tags LOG
	rm -rf $(BIN) $(OBJ) $(GENFILES)
	rm -f testing/*.o
	rm -f testing/xml-test
	rm -f testing/xpath-test
	rm -f testing/ibft-test
	rm -f config.h

distclean::
	rm -f .depend

realclean maintainer-clean: distclean
	rm -rf autom4te.cache
	rm -f aclocal.m4 configure config.* *.log *.scan
	rm -f Makefile.vars wicked.pc wicked.spec
	rm -f $(DIST_ARCHIVE)

install-strip: STRIP_FLAG=-s
install-strip: install

install: Makefile.vars install-no-devel install-devel

install-devel: install-devel-lib install-devel-data

install-no-devel: install-lib install-bin install-data install-man

install-bin: $(APPBINS) install-bin
	install -d -m 755 $(DESTDIR)$(sbindir)
	for app in $(APPS); do \
		install $(STRIP_FLAG) -m 555 bin/$$app $(DESTDIR)$(sbindir); \
	done
	install -d -m 755 $(DESTDIR)$(wickedpiddir)

install-lib: $(TGTLIBS)
	install -d -m 755 $(DESTDIR)$(libdir)
	install -c -m 555 $(LIBNAME).so $(DESTDIR)$(libdir)/$(LIBSOFILE)
	ln -sf $(LIBSOFILE) $(DESTDIR)$(libdir)/$(LIBSONAME)

install-data: $(GENFILES)
	install -d -m 755 $(DESTDIR)$(sysvinitdir)
	install -c -m 755 etc/wickedd.init $(DESTDIR)$(sysvinitdir)/wickedd
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)
	install -m 644 etc/config.xml $(DESTDIR)$(wickedconfigdir)
	install -d -m 755 $(DESTDIR)$(dbus_systemdir)
	install -c -m 444 etc/wicked*.conf $(DESTDIR)$(dbus_systemdir)
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)/schema
	install -c -m 444 schema/*.xml $(DESTDIR)$(wickedconfigdir)/schema
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)/extensions
	install -c -m 555 extensions/* $(DESTDIR)$(wickedconfigdir)/extensions

install-man:
	install -d -m 755 $(DESTDIR)$(mandir)/man{7,8}
	install -c -m 444 man/*.7 $(DESTDIR)$(mandir)/man7
	install -c -m 444 man/*.8 $(DESTDIR)/$(mandir)/man8

install-devel-lib: install-lib
	install -d -m 755 $(DESTDIR)$(devellibdir)
ifeq ($(devellibdir),$(libdir))
	ln -sf $(LIBSONAME) $(DESTDIR)$(devellibdir)/$(LIBNAME).so
else
	ln -sf $(libdir)/$(LIBSONAME) $(DESTDIR)$(devellibdir)/$(LIBNAME).so
endif

install-devel-data:
	install -d -m 755 $(DESTDIR)$(includedir)/wicked
	install -c -m 644 $(wildcard include/wicked/*.h) $(DESTDIR)$(includedir)/wicked
	install -d -m 755 $(DESTDIR)$(pkgconfigdir)
	install -c -m 644 wicked.pc $(DESTDIR)$(pkgconfigdir)

schema/constants.xml: $(BIN)/mkconst schema/constants.xml.in
	@echo Building $@ from $@.in
	@LD_PRELOAD=$$PWD/$(LIBNAME).so $(BIN)/mkconst < $@.in > $@

$(BIN)/wicked: $(CLIENTOBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(CLIENTOBJS) -rdynamic -L. -lwicked -lanl -lm -lnl -ldbus-1 -ldl

$(BIN)/wickedd: $(SERVEROBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(SERVEROBJS) -rdynamic -L. -lwicked -lm -lnl -ldbus-1 -ldl

$(BIN)/dhcp4-supplicant: $(DHCP4OBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(DHCP4OBJS) -L. -lwicked -lm -lnl -ldbus-1 -ldl

$(BIN)/autoip4-supplicant: $(AUTO4OBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(AUTO4OBJS) -L. -lwicked -lm -lnl -ldbus-1 -ldl

$(BIN)/mkconst: $(OBJ)/util/mkconst.o $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(OBJ)/util/mkconst.o -L. -lwicked -lnl -ldbus-1 -ldl

testing/xml-test: testing/xml-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xml-test.o -L. -lwicked -lnl -ldbus-1 -ldl

testing/xpath-test: testing/xpath-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xpath-test.o -L. -lwicked -lnl -ldbus-1 -ldl

testing/ibft-test: testing/ibft-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/ibft-test.o -L. -lwicked -lnl -ldbus-1 -ldl

$(LIBNAME).a: $(LIBOBJS)
	@rm -f $@
	ar cr $@ $(LIBOBJS)

$(LIBNAME).so: $(SHLIBOBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIBSONAME) -o $@ $(SHLIBOBJS)
	ln -sf $@ $(LIBSONAME)

depend:
	gcc $(CFLAGS) -M $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/lib/\2&@' > .depend
	gcc $(CFLAGS) -M $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/shlib/\2&@' > .depend
	gcc $(CFLAGS) -M $(UTILSRCS) | sed 's:^[a-z]:$(OBJ)/util/&:' >> .depend
	gcc $(CFLAGS) -M $(DHCP4SRCS) | sed 's:^[a-z]:$(OBJ)/dhcp4/&:' >> .depend
	gcc $(CFLAGS) -M $(AUTO4SRCS) | sed 's:^[a-z]:$(OBJ)/autoip4/&:' >> .depend
	gcc $(CFLAGS) -M $(CLIENTSRCS) | sed 's:^[a-z]:$(OBJ)/client/&:' >> .depend
	gcc $(CFLAGS) -M $(SERVERSRCS) | sed 's:^[a-z]:$(OBJ)/server/&:' >> .depend

$(OBJ)/%.o: %.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/lib/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ)/shlib/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

$(OBJ)/netcf/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

wicked.spec: wicked.spec.in
	./config.status --file=$@:$<

# we use a tempdir so tar does not complain,
# that the . directory changed while reading
$(DIST_ARCHIVE): wicked.spec
	tmpdir=`mktemp -d .dist.XXXXXX` && \
	tar -cf "$${tmpdir}/$@" --bzip2 --owner=0 --group=0  \
		--transform="s;^[.];$(DIST_DIRNAME);" \
		--show-transformed-names     \
		--exclude="$(DIST_DIRNAME)*" \
		--exclude="$(OBJ)"           \
		--exclude="$(BIN)"           \
		--exclude=".dist.*"          \
		--exclude="*~"               \
		--exclude="*.o"              \
		--exclude="*.a"              \
		--exclude="*.so*"            \
		--exclude="*.log"            \
		--exclude="*.swp"            \
		--exclude=".git*"            \
		--exclude=".depend"          \
		--exclude=".*project"        \
		--exclude="wicked.pc"        \
		--exclude="config.h"         \
		--exclude="config.guess"     \
		--exclude="config.status"    \
		--exclude="autom4te.cache"   \
		--exclude="Makefile.vars"    \
		--exclude="testing/xml-test"   \
		--exclude="testing/ibft-test"  \
		--exclude="testing/xpath-test" \
		-- . && \
	mv "$${tmpdir}/$@" . && rmdir "$${tmpdir}"


config.status: configure

configure: configure.ac
	test -f $@ && ./config.status --recheck || ./autogen.sh

Makefile: Makefile.vars

Makefile.vars: Makefile.vars.in config.status
	./config.status Makefile.vars

-include .depend

