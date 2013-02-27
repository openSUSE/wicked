#
# Include autoconf variables
#
-include Makefile.vars

wickedconfigdir		= ${sysconfdir}/wicked
wickedpiddir		= ${localstatedir}/run/wicked

# ---------------------------------------------------------------

CFLAGS	?= -g -O2
CFLAGS	+= -Wall

LDFLAGS	+=

CPPFLAGS:= $(DEFS) $(CPPFLAGS)
CPPFLAGS+= -I. -Iinclude -Isrc $(LIBNL_CFLAGS) $(LIBDBUS_CFLAGS) $(LIBGCRYPT_FLAGS)
CPPFLAGS+= -DWICKED_CONFIGDIR=\"$(wickedconfigdir)\"

LDCOMMON= $(LIBDL_LIBS) $(LIBNL_LIBS) $(LIBANL_LIBS) $(LIBDBUS_LIBS) $(LIBGCRYPT_LIBS)

APPS	= wicked wickedd network-nanny \
	  dhcp4-supplicant autoip4-supplicant \
	  dhcp6-supplicant
UTILS	= mkconst schema2html
APPBINS	= $(addprefix $(BIN)/,$(APPS) $(UTILS))
TGTLIBS	= $(LIBNAME).so

DIST_DIRNAME    = $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)
DIST_ARCHIVE	= $(PACKAGE_TARNAME)-$(PACKAGE_VERSION).tar.bz2

LIBNAME		= libwicked
LIBSONAME=$(LIBNAME).so.$(LIBWICKED_SONAME_VERSION)
LIBSOFILE=$(LIBNAME).so.$(LIBWICKED_SOFILE_VERSION)
__LIBSRCS= \
	  config.c \
	  calls.c \
	  fsm.c \
	  fsm-policy.c \
	  extension.c \
	  netinfo.c \
	  interface.c \
	  names.c \
	  ethernet.c \
	  vlan.c \
	  bonding.c \
	  bridge.c \
	  wireless.c \
	  rfkill.c \
	  openvpn.c \
	  ppp.c \
	  ipv4.c \
	  ipv6.c \
	  modem-manager.c \
	  state.c \
	  iflist.c \
	  ifconfig.c \
	  ifevent.c \
	  kernel.c \
	  address.c \
	  sysconfig.c \
	  sysfs.c \
	  firmware.c \
	  nis.c \
	  resolver.c \
	  async-resolver.c \
	  update.c \
	  leasefile.c \
	  secret.c \
	  xml.c \
	  xml-reader.c \
	  xml-writer.c \
	  xml-schema.c \
	  xpath.c \
	  xpath-fmt.c \
	  md5sum.c \
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
	  dbus-introspect.c \
	  dbus-xml.c \
	  dbus-server.c \
	  dbus-object.c \
	  dbus-errors.c \
	  dbus-objects/model.c \
	  dbus-objects/interface.c \
	  dbus-objects/ipv4.c \
	  dbus-objects/ipv6.c \
	  dbus-objects/ethernet.c \
	  dbus-objects/wireless.c \
	  dbus-objects/vlan.c \
	  dbus-objects/bridge.c \
	  dbus-objects/bonding.c \
	  dbus-objects/tun.c \
	  dbus-objects/openvpn.c \
	  dbus-objects/ppp.c \
	  dbus-objects/modem.c \
	  dbus-objects/addrconf.c \
	  dbus-objects/misc.c \
	  dbus-objects/naming.c \
	  dbus-objects/state.c \
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
DHCP6SRCS = \
	  dhcp6/main.c \
	  dhcp6/dbus-api.c \
	  dhcp6/duid.c \
	  dhcp6/fsm.c \
	  dhcp6/device.c \
	  dhcp6/protocol.c \
	  dhcp6/state.c
CLIENTSRCS = \
	  client/main.c \
	  client/ifup.c \
	  client/nanny.c \
	  client/compat.c \
	  client/compat-suse.c \
	  client/compat-redhat.c \
	  client/reachable.c
SERVERSRCS = \
	  server/main.c
NANNYSRCS = \
	  nanny/main.c \
	  nanny/nanny.c \
	  nanny/policy.c \
	  nanny/interface.c \
	  nanny/modem.c \
	  nanny/device.c
GENFILES = \
	  schema/constants.xml
TAGDIRS	= \
	  include src \
	  client server \
	  autoip4 dhcp4 dhcp6

BIN	= bin
OBJ	= obj
LIBSRCS	= $(addprefix src/,$(__LIBSRCS))
LIBOBJS	= $(addprefix $(OBJ)/lib/,$(__LIBSRCS:.c=.o))
SHLIBOBJS= $(addprefix $(OBJ)/shlib/,$(__LIBSRCS:.c=.o))
DHCP4OBJS= $(addprefix $(OBJ)/,$(DHCP4SRCS:.c=.o))
AUTO4OBJS= $(addprefix $(OBJ)/,$(AUTO4SRCS:.c=.o))
DHCP6OBJS= $(addprefix $(OBJ)/,$(DHCP6SRCS:.c=.o))
CLIENTOBJS= $(addprefix $(OBJ)/,$(CLIENTSRCS:.c=.o))
SERVEROBJS= $(addprefix $(OBJ)/,$(SERVERSRCS:.c=.o))
NANNYOBJS= $(addprefix $(OBJ)/,$(NANNYSRCS:.c=.o))
UTILSRCS= util/mkconst.c util/schema2html.c

SOURCES= $(LIBSRCS) $(DHCP4SRCS) $(AUTO4SRCS) $(DHCP6SRCS) \
	 $(CLIENTSRCS) $(SERVERSRCS) $(NANNYSRCS)

all: Makefile.vars config.h $(TGTLIBS) $(APPBINS) $(GENFILES)

dist: Makefile.vars wicked.spec $(DIST_ARCHIVE)
	@echo "=============================================="
	@ls -1 wicked.spec $(DIST_ARCHIVE)
	@echo "=============================================="

tags:
	@-ctags -f tags $$(find $(TAGDIRS) -type f -name "*.[ch]")

htmldoc: bin/schema2html
	@rm -rf html
	@mkdir html
	LD_LIBRARY_PATH=. ./bin/schema2html --outdir html --config etc/server.xml

distclean clean::
	rm -f *~ *.o libwicked.* core LOG
	rm -rf $(BIN) $(OBJ) $(GENFILES)
	rm -f testing/*.o
	rm -f testing/*-test

distclean::
	rm -f .depend tags
	rm -f config.h wicked.pc
	rm -f etc/init.d/wicked
	rm -f etc/init.d/network

realclean maintainer-clean: distclean
	rm -rf autom4te.cache *.log *.scan
	rm -f aclocal.m4 configure config.*
	rm -f Makefile.vars wicked.spec
	rm -f $(DIST_ARCHIVE)

install-strip: STRIP_FLAG=-s
install-strip: install

install: Makefile.vars install-no-devel install-devel

install-devel: install-devel-lib install-devel-data

install-no-devel: install-bin install-data install-man

install-init: install-bin
	install -d -m 755 $(DESTDIR)$(sysvinitdir)
	install -c -m 755 etc/init.d/wicked  $(DESTDIR)$(sysvinitdir)/wicked
	install -c -m 755 etc/init.d/network $(DESTDIR)$(sysvinitdir)/network

install-bin: $(APPBINS) install-lib
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
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)
	install -m 644 etc/*.xml $(DESTDIR)$(wickedconfigdir)
	install -d -m 755 $(DESTDIR)$(dbus_systemdir)
	install -c -m 444 etc/*.conf $(DESTDIR)$(dbus_systemdir)
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)/schema
	install -c -m 444 schema/*.xml $(DESTDIR)$(wickedconfigdir)/schema
	install -d -m 755 $(DESTDIR)$(wickedconfigdir)/extensions
	install -c -m 555 extensions/* $(DESTDIR)$(wickedconfigdir)/extensions

install-man:
	install -d -m 755 $(DESTDIR)$(mandir)/man{5,7,8}
	install -c -m 444 man/*.5 $(DESTDIR)$(mandir)/man5
	install -c -m 444 man/*.7 $(DESTDIR)$(mandir)/man7
	install -c -m 444 man/*.8 $(DESTDIR)/$(mandir)/man8

install-devel-lib: install-lib
	install -d -m 755 $(DESTDIR)$(devellibdir)
	ln -sf $(libdir)/$(LIBSONAME) $(DESTDIR)$(devellibdir)/$(LIBNAME).so

install-devel-data: wicked.pc
	install -d -m 755 $(DESTDIR)$(includedir)/wicked
	install -c -m 644 $(wildcard include/wicked/*.h) $(DESTDIR)$(includedir)/wicked
	install -d -m 755 $(DESTDIR)$(pkgconfigdir)
	install -c -m 644 wicked.pc $(DESTDIR)$(pkgconfigdir)

schema/constants.xml: $(BIN)/mkconst schema/constants.xml.in
	@echo Building $@ from $@.in
	@LD_PRELOAD=$$PWD/$(LIBNAME).so $(BIN)/mkconst < $@.in > $@

$(BIN)/wicked: LDFLAGS += -rdynamic -L. -lwicked -lm $(LIBS)
$(BIN)/wicked: LDFLAGS += $(LDCOMMON)
$(BIN)/wicked: $(CLIENTOBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(CLIENTOBJS) $(LDFLAGS)

$(BIN)/wickedd: LDFLAGS += -rdynamic -L. -lwicked -lm $(LIBS)
$(BIN)/wickedd: LDFLAGS += $(LDCOMMON)
$(BIN)/wickedd: $(SERVEROBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(SERVEROBJS) $(LDFLAGS)

$(BIN)/network-nanny: LDFLAGS += -rdynamic -L. -lwicked -lm $(LIBS)
$(BIN)/network-nanny: LDFLAGS += $(LDCOMMON)
$(BIN)/network-nanny: $(NANNYOBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(NANNYOBJS) $(LDFLAGS)

$(BIN)/dhcp4-supplicant: LDFLAGS += -L. -lwicked -lm $(LIBS)
$(BIN)/dhcp4-supplicant: LDFLAGS += $(LDCOMMON)
$(BIN)/dhcp4-supplicant: $(DHCP4OBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(DHCP4OBJS) $(LDFLAGS)

$(BIN)/autoip4-supplicant: LDFLAGS += -L. -lwicked -lm $(LIBS)
$(BIN)/autoip4-supplicant: LDFLAGS += $(LDCOMMON)
$(BIN)/autoip4-supplicant: $(AUTO4OBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(AUTO4OBJS) $(LDFLAGS)

$(BIN)/dhcp6-supplicant: LDFLAGS += -rdynamic -L. -lwicked -lm $(LIBS)
$(BIN)/dhcp6-supplicant: LDFLAGS += $(LDCOMMON)
$(BIN)/dhcp6-supplicant: $(DHCP6OBJS) $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $(DHCP6OBJS) $(LDFLAGS)

$(BIN)/mkconst: LDFLAGS += -L. -lwicked -lm $(LIBS)
$(BIN)/mkconst: LDFLAGS += $(LDCOMMON)
$(BIN)/mkconst: $(OBJ)/util/mkconst.o $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

$(BIN)/schema2html: LDFLAGS += -L. -lwicked -lm $(LIBS)
$(BIN)/schema2html: LDFLAGS += $(LDCOMMON)
$(BIN)/schema2html: $(OBJ)/util/schema2html.o $(TGTLIBS)
	@mkdir -p bin
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

testing: $(basename $(wildcard testing/*-test.c))

testing/%-test: LDFLAGS += -L. -lwicked $(LIBS)
testing/%-test: LDFLAGS += $(LDCOMMON)
testing/%-test: testing/%-test.o $(TGTLIBS)
	@rm -f $@
	$(CC) -o $@ $(CFLAGS) $< $(LDFLAGS)

$(LIBNAME).a: $(LIBOBJS)
	@rm -f $@
	ar cr $@ $(LIBOBJS)

$(LIBNAME).so: LDFLAGS += -lanl
$(LIBNAME).so: $(SHLIBOBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIBSONAME) $(LDFLAGS) -o $@ $(SHLIBOBJS)
	ln -sf $@ $(LIBSONAME)

depend: config.h $(SOURCES)
	$(CC) $(CPPFLAGS) -MM $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/lib/\2&@' > .depend
	$(CC) $(CPPFLAGS) -MM $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/shlib/\2&@' >> .depend
	$(CC) $(CPPFLAGS) -MM $(UTILSRCS) | sed 's:^[a-z]:$(OBJ)/util/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(DHCP4SRCS) | sed 's:^[a-z]:$(OBJ)/dhcp4/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(DHCP6SRCS) | sed 's:^[a-z]:$(OBJ)/dhcp6/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(AUTO4SRCS) | sed 's:^[a-z]:$(OBJ)/autoip4/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(CLIENTSRCS) | sed 's:^[a-z]:$(OBJ)/client/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(SERVERSRCS) | sed 's:^[a-z]:$(OBJ)/server/&:' >> .depend
	$(CC) $(CPPFLAGS) -MM $(NANNYSRCS) | sed 's:^[a-z]:$(OBJ)/nanny/&:' >> .depend

$(OBJ)/%.o: %.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(OBJ)/lib/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(OBJ)/shlib/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -c -o $@ $<

$(OBJ)/netcf/%.o: src/%.c
	@rm -f $@
	@test -d $(dir $@) || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

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
		--exclude="*/.[^.]*"         \
		--exclude="*~"               \
		--exclude="*.o"              \
		--exclude="*.a"              \
		--exclude="*.so*"            \
		--exclude="*.log"            \
		--exclude="*.swp"            \
		--exclude="*.rej"            \
		--exclude="*.orig"           \
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

config.h: config.h.in

config.h.in config.status: configure

configure: configure.ac
	test -f $@ && ./config.status --recheck || ./autogen.sh

Makefile: Makefile.vars

Makefile.vars config.h wicked.pc wicked.spec: config.status
	./config.status $@

-include .depend

