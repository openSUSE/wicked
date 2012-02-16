
CFLAGS	= -Wall -Werror -g -O2 -D_GNU_SOURCE -I. -Iinclude -Isrc \
	  $(CFLAGS_DBUS)
CFLAGS_DBUS := $(shell pkg-config --cflags dbus-1)

APPS	= wicked wickedd wicked-convert \
	  dhcp4-supplicant autoip4-supplicant \
	  testing/xml-test testing/xpath-test \
	  etc/mkconst

TGTLIBS	= libnetinfo.a
	  # libnetinfo.so
# Public header files
LIBHDRS	= logging.h \
	  netinfo.h \
	  types.h \
	  util.h \
	  wicked.h \
	  xml.h \
	  xpath.h
__LIBSRCS= \
	  config.c \
	  extension.c \
	  policy.c \
	  netinfo.c \
	  interface.c \
	  names.c \
	  ethernet.c \
	  vlan.c \
	  bonding.c \
	  bridge.c \
	  wireless.c \
	  state.c \
	  iflist.c \
	  ifconfig.c \
	  ifevent.c \
	  kernel.c \
	  address.c \
	  sysconfig.c \
	  sysfs.c \
	  backend.c \
	  backend-netcf.c \
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
	  dbus-objects/model.c \
	  dbus-objects/interface.c \
	  dbus-objects/ethernet.c \
	  dbus-objects/wireless.c \
	  dbus-objects/vlan.c \
	  dbus-objects/bridge.c \
	  dbus-objects/bonding.c \
	  dbus-objects/addrconf.c \
	  dbus-objects/misc.c \
	  dbus-objects/linkage.c \
	  wpa-supplicant.c \
	  dhcp-lease.c
DHCP4SRCS = \
	  dhcp4/dbus-api.c \
	  dhcp4/fsm.c \
	  dhcp4/device.c \
	  dhcp4/protocol.c
AUTO4SRCS = \
	  autoip4/dbus-api.c \
	  autoip4/device.c \
	  autoip4/fsm.c
CONVSRCS = \
	  convert/suse.c \
	  convert/redhat.c
CLIENTSRCS = \
	  client/ifup.c \
	  client/calls.c
GENFILES = \
	  schema/constants.xml

OBJ	= obj
LIBSRCS	= $(addprefix src/,$(__LIBSRCS))
LIBOBJS	= $(addprefix $(OBJ)/lib/,$(__LIBSRCS:.c=.o))
SHLIBOBJS= $(addprefix $(OBJ)/shlib/,$(__LIBSRCS:.c=.o))
APPSRCS	= $(addsuffix .c,$(APPS))
DHCP4OBJS= $(addprefix $(OBJ)/,$(DHCP4SRCS:.c=.o))
AUTO4OBJS= $(addprefix $(OBJ)/,$(AUTO4SRCS:.c=.o))
CONVOBJS = $(addprefix $(OBJ)/,$(CONVSRCS:.c=.o))
CLIENTOBJS= $(addprefix $(OBJ)/,$(CLIENTSRCS:.c=.o))


all: $(TGTLIBS) $(APPS) $(GENFILES)

distclean clean::
	rm -f *.o *.a *.so $(APPS) core tags
	rm -rf $(OBJ) $(GENFILES)
	rm -f etc/mkconst.o
	rm -f testing/*.o

distclean::
	rm -f .depend

install: install-files
	install -d -m 755 $(DESTDIR)/sbin
	install -s -m 555 wickedd wicked $(DESTDIR)/sbin
	install -d -m 755 $(DESTDIR)/usr/share/man/man{7,8}
	install -c -m 444 man/*.7 $(DESTDIR)/usr/share/man/man7
	install -c -m 444 man/*.8 $(DESTDIR)/usr/share/man/man8

install-files:
	install -d -m 755 $(DESTDIR)/etc/wicked
	install -m 644 etc/wicked/*.xml $(DESTDIR)/etc/wicked
	install -d -m 755 $(DESTDIR)/etc/dbus-1/system.d
	install -c -m 444 etc/wicked*.conf $(DESTDIR)/etc/dbus-1/system.d
	install -d -m 755 $(DESTDIR)/etc/wicked/schema
	install -c -m 444 schema/*.xml $(DESTDIR)/etc/wicked/schema
	install -d -m 755 $(DESTDIR)/var/run/wicked

schema/constants.xml: etc/mkconst schema/constants.xml.in
	etc/mkconst < $@.in > $@

wicked: $(OBJ)/wicked.o $(CLIENTOBJS) $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/wicked.o $(CLIENTOBJS) -rdynamic -L. -lnetinfo -lm -lnl -ldbus-1 -ldl

wickedd: $(OBJ)/wickedd.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/wickedd.o -rdynamic -L. -lnetinfo -lm -lnl -ldbus-1 -ldl

wicked-convert: $(OBJ)/wicked-convert.o $(CONVOBJS) $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/wicked-convert.o $(CONVOBJS) -L. -lnetinfo -lm -lnl -ldbus-1 -ldl

dhcp4-supplicant: $(OBJ)/dhcp4-supplicant.o $(DHCP4OBJS) $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/dhcp4-supplicant.o $(DHCP4OBJS) -L. -lnetinfo -lm -lnl -ldbus-1 -ldl

autoip4-supplicant: $(OBJ)/autoip4-supplicant.o $(AUTO4OBJS) $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/autoip4-supplicant.o $(AUTO4OBJS) -L. -lnetinfo -lm -lnl -ldbus-1 -ldl

etc/mkconst: etc/mkconst.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) etc/mkconst.o -L. -lnetinfo -lnl -ldbus-1 -ldl

test: $(OBJ)/test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/test.o -L. -lnetinfo -ldbus-1

testing/xml-test: testing/xml-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xml-test.o -L. -lnetinfo -ldbus-1

testing/xpath-test: testing/xpath-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xpath-test.o -L. -lnetinfo -ldbus-1

libnetinfo.a: $(LIBOBJS)
	@rm -f $@
	ar cr $@ $(LIBOBJS)

libnetinfo.so: $(SHLIBOBJS)
	$(CC) $(CFLAGS) -shared -o $@ $(SHLIBOBJS)

depend:
	gcc $(CFLAGS) -M $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/lib/\2&@' > .depend
	gcc $(CFLAGS) -M $(APPSRCS) | sed 's:^[a-z]:$(OBJ)/&:' >> .depend
	gcc $(CFLAGS) -M $(DHCP4SRCS) | sed 's:^[a-z]:$(OBJ)/dhcp4/&:' >> .depend
	gcc $(CFLAGS) -M $(AUTO4SRCS) | sed 's:^[a-z]:$(OBJ)/autoip4/&:' >> .depend
	gcc $(CFLAGS) -M $(CONVSRCS) | sed 's:^[a-z]:$(OBJ)/convert/&:' >> .depend
	gcc $(CFLAGS) -M $(CLIENTSRCS) | sed 's:^[a-z]:$(OBJ)/client/&:' >> .depend

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

-include .depend

