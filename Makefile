
CFLAGS	= -Wall -Werror -g -O2 -D_GNU_SOURCE -I. -Iinclude -Isrc \
	  $(CFLAGS_DBUS)
CFLAGS_DBUS := $(shell pkg-config --cflags dbus-1)

APPS	= wicked wickedd dhcp4-supplicant \
	  testing/xml-test testing/xpath-test

TGTLIBS	= libnetinfo.a \
	  libnetcf.a
	  # libnetinfo.so
# Public header files
LIBHDRS	= logging.h \
	  netinfo.h \
	  types.h \
	  util.h \
	  wicked.h \
	  xml.h \
	  xpath.h \
	  netcf.h
__LIBSRCS= \
	  config.c \
	  rest-api.c \
	  extension.c \
	  policy.c \
	  netinfo.c \
	  netconfig.c \
	  ethernet.c \
	  vlan.c \
	  bonding.c \
	  bridge.c \
	  wireless.c \
	  state.c \
	  iflist.c \
	  ifconfig.c \
	  ifevent.c \
	  indirect.c \
	  kernel.c \
	  address.c \
	  sysconfig.c \
	  sysfs.c \
	  syntax.c \
	  backend-suse.c \
	  backend-redhat.c \
	  backend-netcf.c \
	  nis.c \
	  resolver.c \
	  update.c \
	  leasefile.c \
	  xml.c \
	  xml-reader.c \
	  xml-writer.c \
	  xpath.c \
	  xpath-fmt.c \
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
	  dbus-server.c \
	  dbus-object.c \
	  dbus-objects/model.c \
	  dbus-objects/interface.c \
	  dbus-objects/ethernet.c \
	  dbus-objects/vlan.c \
	  dbus-objects/bridge.c \
	  dbus-objects/dhcp4.c \
	  dbus-objects/misc.c \
	  wpa-supplicant.c \
	  ipv6/addrconf.c \
	  dhcp/addrconf.c \
	  dhcp/lease.c \
	  ipv4ll/addrconf.c \
	  ipv4ll/rest-api.c \
	  ipv4ll/device.c \
	  ipv4ll/fsm.c
__NCFSRCS= \
	  netcf.c
DHCP4SRCS = \
	  dhcp4-supplicant.c \
	  dhcp4/dbus-api.c \
	  dhcp4/fsm.c \
	  dhcp4/device.c \
	  dhcp4/protocol.c

OBJ	= obj
LIBSRCS	= $(addprefix src/,$(__LIBSRCS))
LIBOBJS	= $(addprefix $(OBJ)/lib/,$(__LIBSRCS:.c=.o))
SHLIBOBJS= $(addprefix $(OBJ)/shlib/,$(__LIBSRCS:.c=.o))
NCFSRCS	= $(addprefix src/,$(__NCFSRCS))
NCFOBJS	= $(addprefix $(OBJ)/netcf/,$(__NCFSRCS:.c=.o))
APPSRCS	= $(addsuffix .c,$(APPS))
DHCP4OBJS= $(addprefix $(OBJ)/,$(DHCP4SRCS:.c=.o))

all: $(TGTLIBS) $(APPS)

distclean clean::
	rm -f *.o *.a *.so $(APPS) core tags
	rm -rf $(OBJ)
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
	install -d -m 755 $(DESTDIR)/var/run/wicked

wicked: $(OBJ)/wicked.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/wicked.o -L. -lnetinfo -lm -lnl -ldbus-1

wickedd: $(OBJ)/wickedd.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/wickedd.o -L. -lnetinfo -lm -lnl -ldbus-1

dhcp4-supplicant: $(DHCP4OBJS) $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(DHCP4OBJS) -L. -lnetinfo -lm -lnl -ldbus-1

test: $(OBJ)/test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) $(OBJ)/test.o -L. -lnetinfo -ldbus-1

testing/xml-test: testing/xml-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xml-test.o -L. -lnetinfo -ldbus-1

testing/xpath-test: testing/xpath-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xpath-test.o -L. -lnetinfo -ldbus-1

libnetinfo.a: $(LIBOBJS)
	@rm -f $@
	ar cr $@ $(LIBOBJS)

libnetcf.a: $(NCFOBJS)
	@rm -f $@
	ar cr $@ $(NCFOBJS)

libnetinfo.so: $(SHLIBOBJS)
	$(CC) $(CFLAGS) -shared -o $@ $(SHLIBOBJS)

depend:
	gcc $(CFLAGS) -M $(LIBSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/lib/\2&@' > .depend
	gcc $(CFLAGS) -M $(NCFSRCS) | \
		sed 's@^\([^.]*\)\.o: src/\([-a-z0-9/]*\)\1.c@obj/netcf/\2&@' >> .depend
	gcc $(CFLAGS) -M $(APPSRCS) | sed 's:^[a-z]:$(OBJ)/&:' >> .depend
	gcc $(CFLAGS) -M $(DHCP4SRCS) | sed 's:^[a-z]:$(OBJ)/dhcp4/&:' >> .depend

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

