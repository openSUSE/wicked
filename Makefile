
CFLAGS	= -Wall -g -O2 -D_GNU_SOURCE -I.

APPS	= wicked wickedd testing/xml-test testing/xpath-test

TGTLIBS	= libnetinfo.a \
	  # libnetinfo.so
SRCS	= $(LIBSRCS) \
	  $(addsuffix .c,$(APPS))
LIBSRCS	= \
	  config.c \
	  rest-api.c \
	  extension.c \
	  policy.c \
	  netinfo.c \
	  netconfig.c \
	  vlan.c \
	  bonding.c \
	  bridge.c \
	  state.c \
	  iflist.c \
	  ifconfig.c \
	  ifevent.c \
	  kernel.c \
	  address.c \
	  sysconfig.c \
	  sysfs.c \
	  libnetlink.c \
	  syntax.c \
	  backend-suse.c \
	  backend-netcf.c \
	  xml.c \
	  xml-reader.c \
	  xml-writer.c \
	  xpath.c \
	  xpath-fmt.c \
	  util.c \
	  socket.c \
	  logging.c
LIBOBJS	= $(addprefix obj/,$(LIBSRCS:.c=.o))
SHLIBOBJS= $(addprefix obj-shared/,$(LIBSRCS:.c=.o))

all: $(TGTLIBS) $(APPS)

distclean clean::
	rm -f *.o *.a $(APPS) core .depend
	rm -rf obj obj-shared
	rm testing/*.o

distclean::
	rm -f .depend

install: install-files
	install -s -m 555 wickedd wicked $(DESTDIR)/sbin

install-files:
	install -d -m 755 $(DESTDIR)/etc/wicked
	install -m 644 etc/wicked/*.xml $(DESTDIR)/etc/wicked
	install -m 555 etc/wicked/wicked-dhcp4 $(DESTDIR)/etc/wicked

wicked: obj/wicked.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) obj/wicked.o -L. -lnetinfo

wickedd: obj/wickedd.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) obj/wickedd.o -L. -lnetinfo

test: obj/test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) obj/test.o -L. -lnetinfo

testing/xml-test: testing/xml-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xml-test.o -L. -lnetinfo

testing/xpath-test: testing/xpath-test.o $(TGTLIBS)
	$(CC) -o $@ $(CFLAGS) testing/xpath-test.o -L. -lnetinfo

libnetinfo.a: $(LIBOBJS)
	ar cr $@ $(LIBOBJS)

libnetinfo.so: $(SHLIBOBJS)
	$(CC) $(CFLAGS) -shared -o $@ $(SHLIBOBJS)

depend:
	gcc $(CFLAGS) -M $(SRCS) | sed 's:^[a-z]:obj/&:' > .depend

obj/%.o: %.c
	@test -d obj || mkdir -p obj
	$(CC) $(CFLAGS) -c -o $@ $<

obj-shared/%.o: %.c
	@test -d obj-shared || mkdir -p obj-shared
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

-include .depend

