# Settings for Linux - you might have to tweek the include paths
CPP := c++ -g3 -Wall -I/opt/local/include -fPIC
CC := cc -g3 -Wall -I/opt/local/include
LINK := -L/opt/local/lib -lssl -lcrypto
LIBTOOL := libtool
libsdtree_OBJS = fclient.lo fpublish.lo sdtcommon.lo sdtdecrypt.lo sdtkeylist.lo sdtree.lo signature.lo
libdir = /usr/lib
includedir = /usr/include

# Settings for OSX
LIBTOOL := glibtool

define compile_rule_cxx
	$(LIBTOOL) --mode=compile --tag CXX \
	$(CPP) $(CFLAGS) $(CPPFLAGS) -c $<
endef
define compile_rule
	$(LIBTOOL) --mode=compile --tag CC \
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $<
endef
define link_rule
	$(LIBTOOL) --mode=link --tag CC \
	$(CC) $(LDFLAGS) -rpath $(libdir) -o $@ $^ $(LDLIBS) -lstdc++ -lssl -lcrypto
endef
define link_rule_cxx
	$(LIBTOOL) --mode=link --tag CXX \
	$(CC) $(LDFLAGS) -rpath $(libdir) -o $@ $^ $(LDLIBS) -lssl -lcrypto
endef

all: libsdtree.la fsadm sdtdecrypt

LIBS = libsdtree.la

%.lo: %.c
	$(call compile_rule)

%.lo: %.cc
	$(call compile_rule_cxx)

libsdtree.la: $(libsdtree_OBJS)
	$(call link_rule)

fsadm: libsdtree.la fsadm.cc
	$(LIBTOOL) --mode=link --tag CXX $(CPP) $(LDFLAGS)-static -o fsadm fsadm.cc libsdtree.la -lssl -lcrypto

sdtdecrypt:
	$(LIBTOOL) --mode=link --tag CXX $(CPP) $(LDFLAGS)-static -o sdtdecrypt sdtdecrypt.cc libsdtree.la -lssl -lcrypto

install/%.la: %.la
	$(LIBTOOL) --mode=install \
	install -c $(notdir $@) $(libdir)/$(notdir $@)
install: $(addprefix install/,$(LIBS))
	$(LIBTOOL) --mode=finish $(libdir)
	install -c sdtree.h $(includedir)

clean:
	rm -f *.o *.core fsadm sdtdecrypt ccaller libsdtree.a *.lo *.la
	rm -rf .libs

cleanall:
	rm -f *.o *.core fsadm sdtdecrypt cfile serverkey rev ccaller libsdtree.a


