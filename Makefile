LIBS ?= -lpcap -lstdc++
RELEASEFLAGS ?= -O3 -Wall
#CXXFLAGS ?= --std=c++0x

# auto-detect if bsd/strings.h is available
ifeq ($(shell $(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFS) -E -o /dev/null \
    	make-checks/libbsd.cpp 2>/dev/null; echo $$?),0)
	BSDSTR_DEFS := -DUSE_BSD_STRING_H
	BSDSTR_LIBS := -lbsd
endif

# auto-detect rhel/fedora and debian/ubuntu
ifneq ($(wildcard /etc/redhat-release),)
	EXTRA_INSTALL := install-redhat
endif
ifneq ($(wildcard /etc/debian_version),)
	EXTRA_INSTALL := install-debian
endif

all: make-checks/all pcapsipdump

include make-checks/*.mk

pcapsipdump: make-checks *.cpp *.h
	$(CXX) $(RELEASEFLAGS) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) \
	*.cpp \
	$(LIBS) $(BSDSTR_LIBS) \
	-o pcapsipdump

pcapsipdump-debug: make-checks *.cpp *.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) -ggdb \
	*.cpp \
	$(LIBS) $(BSDSTR_LIBS) -pg \
	-o pcapsipdump-debug

clean: make-checks/clean
	rm -f pcapsipdump pcapsipdump-debug gmon.out

install: pcapsipdump $(EXTRA_INSTALL)
	install pcapsipdump ${DESTDIR}/usr/sbin/pcapsipdump
	mkdir -p ${DESTDIR}/var/spool/pcapsipdump
	chmod 0700 ${DESTDIR}/var/spool/pcapsipdump

install-redhat:
	install redhat/pcapsipdump.init ${DESTDIR}/etc/rc.d/init.d/pcapsipdump
	install redhat/pcapsipdump.sysconfig ${DESTDIR}/etc/sysconfig/pcapsipdump

install-debian:
	install debian/pcapsipdump.init ${DESTDIR}/etc/init.d/pcapsipdump
	install debian/pcapsipdump.default ${DESTDIR}/etc/default/pcapsipdump

.PHONY: tests

tests:
	make -C tests
