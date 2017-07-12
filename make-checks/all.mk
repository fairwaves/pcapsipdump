make-checks/all: make-checks/cxx make-checks/libpcap make-checks/libbsd
	@touch make-checks/all

make-checks/clean:
	rm -f make-checks/all make-checks/cxx make-checks/libpcap make-checks/libbsd
