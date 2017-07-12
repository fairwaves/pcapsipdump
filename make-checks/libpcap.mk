CHECK_LIBPCAP = $(CXX) $(CXXFLAGS) $(LDFLAGS) make-checks/libpcap.cpp -lpcap -o make-checks/libpcap

make-checks/libpcap:
	@$(CHECK_LIBPCAP) || (\
	  echo; \
	  echo $(CHECK_LIBPCAP); \
	  echo; \
	  echo "==="; \
	  echo "Required library not found: pcap "; \
	  echo "Please install it in your distribution-specific manner, e.g.:"; \
	  echo " yum install libpcap libpcap-devel"; \
	  echo " apt-get install tcpdump libpcap-dev"; \
	  echo " cd ~ports/net/libpcap && make install"; \
	  echo "==="; \
	  false)
