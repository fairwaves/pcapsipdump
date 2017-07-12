CHECK_LIBBSD = $(CXX) $(CXXFLAGS) $(LDFLAGS) make-checks/libbsd.cpp -lbsd -o make-checks/libbsd 2>/dev/null

make-checks/libbsd:
	@$(CHECK_LIBBSD) || (\
	  echo "*** notice: recommended library not found: libbsd"; \
	  true)
