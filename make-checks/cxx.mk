CHECK_CXX = $(CXX) $(CXXFLAGS) $(LDFLAGS) make-checks/cxx.cpp -lstdc++ -o make-checks/cxx

make-checks/cxx:
	@$(CHECK_CXX) || (\
	  echo; \
	  echo $(CHECK_CXX); \
	  echo; \
	  echo "==="; \
	  echo "C++ compiler and/or standard libraries not found."; \
	  echo "Please install them in your distribution-specific manner, e.g.:"; \
	  echo " yum install gcc-c++ libstdc++-devel"; \
	  echo " apt-get install g++ libstdc++-dev"; \
	  echo "==="; \
	  false)
