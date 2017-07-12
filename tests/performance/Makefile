LIBS ?= -lpcap -lstdc++
CXXFLAGS ?= --std=c++11

tests: calltable_benchmark

calltable_benchmark: calltable_benchmark.cpp ../../calltable.cpp ../../calltable.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(DEFS) $(BSDSTR_DEFS) -ggdb -pg \
	calltable_benchmark.cpp ../../calltable.cpp $(LIBS) $(BSDSTR_LIBS) \
	-o calltable_benchmark
