CFLAGS+=-std=gnu99 -g
CXXFLAGS+=-std=c++11 -g

UNAME := $(shell uname -s)
ifneq ($(UNAME),Darwin)
LDFLAGS+=-lrt -lm
else
OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
CXXFLAGS+=-I$(OPENSSL_PREFIX)/include
LDFLAGS+=-L$(OPENSSL_PREFIX)/lib
endif

PROGS=udpstress isoping isostream isoping_test

all: $(PROGS)

udpstress: udpstress.c dscp.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping: isoping.cc isoping_main.cc
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) -lcrypto

isostream: isostream.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

isoping_test: isoping.cc isoping_test.cc wvtest/cpp/wvtest.cc wvtest/cpp/wvtestmain.cc
	$(CXX) $(CXXFLAGS) -DWVTEST_CONFIGURED -Iwvtest/cpp $^ -o $@ $(LDFLAGS) -lcrypto

test: isoping_test
	./wvtest/wvtestrun ./isoping_test

clean:
	rm -f $(PROGS) *~ .*~ *.o
	rm -rf *.dSYM
