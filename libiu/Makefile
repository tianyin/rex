LINUX ?= ../linux

CXX = clang++
CXXFLAGS = -g -pipe -std=c++17 -fPIC -I${LINUX}/usr/include
LDFLAGS = -Wl,--as-needed
LD = clang++
AR = llvm-ar

all: libiu.a libiu.so

libiu.a: libiu.o
	${AR} rcs $@ $<

libiu.so: libiu.o
	${LD} ${LDFLAGS} -shared $< -lelf -o $@

libiu.o: libiu.cpp libiu.h
	${CXX} ${CXXFLAGS} -c libiu.cpp -o $@

clean:
	rm -f libiu.o libiu.a libiu.so
