LINUX ?= $(HOME)/linux

CXX = clang++
CXXFLAGS = -g -pipe -std=c++17 -fPIC -I${LINUX}/tools/lib -I${LINUX}/tools/include -I${LINUX}/usr/include -I${LINUX}/tools/include/uapi
LDFLAGS = -Wl,--as-needed -L${LINUX}/tools/lib/bpf -lbpf
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
