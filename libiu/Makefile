LINUX ?= $(HOME)/linux

CXX = g++
LD = g++
AR = gcc-ar

INC += -I${LINUX}/tools/lib -I${LINUX}/tools/include -I${LINUX}/usr/include
INC += -I${LINUX}/tools/include/uapi

CXXFLAGS += -O2 -march=native -pipe -std=gnu++17 -fPIC -fno-exceptions
CXXFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition

LDFLAGS += -Wl,--as-needed -Wl,-O1 -L${LINUX}/tools/lib/bpf -lbpf

all: libiu.a libiu.so

libiu.a: libiu.o
	${AR} rcs $@ $<

libiu.so: libiu.o
	${LD} ${CXXFLAGS} ${LDFLAGS} -shared $< -o $@

libiu.o: libiu.cpp libiu.h
	${CXX} ${INC} ${CXXFLAGS} -c libiu.cpp -o $@

clean:
	rm -f libiu.o libiu.a libiu.so
