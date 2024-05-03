LINUX ?= $(HOME)/linux

CXX = g++
LD = g++
AR = gcc-ar

INC += -I${LINUX}/tools/lib -I${LINUX}/usr/include

CXXFLAGS += -O2 -march=native -pipe -std=c++23 -fPIC
CXXFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
CXXFLAGS += -flto=jobserver -ffat-lto-objects -fuse-linker-plugin

LDFLAGS += -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections
LDFLAGS += -L${LINUX}/tools/lib/bpf -lbpf -lelf

all: librex.a librex.so

librex.a: librex.o
	+${AR} rcs $@ $<

librex.so: librex.o
	+${LD} ${CXXFLAGS} -shared -o $@ $< ${LDFLAGS}

librex.o: librex.cpp librex.h
	+${CXX} ${INC} ${CXXFLAGS} -o $@ -c librex.cpp

clean:
	rm -f librex.o librex.a librex.so
