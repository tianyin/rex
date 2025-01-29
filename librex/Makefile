LINUX ?= $(HOME)/linux

ifeq ($(LLVM),1) # Using LLVM toolchain
CXX = clang++
LD = clang++
AR = llvm-ar
else # Using GNU toolchain
CXX = g++
LD = g++
AR = gcc-ar
endif

# Find LLVM-related path
LLVM_INC := $(shell llvm-config --includedir)
LLVM_LIBDIR := $(shell llvm-config --libdir)

INC += -I./include -I${LINUX}/usr/include -I${LINUX}/tools/lib -I${LLVM_INC}

CXXFLAGS += -O2 -march=native -pipe -std=c++23 -fPIC -Wall -Werror -g
CXXFLAGS += -ffunction-sections -fdata-sections -fno-semantic-interposition
CXXFLAGS += -fvisibility=hidden

ifeq ($(LLVM),1) # LLVM ThinLTO
CXXFLAGS += -flto=thin
else # GCC FAT LTO
CXXFLAGS += -flto=jobserver -ffat-lto-objects -fuse-linker-plugin
endif

LDFLAGS += -fuse-ld=mold -Wl,--as-needed -Wl,-O1 -Wl,--gc-sections
LDFLAGS += -L${LINUX}/tools/lib/bpf -L${LLVM_LIBDIR} -lbpf -lelf -lLLVM

all: librex.a librex.so

librex.a: lib/librex.o
	+${AR} rcs $@ $<

librex.so: lib/librex.o
	+${LD} ${CXXFLAGS} -shared -o $@ $< ${LDFLAGS}

lib/librex.o: lib/librex.cpp include/librex.h lib/bindings.h
	+${CXX} ${INC} ${CXXFLAGS} -o $@ -c lib/librex.cpp

clean:
	rm -f lib/librex.o librex.a librex.so
