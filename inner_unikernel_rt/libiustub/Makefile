CC = gcc
CFLAGS = -fPIC
LDFLAGS = -nostartfiles -nodefaultlibs

libiustub.so: lib.c
	${CC} --shared ${CFLAGS} ${LDFLAGS} -o$@ $<

clean:
	rm libiustub.so
