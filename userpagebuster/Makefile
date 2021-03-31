# Usage:
# make		# build library
# make clean	# remove ALL binaries and objects

.PHONY: all clean

CC := gcc
LD := ld

PKG = $(shell pkg-config --cflags --libs glib-2.0)
CFLAGS = -fPIC
LDFLAGS = -shared -ldl

all: userpagebuster.so

userpagebuster.o: userpagebuster.c
	@ echo "Building library ..."
	@ ${CC} -c $< ${CFLAGS} ${PKG}

userpagebuster.so: userpagebuster.o
	@ ${LD} ${LDFLAGS} ${PKG} $< -o $@

clean:
	@ echo "Cleaning up ..."
	@ rm *.so *.o