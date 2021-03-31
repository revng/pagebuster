# Usage:
# make		# build library
# make clean	# remove ALL binaries and objects

.PHONY: all clean

CC := gcc

GLIB = $(shell pkg-config --cflags --libs glib-2.0)

all: userpagebuster.so example

example: example.c
	@ ${CC} $< -g -o $@

userpagebuster.so: userpagebuster.c
	@ ${CC} -shared -fPIC ${GLIB} $< -ldl -o $@

clean:
	@ echo "Cleaning up ..."
	@ rm *.so
