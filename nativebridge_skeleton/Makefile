CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11

.PHONY: all clean run-demo

all: libtiny_nativebridge_stub.so tiny_nb_loader_demo

libtiny_nativebridge_stub.so: tiny_nativebridge_stub.c tiny_nativebridge_stub.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ tiny_nativebridge_stub.c -ldl

tiny_nb_loader_demo: tiny_nb_loader_demo.c tiny_nativebridge_stub.h
	$(CC) $(CFLAGS) -o $@ tiny_nb_loader_demo.c -ldl

run-demo: all
	LD_LIBRARY_PATH=. ./tiny_nb_loader_demo ./libtiny_nativebridge_stub.so

clean:
	rm -f libtiny_nativebridge_stub.so tiny_nb_loader_demo
