CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
LDLIBS ?= -lm

.PHONY: all clean run-demo run-jni-probe

all: libtiny_nativebridge_stub.so tiny_nb_loader_demo tiny_nb_jni_probe

libtiny_nativebridge_stub.so: tiny_nativebridge_stub.c tiny_nativebridge_stub.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ tiny_nativebridge_stub.c -ldl

tiny_nb_loader_demo: tiny_nb_loader_demo.c tiny_nativebridge_stub.h
	$(CC) $(CFLAGS) -o $@ tiny_nb_loader_demo.c -ldl $(LDLIBS)

../tiny_dbt_runtime.o:
	$(MAKE) -C .. tiny_dbt_runtime.o

tiny_nb_jni_probe: tiny_nb_jni_probe.c tiny_nativebridge_stub.h ../tiny_dbt_runtime.h ../tiny_dbt_runtime.o
	$(CC) $(CFLAGS) -I.. -o $@ tiny_nb_jni_probe.c ../tiny_dbt_runtime.o $(LDLIBS)

run-demo: all
	LD_LIBRARY_PATH=. ./tiny_nb_loader_demo ./libtiny_nativebridge_stub.so

run-jni-probe: tiny_nb_jni_probe
	./tiny_nb_jni_probe

clean:
	rm -f libtiny_nativebridge_stub.so tiny_nb_loader_demo tiny_nb_jni_probe
