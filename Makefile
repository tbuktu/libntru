CC=gcc
CFLAGS=-g -Wall

lib: poly.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libntru.so -o libntru.so poly.o

test: lib
	$(CC) $(CFLAGS) -o test -L. -lntru src/test_util.c src/test.c src/test_poly.c
	LD_LIBRARY_PATH=. ./test

%.c %.o:
	$(CC) $(CFLAGS) -c -fPIC src/$*.c -o $@

clean:
	rm -f encparams.o poly.o libntru.so test
