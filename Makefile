CC=gcc
CFLAGS=-g -Wall
SRC=src

lib: ntruencrypt.o poly.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,libntru.so -o libntru.so ntruencrypt.o poly.o

test: lib test_util.o test_poly.o test_ntruencrypt.o
	$(CC) $(CFLAGS) -o test -L. -lntru $(SRC)/test.c $(SRC)/test_util.c $(SRC)/test_poly.c $(SRC)/test_ntruencrypt.c
	LD_LIBRARY_PATH=. ./test

%.c %.o:
	$(CC) $(CFLAGS) -c -fPIC $(SRC)/$*.c -o $@

clean:
	rm -f ntruencrypt.o encparams.o poly.o libntru.so test test_util.o test_poly.o test_ntruencrypt.o
