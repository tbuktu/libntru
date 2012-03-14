CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lcrypto
SRC=src

lib: ntruencrypt.o poly.o hash.o idxgen.o bitstring.o mgf.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,libntru.so -o libntru.so \
	ntruencrypt.o poly.o hash.o bitstring.o idxgen.o mgf.o

test: lib test_util.o test_poly.o test_ntruencrypt.o test_idxgen.o
	$(CC) $(CFLAGS) -o test -L. -lntru $(SRC)/test.c $(SRC)/test_util.c \
	$(SRC)/test_poly.c $(SRC)/test_ntruencrypt.c $(SRC)/test_idxgen.c \
	$(SRC)/test_bitstring.c
	LD_LIBRARY_PATH=. ./test

%.c %.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC $(SRC)/$*.c -o $@

clean:
	rm -f ntruencrypt.o poly.o libntru.so test test_util.o test_poly.o \
	test_ntruencrypt.o hash.o idxgen.o mgf.o test_idxgen.o bitstring.o \
	test_bitstring.o
