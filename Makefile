CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lcrypto
SRC=src

# Use -install_name on Mac OS, -soname everywhere else
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	SONAME=-install_name
else
	SONAME=-soname
endif

lib: ntruencrypt.o poly.o hash.o idxgen.o bitstring.o mgf.o key.o encparams.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,$(SONAME),libntru.so -o libntru.so \
	ntruencrypt.o poly.o hash.o bitstring.o idxgen.o mgf.o key.o encparams.o

test: lib test_util.o test_poly.o test_ntruencrypt.o test_idxgen.o test_key.o
	$(CC) $(CFLAGS) -o test -L. -lntru $(SRC)/test.c $(SRC)/test_util.c \
	$(SRC)/test_poly.c $(SRC)/test_ntruencrypt.c $(SRC)/test_idxgen.c \
	$(SRC)/test_bitstring.c $(SRC)/test_key.c
	LD_LIBRARY_PATH=. ./test

%.c %.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC $(SRC)/$*.c -o $@

clean:
	rm -f ntruencrypt.o poly.o libntru.so test test_util.o test_poly.o \
	test_ntruencrypt.o hash.o idxgen.o mgf.o test_idxgen.o bitstring.o \
	test_bitstring.o key.o test_key.o encparams.o
