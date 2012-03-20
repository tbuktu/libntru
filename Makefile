CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lcrypto
SRC=src
OBJS=ntruencrypt.o poly.o hash.o idxgen.o bitstring.o mgf.o key.o encparams.o
TEST_OBJS=test.o test_util.o test_ntruencrypt.o test_poly.o test_idxgen.o test_bitstring.o test_key.o

# Use -install_name on Mac OS, -soname everywhere else
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	SONAME=-install_name
else
	SONAME=-soname
endif

lib: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,$(SONAME),libntru.so -o libntru.so $(OBJS)

test: lib $(TEST_OBJS)
	$(CC) $(CFLAGS) -o test -L. -lntru $(TEST_OBJS)
	LD_LIBRARY_PATH=. ./test

%.c %.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC $(SRC)/$*.c -o $@

clean:
	rm -f $(OBJS) $(TEST_OBJS) libntru.so test
