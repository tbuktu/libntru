CC=gcc
CFLAGS=-g -Wall
SRC=src
OBJS=ntru.o poly.o hash.o idxgen.o bitstring.o mgf.o key.o encparams.o sha2.o sha2big.o
TEST_OBJS=test.o test_util.o test_ntru.o test_poly.o test_idxgen.o test_bitstring.o test_key.o

# Use -install_name on Mac OS, -soname everywhere else
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	SONAME=-install_name
else
	SONAME=-soname
endif

lib: $(OBJS)
	$(CC) $(CFLAGS) -shared -Wl,$(SONAME),libntru.so -o libntru.so $(OBJS) $(LDFLAGS)

test: lib $(TEST_OBJS)
	$(CC) $(CFLAGS) -o test.out $(TEST_OBJS) -L. -lntru
	LD_LIBRARY_PATH=. ./test.out

%.c %.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC $(SRC)/$*.c -o $@

clean:
	rm -f $(OBJS) $(TEST_OBJS) libntru.so test.out
