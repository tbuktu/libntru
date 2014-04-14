CC?=gcc
CFLAGS=-g -Wall -Wextra -Wno-unused-parameter -O2
LDFLAGS=-lrt
SRCDIR=src
TESTDIR=tests
LIB_OBJS=bitstring.o encparams.o hash.o idxgen.o key.o mgf.o ntru.o poly.o rand.o sha1.o sha2.o
TEST_OBJS=test_bitstring.o test_hash.o test_idxgen.o test_key.o test_ntru.o test.o test_poly.o test_util.o

LIB_OBJS_PATHS=$(patsubst %,$(SRCDIR)/%,$(LIB_OBJS))
TEST_OBJS_PATHS=$(patsubst %,$(TESTDIR)/%,$(TEST_OBJS))

.PHONY: lib
lib: $(LIB_OBJS_PATHS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,libntru.so -o libntru.so $(LIB_OBJS_PATHS) $(LDFLAGS)

test: lib $(TEST_OBJS_PATHS)
	$(CC) $(CFLAGS) -o test $(TEST_OBJS_PATHS) -L. -lntru -lm
	LD_LIBRARY_PATH=. ./test

bench: lib $(SRCDIR)/bench.o
	$(CC) $(CFLAGS) -o bench $(SRCDIR)/bench.o -L. -lntru

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -fPIC $< -o $@

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) -fPIC -I$(SRCDIR) -c $< -o $@

.PHONY: clean
clean:
	@# also clean files generated on other OSes
	rm -f $(SRCDIR)/*.o $(TESTDIR)/*.o libntru.so libntru.dylib libntru.dll test test.exe bench bench.exe
