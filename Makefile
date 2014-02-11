CFLAGS=-g -Wall
LDFLAGS=-lrt

# Use -install_name on Mac OS, -soname everywhere else
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	SONAME=-install_name
else
	SONAME=-soname
endif

lib: src/*.o
	$(CC) $(CFLAGS) -shared -Wl,$(SONAME),libntru.so -o libntru.so src/*.o $(LDFLAGS)

test: lib tests/*.o
	$(CC) $(CFLAGS) -o test.out tests/*.o -L./tests -L. -lntru -lm
	LD_LIBRARY_PATH=. ./test.out

src/%.c src/%.o:
	cd src && $(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC $*.c

tests/%.c tests/%.o:
	cd tests && $(CC) $(CFLAGS) $(LDFLAGS) -c -fPIC -I../src $*.c

clean:
	rm -f src/*.o tests/*.o libntru.so test.out
