ifeq ($(OS), Windows_NT)
    include Makefile.win
else ifeq ($(shell uname), Darwin)
    include Makefile.osx
else ifeq ($(shell uname), OS/2)
    include Makefile.os2
else ifeq ($(shell uname), FreeBSD)
    include Makefile.bsd
else ifeq ($(shell uname), OpenBSD)
    include Makefile.bsd
else
    include Makefile.linux
endif
