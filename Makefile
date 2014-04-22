ifeq ($(OS), Windows_NT)
    include Makefile.win
else ifeq ($(shell uname), Darwin)
    include Makefile.osx
else
    include Makefile.linux
endif
