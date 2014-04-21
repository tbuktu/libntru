ifeq ($(shell uname), Darwin)
    include Makefile.osx
else ifeq ($(OS), Windows_NT)
    include Makefile.win
else
    include Makefile.linux
endif
