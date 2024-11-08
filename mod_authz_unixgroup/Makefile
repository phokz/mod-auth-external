# Location of apxs command:
#APXS=apxs2
APXS=apxs

ifneq ($(OS),Windows_NT)
	OS := $(shell uname -s)
endif

TAR= README INSTALL NOTICE CHANGES CONTRIBUTORS LICENSE \
	mod_authz_unixgroup.c Makefile Makefile.win

.DEFAULT_GOAL:= build
.PHONY: install build clean tar

install: mod_authz_unixgroup.la
	$(APXS) -i -a mod_authz_unixgroup.la

build: mod_authz_unixgroup.la

mod_authz_unixgroup.la: mod_authz_unixgroup.c
	$(info REMINDER: This project requires libbsd and associated headers to compile and run. Please install any necessary development packages for your platform if you have not already. macOS users should install libbsd via homebrew.)
ifeq ($(OS),Darwin)
		$(APXS) -I/opt/homebrew/opt/libbsd/include -c mod_authz_unixgroup.c 
else
		$(APXS) -c mod_authz_unixgroup.c -lbsd
endif

clean:
	rm -rf mod_authz_unixgroup.so mod_authz_unixgroup.o \
	    mod_authz_unixgroup.la mod_authz_unixgroup.slo \
	    mod_authz_unixgroup.lo .libs

tar: mod_authz_unixgroup.tar

mod_authz_unixgroup.tar: $(TAR)
	tar cvf mod_authz_unixgroup.tar $(TAR)
