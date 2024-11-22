# Location of apxs command:
#APXS=apxs2
APXS=apxs

TAR= README INSTALL NOTICE CHANGES CONTRIBUTORS LICENSE \
	mod_authz_unixgroup.c Makefile Makefile.win

.DEFAULT_GOAL:= build
.PHONY: install build clean tar

install: mod_authz_unixgroup.la
	$(APXS) -i -a mod_authz_unixgroup.la

build: mod_authz_unixgroup.la

mod_authz_unixgroup.la: mod_authz_unixgroup.c
	$(APXS) -c mod_authz_unixgroup.c

clean:
	rm -rf mod_authz_unixgroup.so mod_authz_unixgroup.o \
	    mod_authz_unixgroup.la mod_authz_unixgroup.slo \
	    mod_authz_unixgroup.lo .libs
	-ls -a .*.swp

tar: mod_authz_unixgroup.tar

mod_authz_unixgroup.tar: $(TAR)
	tar cvf mod_authz_unixgroup.tar $(TAR)
