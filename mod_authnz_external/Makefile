# Location of apxs command:
#APXS=apxs2
APXS=apxs

TAR= README INSTALL INSTALL.HARDCODE CHANGES CONTRIBUTORS AUTHENTICATORS UPGRADE TODO \
	mod_authnz_external.c test/* Makefile

version = $(error version is not set)

.DEFAULT_GOAL:= build
.PHONY: install build clean

install: mod_authnz_external.la
	$(APXS) -i -a mod_authnz_external.la

build: mod_authnz_external.la

mod_authnz_external.la: mod_authnz_external.c
	$(APXS) -c mod_authnz_external.c

clean:
	rm -rf mod_authnz_external.so mod_authnz_external.o \
	    mod_authnz_external.la mod_authnz_external.slo \
	    mod_authnz_external.lo .libs
	-ls -a .*.swp

mae.tar: $(TAR)
	tar cvf mae.tar $(TAR)

debian-package-dependencies:
	sudo apt install build-essential fakeroot devscripts apxs apache2-dev

debian-package-version:
	dch -v $(version)

debian-package:
	debuild --rootcmd=sudo --no-tgz-check -us -uc
