AM_MAKEFLAGS= --no-print-directory
ACLOCAL_AMFLAGS= -I m4 ${ACLOCAL_FLAGS}
AUTOMAKE_OPTIONS= dist-bzip2 no-dist-gzip std-options subdir-objects foreign

CLEANFILES= *~
MAINTAINERCLEANFILES= \
		      Makefile.in \
		      configure \
		      aclocal.m4 \
		      config.h \
		      config.h.in \
		      INSTALL

EXTRA_DIST= \
	    autogen.sh

dist_doc_DATA= \
	       COPYRIGHT \
	       README.mkd \
	       man/ptrace-ntpl.txt

DISTCHECK_CONFIGURE_FLAGS= \
			   --enable-seccomp \
			   --enable-debug

TAR_FILE= $(PACKAGE)-$(VERSION).tar.bz2
SHA1_FILE= $(TAR_FILE).sha1sum
GPG_FILE= $(SHA1_FILE).asc

.PHONY: doxygen
doxygen: all
	$(MAKE) -C doc $@

$(SHA1_FILE): dist
	@echo "SHA1 $(TAR_FILE)"
	sha1sum $(TAR_FILE) > $(SHA1_FILE)

$(GPG_FILE): $(SHA1_FILE)
	@echo "SIGN $(SHA1_FILE)"
	gpg --detach-sign --armor $(SHA1_FILE)

.PHONY: upload
upload:
	$(MAKE) -C data upload
	$(MAKE) -C man upload

.PHONY: upload-release
upload-release: upload $(SHA1_FILE) $(GPG_FILE)
	rsync --partial --progress -ave ssh $(TAR_FILE) $(SHA1_FILE) $(GPG_FILE) tchaikovsky.exherbo.org:public_html/sydbox/

.PHONY: jenkins
jenkins:
	misc/jenkins-build.sh

install-data-hook:
	@echo
	@echo "NOTE ABOUT TESTS:"
	@echo
	@echo "sydbox tests have been installed under $(libexecdir)/$(PACKAGE)/t"
	@echo "To run use _one_ of the commands below:"
	@echo
	@echo "make -C $(libexecdir)/$(PACKAGE)/t test"
	@echo "make -C $(libexecdir)/$(PACKAGE)/t prove"
	@echo
	@echo "The second command uses prove(1) to run tests."
	@echo
	@echo "NOTE: the check output logs will be generated in the current directory!"
	@echo "Pass TEST_OUTPUT_DIRECTORY=/path/to/output/dir to the make command above if this is not wanted."
	@echo

SUBDIRS= src data man t .
