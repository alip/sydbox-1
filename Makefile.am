ACLOCAL_AMFLAGS= -I m4 ${ACLOCAL_FLAGS}
AUTOMAKE_OPTIONS= dist-bzip2 no-dist-gzip std-options foreign
AM_MAKEFLAGS= --no-print-directory

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
	       README.mkd \
	       LICENSE.BSD3 \
	       LICENSE.GPL3

DISTCHECK_CONFIGURE_FLAGS= \
			   --enable-doxygen \
			   --enable-ipv6

.PHONY: doxygen
doxygen: all
	$(MAKE) -C doc $@

.PHONY: upload
upload:
	$(MAKE) -C data upload
	$(MAKE) -C man upload

SUBDIRS= pinktrace src data doc man pkg-config tests .
