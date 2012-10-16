ACLOCAL_AMFLAGS= -I m4
AUTOMAKE_OPTIONS= dist-bzip2 no-dist-gzip std-options foreign

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
			   --enable-ipv6

#pinktrace_includedir=$(includedir)/pinktrace-$(PINKTRACE_PC_SLOT)/pinktrace/
#pinktrace_include_HEADERS=
noinst_HEADERS= \
			  include/pinktrace/about.h \
			  include/pinktrace/system.h \
			  include/pinktrace/abi.h \
			  include/pinktrace/compat.h \
			  include/pinktrace/compiler.h \
			  include/pinktrace/event.h \
			  include/pinktrace/read.h \
			  include/pinktrace/regs.h \
			  include/pinktrace/socket.h \
			  include/pinktrace/syscall.h \
			  include/pinktrace/trace.h \
			  include/pinktrace/write.h \
			  include/pinktrace/pink.h

EXTRA_DIST+= \
	     include/pinktrace/about.h.in \
	     include/pinktrace/system.h.in
MAINTAINERCLEANFILES+= \
		       include/pinktrace/about.h \
		       include/pinktrace/system.h
noinst_HEADERS+= \
		include/pinktrace/internal.h

pinktrace_easy_DIST= \
		     include/pinktrace/easy/attach.h \
		     include/pinktrace/easy/call.h \
		     include/pinktrace/easy/callback.h \
		     include/pinktrace/easy/context.h \
		     include/pinktrace/easy/error.h \
		     include/pinktrace/easy/exec.h \
		     include/pinktrace/easy/func.h \
		     include/pinktrace/easy/init.h \
		     include/pinktrace/east/intr.h \
		     include/pinktrace/easy/loop.h \
		     include/pinktrace/easy/process.h \
		     include/pinktrace/easy/step.h \
		     include/pinktrace/easy/pink.h
EXTRA_DIST+= \
	     $(pinktrace_easy_DIST) \
	     include/pinktrace/easy/internal.h
#if WANT_EASY
#pinktrace_easy_includedir=$(includedir)/pinktrace-$(PINKTRACE_PC_SLOT)/pinktrace/easy
#pinktrace_easy_include_HEADERS= $(pinktrace_easy_DIST)
#endif # WANT_EASY

upload:
	make -C data upload
	make -C man upload
.PHONY: upload

SUBDIRS= pinktrace src data man pkg-config tests .
