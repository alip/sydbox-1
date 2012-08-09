MAINTAINERCLEANFILES= Makefile.in
CLEANFILES= pinktrace.pc
EXTRA_DIST= pinktrace.pc.in pinktrace_easy.pc.in

noinst_DATA=pinktrace.pc
#pkgconfigdir=$(libdir)/pkgconfig
#pkgconfig_DATA=pinktrace.pc

pinktrace.pc: pinktrace.pc.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
	    -e "s,#PINKTRACE_PC_PREFIX#,$(prefix)," \
	    -e "s,#PINKTRACE_PC_LIBDIR#,$(libdir)," \
	    -e "s,#PINKTRACE_PC_INCLUDEDIR#,$(includedir)/pinktrace-$(PINKTRACE_PC_SLOT)," \
	    -e "s,#PINKTRACE_PC_VERSION#,$(PINKTRACE_PC_VERSION)," \
	    -e "s,#PINKTRACE_PC_LIBS#,$(PINKTRACE_PC_LIBS)," \
	    -e "s,#PINKTRACE_PC_CFLAGS#,$(PINKTRACE_PC_CFLAGS)," \
	    < $(srcdir)/pinktrace.pc.in > pinktrace.pc

#if WANT_EASY
CLEANFILES+= pinktrace_easy.pc
noinst_DATA+= pinktrace_easy.pc
#pkgconfig_DATA+= pinktrace_easy.pc

pinktrace_easy.pc: pinktrace_easy.pc.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
	    -e "s,#PINKTRACE_PC_PREFIX#,$(prefix)," \
	    -e "s,#PINKTRACE_PC_LIBDIR#,$(libdir)," \
	    -e "s,#PINKTRACE_PC_INCLUDEDIR#,$(includedir)/pinktrace-$(PINKTRACE_PC_SLOT)," \
	    -e "s,#PINKTRACE_PC_VERSION#,$(PINKTRACE_PC_VERSION)," \
	    -e "s,#PINKTRACE_PC_LIBS#,$(PINKTRACE_PC_LIBS)," \
	    -e "s,#PINKTRACE_EASY_PC_LIBS#,$(PINKTRACE_EASY_PC_LIBS)," \
	    -e "s,#PINKTRACE_PC_CFLAGS#,$(PINKTRACE_PC_CFLAGS)," \
	    < $(srcdir)/pinktrace_easy.pc.in > pinktrace_easy.pc
#endif # WANT_EASY
