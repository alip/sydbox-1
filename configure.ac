dnl Program, version
AC_PREREQ(2.59)

AC_INIT([pandora], [1], [alip@exherbo.org] [pandora])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip std-options foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Git revision
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z "${GITHEAD}" ; then
		GITHEAD=`git rev-parse HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD="${GITHEAD}-dirty"
	fi
	if test -n "${GITHEAD}" ; then
		GITHEAD="-${GITHEAD}"
	fi
else
	GITHEAD=
fi
AC_MSG_CHECKING([for git head])
AC_ARG_WITH([git-head],
	AS_HELP_STRING([--with-git-head], [Specify Git head]),
	GITHEAD=`eval echo $withval`,
	GITHEAD=`eval echo $GITHEAD`)
AC_MSG_RESULT([$GITHEAD])
AC_SUBST([GITHEAD])

PANDORA_CFLAGS=

dnl toolchain checks
AC_PROG_CC_C99
if test x"$ac_cv_prog_cc_c99" = x"no"; then
	AC_MSG_ERROR([pandora requires a C compiler that supports ISO C99!])
fi
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_SED

dnl check for sizes
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int16_t])
AC_CHECK_SIZEOF([uint16_t])
AC_CHECK_SIZEOF([int32_t])
AC_CHECK_SIZEOF([uint32_t])
AC_CHECK_SIZEOF([int64_t])
AC_CHECK_SIZEOF([off_t])
AC_CHECK_SIZEOF([off64_t])

dnl check for headers
AC_CHECK_HEADER([sys/queue.h], [], AC_MSG_ERROR([I need sys/queue.h]))
AC_CHECK_HEADER([sys/socket.h], [], AC_MSG_ERROR([I need sys/socket.h]))
AC_CHECK_HEADER([ctype.h], [], AC_MSG_ERROR([I need ctype.h]))
AC_CHECK_HEADER([arpa/inet.h], [], AC_MSG_ERROR([I need arpa/inet.h]))
AC_CHECK_HEADER([netdb.h], [], AC_MSG_ERROR([I need netdb.h]))

dnl check for functions
AC_CHECK_FUNCS([asprintf], [], [AC_MSG_ERROR([I need asprintf])])
AC_CHECK_FUNCS([dprintf],  [], [AC_MSG_ERROR([I need dprintf])])
AC_CHECK_FUNCS([vdprintf], [], [AC_MSG_ERROR([I need vdprintf])])
AC_CHECK_FUNCS([isdigit], [], [AC_MSG_ERROR([I need isdigit])])
AC_CHECK_FUNCS([ntohs], [], [AC_MSG_ERROR([I need ntohs])])
AC_CHECK_FUNCS([getservbyname], [], [AC_MSG_ERROR([I need getservbyname])])

dnl check for large file support
AC_SYS_LARGEFILE

dnl check for libraries
PINKTRACE_REQUIRED=0.2.0

PKG_PROG_PKG_CONFIG([0.20.0])
PKG_CHECK_MODULES([pinktrace], [pinktrace >= $PINKTRACE_REQUIRED],,
				  AC_MSG_ERROR([pandora requires pinktrace-$PINKTRACE_REQUIRED or newer]))
PKG_CHECK_MODULES([pinktrace_easy], [pinktrace_easy >= $PINKTRACE_REQUIRED],,
				  AC_MSG_ERROR([pandora requires pinktrace_easy-$PINKTRACE_REQUIRED]))

dnl check for supported OS of pinktrace
AC_MSG_CHECKING([for supported OS of pinktrace])
old_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#ifndef PINKTRACE_LINUX
#error nope
#endif
])],
	[AC_MSG_RESULT([ok])],
	[AC_MSG_ERROR([pandora only supports Linux])])
CPPFLAGS="${old_CPPFLAGS}"
dnl }}}

dnl {{{ Check for supported bitness count of pinktrace
AC_MSG_CHECKING([for supported bitness count of pinktrace])
old_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#if PINKTRACE_BITNESS_COUNT_SUPPORTED < 2
#error nope
#endif
])],
	[pinktrace_bitness_count_supported=2],
	[pinktrace_bitness_count_supported=1])
CPPFLAGS="${old_CPPFLAGS}"
AC_MSG_RESULT([$pinktrace_bitness_count_supported])
AM_CONDITIONAL(BITNESS_TWO, test x"$pinktrace_bitness_count_supported" = x"2")

dnl check for IPV6 support
AC_ARG_ENABLE([ipv6],
			  [AS_HELP_STRING([--enable-ipv6],
							  [enable IPV6 support])],
			  WANT_IPV6="$enableval",
			  WANT_IPV6="no")
if test x"$WANT_IPV6" = x"yes" ; then
	AC_MSG_CHECKING([whether pinktrace was compiled with IPV6 support])
	old_CPPFLAGS="${CPPFLAGS}"
	CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
	AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#if !PINKTRACE_HAVE_IPV6
#error nope
#endif
	])],
		[pinktrace_have_ipv6=yes],
		[pinktrace_have_ipv6=no])
	CPPFLAGS="${old_CPPFLAGS}"
	AC_MSG_RESULT([$pinktrace_have_ipv6])
	if test x"$pinktrace_have_ipv6" = x"no" ; then
		AC_MSG_ERROR([--enable-ipv6 requires pinktrace IPV6 support])
	fi
	AC_DEFINE([PANDORA_HAVE_IPV6], 1, [Define for IPV6 support])
else
	AC_DEFINE([PANDORA_HAVE_IPV6], 0, [Define for IPV6 support])
fi
AM_CONDITIONAL(WANT_IPV6, test x"$WANT_IPV6" = x"yes")

dnl Extra CFLAGS
WANTED_CFLAGS="-pedantic -W -Wall -Wextra"
for flag in $WANTED_CFLAGS ; do
	AX_CHECK_COMPILER_FLAGS([$flag], [PANDORA_CFLAGS="$PANDORA_CFLAGS $flag"],)
done
AC_SUBST([PANDORA_CFLAGS])

dnl Check for xsltproc
AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL([HAVE_XSLTPROC], test x"$XSLTPROC" != x"")

dnl Output
AC_CONFIG_FILES([
		 Makefile
		 src/Makefile
		 tests/Makefile
		 data/Makefile
])
AC_OUTPUT
