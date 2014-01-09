dnl Program, version
AC_PREREQ(2.59)

dnl Versioning
dnl major: User interface changes (magic commands, configuration format)
dnl minor: Major changes without UI breakage
dnl micro: Every other change increases micro version
dnl suffix: For prerelease, alpha, beta versions
m4_define([sydbox_version_major],  [1])
m4_define([sydbox_version_minor],  [0])
m4_define([sydbox_version_micro],  [0])
m4_define([sydbox_version_suffix], [_beta])
m4_define([sydbox_version_full],   [sydbox_version_major.sydbox_version_minor.sydbox_version_micro[]sydbox_version_suffix])
m4_define([sydbox_version],        [sydbox_version_full])

m4_define([sydbox_api_version],    [sydbox_version_major])
m4_define([sydbox_fname_ext],      [syd-])

AC_INIT([sydbox], [sydbox_version], [alip@exherbo.org], [sydbox])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/sydbox.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip std-options subdir-objects foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Git revision
GITHEAD=
GITVERSION=
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z "${GITHEAD}" ; then
		GITHEAD=`git rev-parse --short HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD="${GITHEAD}-dirty"
	fi
fi
AC_MSG_CHECKING([for git head])
AC_ARG_WITH([git-head],
	AS_HELP_STRING([--with-git-head], [Specify Git head]),
	GITHEAD=`eval echo $withval`,
	GITHEAD=`eval echo $GITHEAD`)
AC_MSG_RESULT([$GITHEAD])
AC_SUBST([GITHEAD])

if test -n "${GITHEAD}" ; then
	GITVERSION="-${GITHEAD}"
fi
AC_SUBST([GITVERSION])

SYDBOX_API_VERSION=sydbox_api_version
SYDBOX_FNAME_EXT="sydbox_fname_ext"
AC_DEFINE_UNQUOTED([SYDBOX_API_VERSION], [$SYDBOX_API_VERSION], [Sydbox magic API version])
AC_SUBST([SYDBOX_API_VERSION])
AC_DEFINE_UNQUOTED([SYDBOX_FNAME_EXT], ["$SYDBOX_FNAME_EXT"], [Sydbox filename extension])
AC_SUBST([SYDBOX_FNAME_EXT])

dnl remove the check for c++ and fortran compiler
m4_defun([_LT_AC_LANG_CXX_CONFIG], [:])
m4_defun([_LT_AC_LANG_F77_CONFIG], [:])

dnl toolchain checks
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99
if test x"$ac_cv_prog_cc_c99" = x"no"; then
	AC_MSG_ERROR([sydbox requires a C compiler that supports ISO C99!])
fi
AC_PROG_LD
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_SED
LT_INIT

AM_CONDITIONAL([HAVE_GNU_CC], [test x"$GCC" = x"yes"])
AM_CONDITIONAL([HAVE_GNU_LD], [test x"$with_gnu_ld" = x"yes"])

dnl check for supported operating system
AC_CANONICAL_HOST
AC_MSG_CHECKING([for supported operating system])
case "$host_os" in
linux*)
	opsys="linux"
	AC_MSG_RESULT([$host_os])
	AC_MSG_CHECKING([for supported kernel])
	kernel_version=`uname -r | cut -d'-' -f1`
	case "$kernel_version" in
	3.*|2.6*)
		AC_MSG_RESULT([$kernel_version])
		;;
	2.5*)
		kernel_minor_version=`echo $kernel_version | cut -d'.' -f3`
		if test "$kernel_minor_version" -lt 46; then
			AC_MSG_RESULT([NO!])
			AC_MSG_ERROR([Linux kernel version $kernel_version is not supported by sydbox])
		fi
		AC_MSG_RESULT([$kernel_version])
		;;
	*)
		AC_MSG_RESULT([NO!])
		AC_MSG_ERROR([Linux kernel version $kernel_version is not supported by sydbox])
		;;
	esac
	;;
*)
	AC_MSG_RESULT([NO!])
	AC_MSG_ERROR([Operating system $host_os is not supported by sydbox])
	;;
esac

dnl check for types
AC_TYPE_PID_T
AC_TYPE_SIZE_T

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

dnl check for pinktrace headers
AC_CHECK_HEADER([sys/types.h],  [], AC_MSG_ERROR([I need sys/types.h]))
AC_CHECK_HEADER([sys/wait.h],   [], AC_MSG_ERROR([I need sys/wait.h]))
AC_CHECK_HEADER([sys/ptrace.h], [], AC_MSG_ERROR([I need sys/ptrace.h]))
AC_CHECK_HEADER([sys/socket.h], [], AC_MSG_ERROR([I need sys/socket.h]))
AC_CHECK_HEADER([netinet/in.h], [], AC_MSG_ERROR([I need netinet/in.h]))
AC_CHECK_HEADER([sys/un.h],     [], AC_MSG_ERROR([I need sys/un.h]))
AC_CHECK_HEADERS([sys/reg.h sys/uio.h], [], [])

dnl check for sydbox headers
AC_CHECK_HEADER([limits.h],      [], AC_MSG_ERROR([I need limits.h]))
AC_CHECK_HEADER([signal.h],      [], AC_MSG_ERROR([I need signal.h]))
AC_CHECK_HEADER([sys/utsname.h], [], AC_MSG_ERROR([I need sys/utsname.h]))
AC_CHECK_HEADER([sys/socket.h],  [], AC_MSG_ERROR([I need sys/socket.h]))
AC_CHECK_HEADER([ctype.h],       [], AC_MSG_ERROR([I need ctype.h]))
AC_CHECK_HEADER([arpa/inet.h],   [], AC_MSG_ERROR([I need arpa/inet.h]))
AC_CHECK_HEADER([netdb.h],       [], AC_MSG_ERROR([I need netdb.h]))
AC_CHECK_HEADER([sched.h],       [], AC_MSG_ERROR([I need sched.h]))
AC_CHECK_TYPE([sig_atomic_t],    [], AC_MSG_ERROR([I need sigatomic_t]), [#include <signal.h>])

dnl check for functions
AC_CHECK_FUNCS([asprintf],      [], [AC_MSG_ERROR([I need asprintf])])
AC_CHECK_FUNCS([isdigit],       [], [AC_MSG_ERROR([I need isdigit])])
AC_CHECK_FUNCS([ntohs],         [], [AC_MSG_ERROR([I need ntohs])])
AC_CHECK_FUNCS([getservbyname], [], [AC_MSG_ERROR([I need getservbyname])])
AC_CHECK_FUNCS([pipe2])
AC_CHECK_FUNCS([fchdir])

dnl check for large file support
AC_SYS_LARGEFILE

dnl check for pinktrace
PINKTRACE_REQUIRED=0.9

PKG_PROG_PKG_CONFIG([0.20.0])
PKG_CHECK_MODULES([pinktrace], [pinktrace >= $PINKTRACE_REQUIRED],,
		  AC_MSG_ERROR([sydbox requires pinktrace-$PINKTRACE_REQUIRED or newer]))

dnl check for seccomp support
AC_ARG_ENABLE([seccomp],
	      [AS_HELP_STRING([--enable-seccomp], [enable seccomp support])],
	      [WANT_SECCOMP="$enableval"],
	      [WANT_SECCOMP="no"])
if test x"$WANT_SECCOMP" = x"yes" ; then
	AC_CHECK_HEADER([sys/prctl.h],       [], [AC_MSG_ERROR([I need sys/prctl.h for seccomp support!])])
	AC_CHECK_HEADERS([linux/audit.h linux/seccomp.h])
	m4_define([include_seccomp_headers],
		  [#include <stdint.h>
		   #include <sys/prctl.h>
		   #ifdef HAVE_LINUX_AUDIT_H
		   #include <linux/audit.h>
		   #endif
		   #ifdef HAVE_LINUX_SECCOMP_H
		   #include <linux/seccomp.h>
		   #endif
		  ])
	AC_CHECK_DECL([SECCOMP_MODE_FILTER], [], [AC_MSG_WARN([SECCOMP_MODE_FILTER not declared! (seccomp may not work!)])],
		      [include_seccomp_headers])
	AC_CHECK_DECL([SECCOMP_RET_TRACE],   [], [AC_MSG_WARN([SECCOMP_RET_TRACE not declared! (seccomp may not work!)])],
		      [include_seccomp_headers])
	SYDBOX_HAVE_SECCOMP=1
else
	SYDBOX_HAVE_SECCOMP=0
fi
AC_MSG_CHECKING([for seccomp support])
AC_MSG_RESULT([$WANT_SECCOMP])
AM_CONDITIONAL([WANT_SECCOMP], test x"$WANT_SECCOMP" = x"yes")
AC_DEFINE_UNQUOTED([SYDBOX_HAVE_SECCOMP], [$SYDBOX_HAVE_SECCOMP], [Enable seccomp support])
AC_SUBST([SYDBOX_HAVE_SECCOMP])

dnl extra CFLAGS
SYDBOX_WANTED_CFLAGS="-pedantic -W -Wall -Wextra -Wshadow -Wno-unused-parameter"
for flag in $SYDBOX_WANTED_CFLAGS ; do
	AX_CHECK_COMPILER_FLAGS([$flag], [SYDBOX_CFLAGS="$SYDBOX_CFLAGS $flag"],)
done
AC_SUBST([SYDBOX_CFLAGS])

dnl check for xsltproc
AC_PATH_PROG([XSLTPROC], [xsltproc])
AM_CONDITIONAL([HAVE_XSLTPROC], test x"$XSLTPROC" != x"")

dnl installed tests
AC_MSG_CHECKING([whether tests should be installed])
AC_ARG_ENABLE([installed-tests],
	      AS_HELP_STRING([--enable-installed-tests], [Install tests]),
	      [ENABLE_INSTALLED_TESTS=$enableval],
	      [ENABLE_INSTALLED_TESTS=no])
AC_MSG_RESULT([$ENABLE_INSTALLED_TESTS])
if test x"$ENABLE_INSTALLED_TESTS" = x"yes"; then
	if test x"$HAVE_CHECK" = x"no"; then
		AC_MSG_ERROR([Installed tests require check-$CHECK_REQ or newer])
	fi
fi
AM_CONDITIONAL([ENABLE_INSTALLED_TESTS], test "x$ENABLE_INSTALLED_TESTS" = x"yes")

dnl built sources
GENERATED_FILE=misc/generated-file.txt
AC_SUBST_FILE([GENERATED_FILE])

dnl output
AC_CONFIG_FILES([Makefile
		 src/Makefile
		 tests/Makefile
		 tests/bin/Makefile
		 data/Makefile
		 man/Makefile])
AC_OUTPUT
