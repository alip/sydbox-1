/*
 * sydbox/strtable.h
 *
 * String tables
 *
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
 */

#ifndef STRTABLE_H
#define STRTABLE_H 1

#include <errno.h>
#include <sys/socket.h>
#include "util.h"

static const char *const address_family_table[] = {
#ifdef AF_UNSPEC
	[AF_UNSPEC] = "AF_UNSPEC",
#endif
#if defined(AF_LOCAL)
	[AF_LOCAL] = "AF_LOCAL",
#elif defined(AF_UNIX)
	[AF_UNIX] = "AF_UNIX",
#elif defined(AF_FILE)
	[AF_FILE] = "AF_FILE",
#endif
#ifdef AF_INET
	[AF_INET] = "AF_INET",
#endif
#ifdef AF_AX25
	[AF_AX25] = "AF_AX25",
#endif
#ifdef AF_IPX
	[AF_IPX] = "AF_IPX",
#endif
#ifdef AF_APPLETALK
	[AF_APPLETALK] = "AF_APPLETALK",
#endif
#ifdef AF_NETROM
	[AF_NETROM] = "AF_NETROM",
#endif
#ifdef AF_BRIDGE
	[AF_BRIDGE] = "AF_BRIDGE",
#endif
#ifdef AF_ATMPVC
	[AF_ATMPVC] = "AF_ATMPVC",
#endif
#ifdef AF_X25
	[AF_X25] = "AF_X25",
#endif
#ifdef AF_INET6
	[AF_INET6] = "AF_INET6",
#endif
#ifdef AF_ROSE
	[AF_ROSE] = "AF_ROSE",
#endif
#ifdef AF_DECnet
	[AF_DECnet] = "AF_DECnet",
#endif
#ifdef AF_NETBEUI
	[AF_NETBEUI] = "AF_NETBEUI",
#endif
#ifdef AF_SECURITY
	[AF_SECURITY] = "AF_SECURITY",
#endif
#ifdef AF_KEY
	[AF_KEY] = "AF_KEY",
#endif
#if defined(AF_NETLINK)
	[AF_NETLINK] = "AF_NETLINK",
#elif defined(AF_ROUTE)
	[AF_ROUTE] = "AF_ROUTE",
#endif
#ifdef AF_PACKET
	[AF_PACKET] = "AF_PACKET",
#endif
#ifdef AF_ASH
	[AF_ASH] = "AF_ASH",
#endif
#ifdef AF_ECONET
	[AF_ECONET] = "AF_ECONET",
#endif
#ifdef AF_ATMSVC
	[AF_ATMSVC] = "AF_ATMSVC",
#endif
#ifdef AF_RDS
	[AF_RDS] = "AF_RDS",
#endif
#ifdef AF_SNA
	[AF_SNA] = "AF_SNA",
#endif
#ifdef AF_IRDA
	[AF_IRDA] = "AF_IRDA",
#endif
#ifdef AF_PPPOX
	[AF_PPPOX] = "AF_PPPOX",
#endif
#ifdef AF_WANPIPE
	[AF_WANPIPE] = "AF_WANPIPE",
#endif
#ifdef AF_LLC
	[AF_LLC] = "AF_LLC",
#endif
#ifdef AF_CAN
	[AF_CAN] = "AF_CAN",
#endif
#ifdef AF_TIPC
	[AF_TIPC] = "AF_TIPC",
#endif
#ifdef AF_BLUETOOTH
	[AF_BLUETOOTH] = "AF_BLUETOOTH",
#endif
#ifdef AF_IUCV
	[AF_IUCV] = "AF_IUCV",
#endif
#ifdef AF_RXRPC
	[AF_RXRPC] = "AF_RXRPC",
#endif
#ifdef AF_ISDN
	[AF_ISDN] = "AF_ISDN",
#endif
#ifdef AF_PHONET
	[AF_PHONET] = "AF_PHONET",
#endif
#ifdef AF_IEEE802154
	[AF_IEEE802154] = "AF_IEEE802154",
#endif
};
DEFINE_STRING_TABLE_LOOKUP(address_family, int)

static const char *const errno_table[] = {
	[0] = "ERRNO_0",
	[EPERM] = "EPERM",
	[ENOENT] = "ENOENT",
	[ESRCH] = "ESRCH",
	[EINTR] = "EINTR",
	[EIO] = "EIO",
	[ENXIO] = "ENXIO",
	[E2BIG] = "E2BIG",
	[ENOEXEC] = "ENOEXEC",
	[EBADF] = "EBADF",
	[ECHILD] = "ECHILD",
	[EAGAIN] = "EAGAIN",
	[ENOMEM] = "ENOMEM",
	[EACCES] = "EACCES",
	[EFAULT] = "EFAULT",
	[ENOTBLK] = "ENOTBLK",
	[EBUSY] = "EBUSY",
	[EEXIST] = "EEXIST",
	[EXDEV] = "EXDEV",
	[ENODEV] = "ENODEV",
	[ENOTDIR] = "ENOTDIR",
	[EISDIR] = "EISDIR",
	[EINVAL] = "EINVAL",
	[ENFILE] = "ENFILE",
	[EMFILE] = "EMFILE",
	[ENOTTY] = "ENOTTY",
	[ETXTBSY] = "ETXTBSY",
	[EFBIG] = "EFBIG",
	[ENOSPC] = "ENOSPC",
	[ESPIPE] = "ESPIPE",
	[EROFS] = "EROFS",
	[EMLINK] = "EMLINK",
	[EPIPE] = "EPIPE",
	[EDOM] = "EDOM",
	[ERANGE] = "ERANGE",
#ifdef EDEADLK
	[EDEADLK] = "EDEADLK",
#endif
#ifdef ENAMETOOLONG
	[ENAMETOOLONG] = "ENAMETOOLONG",
#endif
#ifdef ENOLCK
	[ENOLCK] = "ENOLCK",
#endif
#ifdef ENOSYS
	[ENOSYS] = "ENOSYS",
#endif
#ifdef ENOTEMPTY
	[ENOTEMPTY] = "ENOTEMPTY",
#endif
#ifdef ELOOP
	[ELOOP] = "ELOOP",
#endif
/*
#ifdef EWOULDBLOCK
	[EWOULDBLOCK] = "EWOULDBLOCK",
#endif
*/
#ifdef ENOMSG
	[ENOMSG] = "ENOMSG",
#endif
#ifdef EIDRM
	[EIDRM] = "EIDRM",
#endif
#ifdef ECHRNG
	[ECHRNG] = "ECHRNG",
#endif
#ifdef EL2NSYNC
	[EL2NSYNC] = "EL2NSYNC",
#endif
#ifdef EL3HLT
	[EL3HLT] = "EL3HLT",
#endif
#ifdef EL3RST
	[EL3RST] = "EL3RST",
#endif
#ifdef ELNRNG
	[ELNRNG] = "ELNRNG",
#endif
#ifdef EUNATCH
	[EUNATCH] = "EUNATCH",
#endif
#ifdef ENOCSI
	[ENOCSI] = "ENOCSI",
#endif
#ifdef EL2HLT
	[EL2HLT] = "EL2HLT",
#endif
#ifdef EBADE
	[EBADE] = "EBADE",
#endif
#ifdef EBADR
	[EBADR] = "EBADR",
#endif
#ifdef EXFULL
	[EXFULL] = "EXFULL",
#endif
#ifdef ENOANO
	[ENOANO] = "ENOANO",
#endif
#ifdef EBADRQC
	[EBADRQC] = "EBADRQC",
#endif
#ifdef EBADSLT
	[EBADSLT] = "EBADSLT",
#endif
/*
#ifdef EDEADLOCK
	[EDEADLOCK] = "EDEADLOCK",
#endif
*/
#ifdef EBFONT
	[EBFONT] = "EBFONT",
#endif
#ifdef ENOSTR
	[ENOSTR] = "ENOSTR",
#endif
#ifdef ENODATA
	[ENODATA] = "ENODATA",
#endif
#ifdef ETIME
	[ETIME] = "ETIME",
#endif
#ifdef ENOSR
	[ENOSR] = "ENOSR",
#endif
#ifdef ENONET
	[ENONET] = "ENONET",
#endif
#ifdef ENOPKG
	[ENOPKG] = "ENOPKG",
#endif
#ifdef EREMOTE
	[EREMOTE] = "EREMOTE",
#endif
#ifdef ENOLINK
	[ENOLINK] = "ENOLINK",
#endif
#ifdef EADV
	[EADV] = "EADV",
#endif
#ifdef ESRMNT
	[ESRMNT] = "ESRMNT",
#endif
#ifdef ECOMM
	[ECOMM] = "ECOMM",
#endif
#ifdef EPROTO
	[EPROTO] = "EPROTO",
#endif
#ifdef EMULTIHOP
	[EMULTIHOP] = "EMULTIHOP",
#endif
#ifdef EDOTDOT
	[EDOTDOT] = "EDOTDOT",
#endif
#ifdef EBADMSG
	[EBADMSG] = "EBADMSG",
#endif
#ifdef EOVERFLOW
	[EOVERFLOW] = "EOVERFLOW",
#endif
#ifdef ENOTUNIQ
	[ENOTUNIQ] = "ENOTUNIQ",
#endif
#ifdef EBADFD
	[EBADFD] = "EBADFD",
#endif
#ifdef EREMCHG
	[EREMCHG] = "EREMCHG",
#endif
#ifdef ELIBACC
	[ELIBACC] = "ELIBACC",
#endif
#ifdef ELIBBAD
	[ELIBBAD] = "ELIBBAD",
#endif
#ifdef ELIBSCN
	[ELIBSCN] = "ELIBSCN",
#endif
#ifdef ELIBMAX
	[ELIBMAX] = "ELIBMAX",
#endif
#ifdef ELIBEXEC
	[ELIBEXEC] = "ELIBEXEC",
#endif
#ifdef EILSEQ
	[EILSEQ] = "EILSEQ",
#endif
#ifdef ERESTART
	[ERESTART] = "ERESTART",
#endif
#ifdef ESTRPIPE
	[ESTRPIPE] = "ESTRPIPE",
#endif
#ifdef EUSERS
	[EUSERS] = "EUSERS",
#endif
#ifdef ENOTSOCK
	[ENOTSOCK] = "ENOTSOCK",
#endif
#ifdef EDESTADDRREQ
	[EDESTADDRREQ] = "EDESTADDRREQ",
#endif
#ifdef EMSGSIZE
	[EMSGSIZE] = "EMSGSIZE",
#endif
#ifdef EPROTOTYPE
	[EPROTOTYPE] = "EPROTOTYPE",
#endif
#ifdef ENOPROTOOPT
	[ENOPROTOOPT] = "ENOPROTOOPT",
#endif
#ifdef EPROTONOSUPPORT
	[EPROTONOSUPPORT] = "EPROTONOSUPPORT",
#endif
#ifdef ESOCKTNOSUPPORT
	[ESOCKTNOSUPPORT] = "ESOCKTNOSUPPORT",
#endif
#ifdef EOPNOTSUPP
	[EOPNOTSUPP] = "EOPNOTSUPP",
#endif
#ifdef EPFNOSUPPORT
	[EPFNOSUPPORT] = "EPFNOSUPPORT",
#endif
#ifdef EAFNOSUPPORT
	[EAFNOSUPPORT] = "EAFNOSUPPORT",
#endif
#ifdef EADDRINUSE
	[EADDRINUSE] = "EADDRINUSE",
#endif
#ifdef EADDRNOTAVAIL
	[EADDRNOTAVAIL] = "EADDRNOTAVAIL",
#endif
#ifdef ENETDOWN
	[ENETDOWN] = "ENETDOWN",
#endif
#ifdef ENETUNREACH
	[ENETUNREACH] = "ENETUNREACH",
#endif
#ifdef ENETRESET
	[ENETRESET] = "ENETRESET",
#endif
#ifdef ECONNABORTED
	[ECONNABORTED] = "ECONNABORTED",
#endif
#ifdef ECONNRESET
	[ECONNRESET] = "ECONNRESET",
#endif
#ifdef ENOBUFS
	[ENOBUFS] = "ENOBUFS",
#endif
#ifdef EISCONN
	[EISCONN] = "EISCONN",
#endif
#ifdef ENOTCONN
	[ENOTCONN] = "ENOTCONN",
#endif
#ifdef ESHUTDOWN
	[ESHUTDOWN] = "ESHUTDOWN",
#endif
#ifdef ETOOMANYREFS
	[ETOOMANYREFS] = "ETOOMANYREFS",
#endif
#ifdef ETIMEDOUT
	[ETIMEDOUT] = "ETIMEDOUT",
#endif
#ifdef ECONNREFUSED
	[ECONNREFUSED] = "ECONNREFUSED",
#endif
#ifdef EHOSTDOWN
	[EHOSTDOWN] = "EHOSTDOWN",
#endif
#ifdef EHOSTUNREACH
	[EHOSTUNREACH] = "EHOSTUNREACH",
#endif
#ifdef EALREADY
	[EALREADY] = "EALREADY",
#endif
#ifdef EINPROGRESS
	[EINPROGRESS] = "EINPROGRESS",
#endif
#ifdef ESTALE
	[ESTALE] = "ESTALE",
#endif
#ifdef EUCLEAN
	[EUCLEAN] = "EUCLEAN",
#endif
#ifdef ENOTNAM
	[ENOTNAM] = "ENOTNAM",
#endif
#ifdef ENAVAIL
	[ENAVAIL] = "ENAVAIL",
#endif
#ifdef EISNAM
	[EISNAM] = "EISNAM",
#endif
#ifdef EREMOTEIO
	[EREMOTEIO] = "EREMOTEIO",
#endif
#ifdef EDQUOT
	[EDQUOT] = "EDQUOT",
#endif
#ifdef ENOMEDIUM
	[ENOMEDIUM] = "ENOMEDIUM",
#endif
#ifdef EMEDIUMTYPE
	[EMEDIUMTYPE] = "EMEDIUMTYPE",
#endif
#ifdef ECANCELED
	[ECANCELED] = "ECANCELED",
#endif
#ifdef ENOKEY
	[ENOKEY] = "ENOKEY",
#endif
#ifdef EKEYEXPIRED
	[EKEYEXPIRED] = "EKEYEXPIRED",
#endif
#ifdef EKEYREVOKED
	[EKEYREVOKED] = "EKEYREVOKED",
#endif
#ifdef EKEYREJECTED
	[EKEYREJECTED] = "EKEYREJECTED",
#endif
#ifdef EOWNERDEAD
	[EOWNERDEAD] = "EOWNERDEAD",
#endif
#ifdef ENOTRECOVERABLE
	[ENOTRECOVERABLE] = "ENOTRECOVERABLE",
#endif
#ifdef ERFKILL
	[ERFKILL] = "ERFKILL",
#endif
};
DEFINE_STRING_TABLE_LOOKUP(errno, int)

#endif /* !STRTABLE_H */
