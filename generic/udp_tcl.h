/*
 *----------------------------------------------------------------------
 * udp_tcl.h --
 *
 *	Macro and structure definitions
 *
 * Copyright (c) 1999-2003 by Columbia University; all rights reserved
 * Copyright (c) 2003-2005 Pat Thoyts <patthoyts@users.sourceforge.net>
 *
 * Written by Xiaotao Wu
 *----------------------------------------------------------------------
 */

#ifndef UDP_TCL_H
#define UDP_TCL_H

/* Platform unique definitions */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#endif /* _WIN32 */

/* Windows needs to know which symbols to export. */
#ifdef BUILD_udp
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif /* BUILD_udp */

/* Handle TCL 8.6 CONST changes */
#ifndef CONST86
#   if TCL_MAJOR_VERSION > 8
#	define CONST86 const
#   else
#	define CONST86
#   endif
#endif

/*
 * Backwards compatibility for size type change
 */
#if TCL_MAJOR_VERSION < 9 && TCL_MINOR_VERSION < 7
    #include <limits.h>
    #define TCL_SIZE_MAX INT_MAX

    #ifndef Tcl_Size
        typedef int Tcl_Size;
    #endif

    #define TCL_SIZE_MODIFIER ""
    #define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
    #define Tcl_NewSizeIntObj     Tcl_NewIntObj
    #define Tcl_NewSizeIntFromObj Tcl_NewWideIntObj
#endif

#ifdef _WIN32

typedef u_short uint16_t;

typedef struct {
    Tcl_Event         header;     /* Information that is standard for */
    Tcl_Channel       chan;       /* Socket descriptor that is ready  */
} UdpEvent;

typedef struct PacketList {
    char              *message;
    int               actual_size;
    char              r_host[256];
    int               r_port;
    struct PacketList *next;
} PacketList;

#endif /* _WIN32 */

typedef struct UdpState {
    Tcl_Channel       channel;
#ifdef _WIN32
    SOCKET            sock;
#else
    int               sock;
#endif
    char              remotehost[256];	/* send packets to */
    uint16_t          remoteport;
    char              peerhost[256];	/* receive packets from */
    uint16_t          peerport;
    uint16_t          localport;
    int               doread;
#ifdef _WIN32
    HWND              hwnd;
    PacketList        *packets;
    PacketList        *packetsTail;
    int               packetNum;
    struct UdpState   *next;
    Tcl_ThreadId      threadId;		/* for Tcl_ThreadAlert */
#endif
    short	      ss_family;	/* indicator set for ipv4 or ipv6 usage */
    int               multicast;	/* indicator set for multicast add */
    Tcl_Obj          *groupsObj;	/* list of the mcast groups */
} UdpState;


#if defined(_WIN32) && defined(_M_AMD64)
# define SOCKET_PRINTF_FMT "%I64u"
#else
# define SOCKET_PRINTF_FMT "%d"
#endif


EXTERN int Udp_Init(Tcl_Interp *interp);
EXTERN int Udp_SafeInit(Tcl_Interp *interp);

#endif /* _UDP_TCL_H */
