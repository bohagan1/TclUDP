/******************************************************************************
 * UDP Extension for Tcl 8.4
 *
 * Copyright (c) 1999-2000 by Columbia University; all rights reserved
 * Copyright (c) 2003-2005 Pat Thoyts <patthoyts@users.sourceforge.net>
 *
 * Written by Xiaotao Wu
 * Last modified: 08/21/2014
 *
 * $Id: udp_tcl.c,v 1.48 2014/08/24 07:17:21 huubeikens Exp $
 ******************************************************************************/

#if defined(_DEBUG) && !defined(DEBUG)
#define DEBUG
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include "tcl.h"
#include "udp_tcl.h"
#include "udpUuid.h"

#ifdef _WIN32
#include <malloc.h>
typedef int socklen_t;
#else /* ! _WIN32 */
#include <net/if.h>
#if defined(HAVE_SYS_FILIO_H)
#include <sys/filio.h>
#endif
#if defined(HAVE_SOCKET_H)
#include <sys/socket.h>
#endif
#if defined(HAVE_SYS_IOCTL_H)
#include <sys/ioctl.h>
#endif
#if !defined(HAVE_SYS_FILIO_H) && !defined(HAVE_SYS_IOCTL_H)
#error "Neither sys/ioctl.h nor sys/filio.h found. We need ioctl()"
#endif
#endif /* _WIN32 */

#if HAVE_FCNTL_H
#  include <fcntl.h>
#endif

/* bug #1240127: May not be found on certain versions of mingw-gcc */
#ifndef IP_TTL
#define IP_TTL 4
#endif

#if defined(_XOPEN_SOURCE_EXTENDED) && defined(__hpux)
/*
 * This won't get defined on HP-UX if _XOPEN_SOURCE_EXTENDED is defined,
 * but we need it and TEA causes this macro to be defined.
 */

struct ip_mreq {
    struct in_addr imr_multiaddr; /* IP multicast address of group */
    struct in_addr imr_interface; /* local IP address of interface */
};

struct ipv6_mreq {
    struct in6_addr ipv6mr_multiaddr; /* IPv6 multicast addr */
    unsigned int    ipv6mr_interface; /* interface index */
};

#endif /* _XOPEN_SOURCE_EXTENDED */

/*
 * This is needed to comply with the strict aliasing rules of GCC, but it also
 * simplifies casting between the different sockaddr types.
 */

typedef union {
    struct sockaddr sa;
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    struct sockaddr_storage sas;
} address;

/* define some Win32isms for Unix */
#ifndef _WIN32
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket close
#define ioctlsocket ioctl
#endif /* _WIN32 */

#ifdef DEBUG
#define UDPTRACE udpTrace
#else
#define UDPTRACE 1 ? ((void)0) : udpTrace
#endif

#ifdef _MSC_VER
#define snprintf _snprintf      /* trust Microsoft to complicate things */
#endif

FILE *dbg;

#define MAXBUFFERSIZE 65535

/*
 * internal functions
 */
static int UdpMulticast(UdpState *statePtr, Tcl_Interp *, const char *, int);

/*
 * Windows specific functions
 */
#ifdef _WIN32

/* FIX ME - these should be part of a thread/package specific structure */
static HANDLE waitForSock;
static HANDLE sockListLock;
static UdpState *sockList;

typedef struct ThreadSpecificData {
    int sourceInit;
} ThreadSpecificData;

static Tcl_ThreadDataKey dataKey;

#endif /* ! _WIN32 */

/*
 * Probably we should provide an equivalent to the C API for TCP.
 *
 * Tcl_Channel Tcl_OpenUdpClient(interp, port, host, myaddr, myport, async);
 * Tcl_Channel Tcl_OpenUdpServer(interp, port, myaddr, proc, clientData);
 * Tcl_Channel Tcl_MakeUdpClientChannel(sock);
 */

/*
 * Options for address configure commands
 */
static const char *cfg_opts[] = {
    "-broadcast", "-family", "-mcastadd", "-mcastdrop", "-mcastgroups", "-mcastif",
    "-mcastloop", "-myport", "-peer", "-remote", "-ttl", NULL};

enum _cfg_opts {
    _opt_broadcast, _opt_family, _opt_mcastadd, _opt_mcastdrop, _opt_mcastgroups,
    _opt_mcastif, _opt_mcastloop, _opt_myport, _opt_peer, _opt_remote, _opt_ttl
};


/*
 * Helper Functions
 */

static void AppendWinCharsToObj(Tcl_Obj *errObj, LPWSTR sMsg, Tcl_Size len) {
    Tcl_DString ds;
    Tcl_DStringInit(&ds);
    Tcl_Char16ToUtfDString(sMsg, len, &ds);
    Tcl_AppendToObj(errObj, Tcl_DStringValue(&ds), Tcl_DStringLength(&ds));
    Tcl_DStringFree(&ds);
}

/*
* -----------------------------------------------------------------------
* ErrorToObj --
* -----------------------------------------------------------------------
*/

static Tcl_Obj * ErrorToObj(const char * prefix) {
    Tcl_Obj *errObj;
#ifdef _WIN32
    LPVOID sMsg;
    DWORD len = 0;

    len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
	| FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL,
	SUBLANG_DEFAULT), (LPWSTR)&sMsg, 0, NULL);
    errObj = Tcl_NewStringObj(prefix, -1);
    Tcl_AppendToObj(errObj, ": ", -1);
#if TCL_UTF_MAX < 4
    Tcl_AppendUnicodeToObj(errObj, (LPWSTR)sMsg, (Tcl_Size) (len - 1));
#else
    AppendWinCharsToObj(errObj, (LPWSTR) sMsg, len-1);
#endif
    LocalFree(sMsg);
#else
    errObj = Tcl_NewStringObj(prefix, -1);
    Tcl_AppendStringsToObj(errObj, ": ", strerror(errno), (char *) NULL);
#endif
    return errObj;
}

/*
 * ----------------------------------------------------------------------
 * udpTrace --
 * ----------------------------------------------------------------------
 */
static void udpTrace(const char *format, ...) {
    va_list args;

#ifdef _WIN32

    static char buffer[1024];
    va_start (args, format);
    _vsnprintf(buffer, 1023, format, args);
    OutputDebugStringA(buffer);

#else /* ! _WIN32 */
    va_start (args, format);
    vfprintf(dbg, format, args);
    fflush(dbg);

#endif /* ! _WIN32 */

    va_end(args);
}

/*
 *---------------------------------------------------------------------------
 *
 * UdpSockGetPort --
 *
 *      Maps from a string, which could be a service name, to a port.
 *      Used by socket creation code to get port numbers and resolve
 *      registered service names to port numbers.
 *
 *      NOTE: this is a copy of TclSockGetPort.
 *
 * Results:
 *      A standard Tcl result.  On success, the port number is returned
 *      in portPtr. On failure, an error message is left in the interp's
 *      result.
 *
 * Side effects:
 *      None.
 *
 *---------------------------------------------------------------------------
*/

int UdpSockGetPort(
     Tcl_Interp *interp, 
     const char *service,	/* Integer or service name */
     const char *proto,		/* "tcp" or "udp", typically */
     int *portPtr)		/* Return port number */
{

    /* Get int or service name */
    if (Tcl_GetInt(NULL, service, portPtr) != TCL_OK) {
	Tcl_DString ds;
	const char *native;
	struct servent *sp;          /* Protocol info for named services */

	/*
	 * Don't bother translating 'proto' to native.
	 */

	native = Tcl_UtfToExternalDString(NULL, service, -1, &ds);
	sp = getservbyname(native, proto);              /* INTL: Native. */
	Tcl_DStringFree(&ds);
	if (sp != NULL) {
	    *portPtr = ntohs((unsigned short) sp->s_port);
		return TCL_OK;
	}
    }

    if (Tcl_GetInt(interp, service, portPtr) != TCL_OK) {
		return TCL_ERROR;
	    }
    if (*portPtr > 0xFFFF) {
	Tcl_AppendResult(interp, "couldn't open socket: port number too high", (char *) NULL);
	    return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpGetService --
 *
 *  Return the service port number in network byte order from either a
 *  string representation of the port number or the service name. If the
 *  service string cannot be converted (ie: a name not present in the
 *  services database) then set a Tcl error.
 * ----------------------------------------------------------------------
 */

static int udpGetService(Tcl_Interp *interp, const char *service, uint16_t *servicePort) {
    int port = 0;
    int r = UdpSockGetPort(interp, service, "udp", &port);

    if (r == TCL_OK) {
	*servicePort = htons((uint16_t)port);
    }
    return r;
}

/*
 * Windows Only Functions
 */

#ifdef _WIN32
/*
 * ----------------------------------------------------------------------
 * UdpEventProc --
 *
 *  Raise an event from the UDP read thread to notify the Tcl interpreter
 *  that something has happened.
 *
 * ----------------------------------------------------------------------
 */
int UdpEventProc(Tcl_Event *evPtr, int flags) {
    UdpEvent *eventPtr = (UdpEvent *) evPtr;
    UdpState *statePtr;

    if (!(flags & TCL_FILE_EVENTS)) {
	return 0;
    }

    statePtr = eventPtr->state;
    statePtr->doread = 1;
    Tcl_NotifyChannel(statePtr->channel, TCL_READABLE);
    return 1;
}

/*
 * ----------------------------------------------------------------------
 * UdpDeleteEvent --
 *
 *  Remove any queued UDP events from the event queue.  Called from
 *  Tcl_DeleteEvents when the channel is closed.  Tests each passed
 *  event, and returns 1 if the event should be deleted, 0 otherwise.
 *
 * ----------------------------------------------------------------------
 */
static int UdpDeleteEvent(Tcl_Event *evPtr, ClientData channel) {
    UdpEvent *eventPtr = (UdpEvent *) evPtr;

    return eventPtr->header.proc == UdpEventProc && eventPtr->chan == (Tcl_Channel)channel;
}

/*
 * ----------------------------------------------------------------------
 * UDP_SetupProc - called in Tcl_SetEventSource to do the setup step
 * ----------------------------------------------------------------------
 */
static void UDP_SetupProc(ClientData data, int flags) {
    UdpState *statePtr;
    Tcl_Time blockTime = { 0, 0 };

    /* UDPTRACE("setupProc\n"); */

    if (!(flags & TCL_FILE_EVENTS)) {
	return;
    }

    WaitForSingleObject(sockListLock, INFINITE);
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
	if (statePtr->packetNum > 0 && statePtr->threadId == Tcl_GetCurrentThread()) {
	    UDPTRACE("UDP_SetupProc\n");
	    Tcl_SetMaxBlockTime(&blockTime);
	    break;
	}
    }
    SetEvent(sockListLock);
}

/*
 * ----------------------------------------------------------------------
 * UDP_CheckProc --
 * ----------------------------------------------------------------------
 */
void UDP_CheckProc(ClientData data, int flags) {
    UdpState *statePtr;
    UdpEvent *evPtr;
    int actual_size;
    socklen_t socksize;
    int buffer_size = MAXBUFFERSIZE;
    char *message;
    address recvaddr;
    PacketList *p;
#ifdef _WIN32
    char hostaddr[256];
    char *portaddr;
    char remoteaddr[256];
    int remoteaddrlen; /* bytes for ANSI strings, WCHARs for Unicode */
#endif /*  _WIN32 */
    Tcl_ThreadId currentThreadId = Tcl_GetCurrentThread();

    UDPTRACE("checkProc\n");

    /* synchronized */
    WaitForSingleObject(sockListLock, INFINITE);

    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
	if (statePtr->threadId != currentThreadId) {
	    continue;
	}

	/* Read the data from socket and put it into statePtr */
	socksize = sizeof(recvaddr);
	memset(&recvaddr, 0, socksize);

	/* reserve one more byte for terminating null byte */
	message = (char *)ckalloc(MAXBUFFERSIZE+1);
	if (message == NULL) {
	    UDPTRACE("ckalloc error\n");
	    exit(1);
	}
	memset(message, 0, MAXBUFFERSIZE+1);

	actual_size = recvfrom(statePtr->sock, message, buffer_size, 0,
		(struct sockaddr *)&recvaddr, &socksize);

	if (actual_size < 0) {
	    UDPTRACE("UDP error - recvfrom %d\n", statePtr->sock);
	    ckfree(message);
	} else {
	    p = (PacketList *)ckalloc(sizeof(struct PacketList));
	    p->message = message;
	    p->actual_size = actual_size;
#ifdef _WIN32
	    /*
	     * In windows, do not use getnameinfo() since this function does
	     * not work correctly in case of multithreaded. Also inet_ntop() is
	     * not available in older windows versions.
	     */
	    memset(hostaddr, 0 , sizeof(hostaddr));
	    memset(remoteaddr, 0, sizeof(remoteaddr));
	    remoteaddrlen = sizeof(remoteaddr);
	    if (WSAAddressToStringA((struct sockaddr *)&recvaddr, socksize, NULL,
		    remoteaddr, &remoteaddrlen) == 0) {
		/*
		 * We now have an address in the format of <ip address>:<port>
		 * Search backwards for the last ':'
		 */
		portaddr = strrchr(remoteaddr,':') + 1;
		strncpy(hostaddr,remoteaddr,strlen(remoteaddr)-strlen(portaddr)-1);
		statePtr->peerport = atoi(portaddr);
		p->r_port = statePtr->peerport;
		strcpy(statePtr->peerhost,hostaddr);
		strcpy(p->r_host,hostaddr);
	    }
#else
	    if (statePtr->ss_family == AF_INET ) {
		    inet_ntop(AF_INET, &recvaddr.sa4.sin_addr, statePtr->peerhost, sizeof(statePtr->peerhost) );
		    inet_ntop(AF_INET, &recvaddr.sa4.sin_addr, p->r_host, sizeof(p->r_host) );
		    p->r_port = ntohs(recvaddr.sa4.sin_port);
		    statePtr->peerport = ntohs(recvaddr.sa4.sin_port);
		} else {
		    inet_ntop(AF_INET6, &recvaddr.sa6.sin6_addr, statePtr->peerhost, sizeof(statePtr->peerhost) );
		    inet_ntop(AF_INET6, &recvaddr.sa6.sin6_addr, p->r_host, sizeof(p->r_host) );
		    p->r_port = ntohs(recvaddr.sa6.sin6_port);
		    statePtr->peerport = ntohs(recvaddr.sa6.sin6_port);
	    }
#endif /*  _WIN32 */

	    p->next = NULL;

	    if (statePtr->packets == NULL) {
		statePtr->packets = p;
		statePtr->packetsTail = p;
	    } else {
		statePtr->packetsTail->next = p;
		statePtr->packetsTail = p;
	    }

	    UDPTRACE("Received %d bytes from %s:%d through %d\n", p->actual_size, p->r_host,
		p->r_port, statePtr->sock);
	    UDPTRACE("%s\n", p->message);
	}

	if (actual_size > 0) {
	    evPtr = (UdpEvent *) ckalloc(sizeof(UdpEvent));
	    evPtr->header.proc = UdpEventProc;
	    evPtr->chan = statePtr->channel;
	    evPtr->state = statePtr;
	    Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
	    UDPTRACE("socket %d has data\n", statePtr->sock);
	}
    }

    SetEvent(sockListLock);
}

/*
 * ----------------------------------------------------------------------
 * UDP_ExitProc - called at thread exit
 * ----------------------------------------------------------------------
 */
void UDP_ExitProc(ClientData clientData) {
    Tcl_DeleteEventSource(UDP_SetupProc, UDP_CheckProc, NULL);
    
    /* Delete threads */
    CloseHandle(waitForSock);
    CloseHandle(sockListLock);
    /* TBD delete thread 
    	socketThread = CreateThread(NULL, 16384, SocketThread, NULL, 0, &id);
    */
}

/*
 * ----------------------------------------------------------------------
 * InitSockets
 * ----------------------------------------------------------------------
 */
static int InitSockets() {
    WSADATA wsaData;

    /* Load the socket DLL and initialize the function table. */
    if (WSAStartup(0x0202, &wsaData)) {
	return 0;
    }
    return 1;
}

/*
 * ----------------------------------------------------------------------
 * ExitSockets
 * ----------------------------------------------------------------------
 */
void ExitSockets(ClientData clientData) {
    WSACleanup();
}

/*
 * ----------------------------------------------------------------------
 * SocketThread
 * ----------------------------------------------------------------------
 */
static DWORD WINAPI SocketThread(LPVOID arg) {
    fd_set readfds; /* variable used for select */
    struct timeval timeout;
    UdpState *statePtr;
    int *packetNums[FD_SETSIZE];
    SOCKET socks[FD_SETSIZE];
    Tcl_ThreadId tids[FD_SETSIZE];
    int found, count, n;

    UDPTRACE("In socket thread\n");

    while (1) {
	FD_ZERO(&readfds);
	timeout.tv_sec  = 0;
	timeout.tv_usec = 50000;

	/* synchronized */
	WaitForSingleObject(sockListLock, INFINITE);

	/* set each socket for select */
	count = 0;
	for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
	    if (statePtr->packetNum > 0) {
		continue;
	    }
	    FD_SET(statePtr->sock, &readfds);
	    socks[count] = statePtr->sock;
	    packetNums[count] = &statePtr->packetNum;
	    tids[count] = statePtr->threadId;
	    if (++count >= FD_SETSIZE) {
		break;
	    }
	    UDPTRACE("SET sock %d\n", statePtr->sock);
	}

	SetEvent(sockListLock);
	if (count == 0) {
	    WaitForSingleObject(waitForSock, INFINITE);
	    continue;
	}

	/* block here */
	UDPTRACE("Wait for select\n");
	found = select(0, &readfds, NULL, NULL, &timeout);
	UDPTRACE("select end\n");

	if (found <= 0) {
	    /* We closed the socket during select or time out */
	    continue;
	}

	UDPTRACE("Packet comes in\n");
	WaitForSingleObject(sockListLock, INFINITE);

	/* How many packets */
	n = 0;
	for (n = 0; n < count; n++) {
	    if (FD_ISSET(socks[n], &readfds)) {
		packetNums[n][0] += 1;
	    } else {
		tids[n] = NULL;
	    }
	}
	SetEvent(sockListLock);

	/* Trigger event checking */
	for (n = 0; n < count; n++) {
	    if (tids[n] != NULL) {
		/* alert the thread to do event checking */
		Tcl_ThreadAlert(tids[n]);
	    }
	}
    }
    return 0;
}

/*
 * ----------------------------------------------------------------------
 * Udp_WinHasSockets --
 * ----------------------------------------------------------------------
 */
int Udp_WinHasSockets(Tcl_Interp *interp) {
    static int initialized = 0; /* 1 if the socket sys has been initialized. */
    static int hasSockets = 0;  /* 1 if the system supports sockets. */
    HANDLE socketThread;
    DWORD id;

    if (!initialized) {
	initialized = 1;

	/* Load the library and initialize the stub table. */
	hasSockets = InitSockets();

	/*
	 * Start the socketThread window and set the thread priority of the
	 * socketThread as highest
	 */

	sockList = NULL;
	waitForSock = CreateEvent(NULL, FALSE, FALSE, NULL);
	sockListLock = CreateEvent(NULL, FALSE, TRUE, NULL);

	socketThread = CreateThread(NULL, 16384, SocketThread, NULL, 0, &id);
	SetThreadPriority(socketThread, THREAD_PRIORITY_HIGHEST);

	UDPTRACE("Initialize socket thread\n");

	if (socketThread == NULL) {
	    UDPTRACE("Failed to create thread\n");
	}
    }
    if (hasSockets) {
	return TCL_OK;
    }
    if (interp != NULL) {
	Tcl_AppendResult(interp, "sockets are not available on this system", (char *) NULL);
    }
    return TCL_ERROR;
}
#endif /* ! _WIN32 */


/*
 * Channel handling procedures
 */


/*
 * ----------------------------------------------------------------------
 * udpClose --
 *  Called from the channel driver code to cleanup and close
 *  the socket.
 *
 * Results:
 *  0 if successful, the value of errno if failed.
 *
 * Side effects:
 *  The socket is closed.
 *
 * ----------------------------------------------------------------------
 */
static int udpClose(ClientData instanceData, Tcl_Interp *interp) {
#ifdef _WIN32
    SOCKET sock;
#else
    int sock;
#endif
    int errorCode = 0;
    Tcl_Size objc;
    Tcl_Obj **objv;
    UdpState *statePtr = (UdpState *) instanceData;
#ifdef _WIN32
    UdpState *tmp, *p;

    WaitForSingleObject(sockListLock, INFINITE);
#endif /* ! _WIN32 */

    sock = statePtr->sock;

#ifdef _WIN32
    /* Delete any queued events for this channel. */
    Tcl_DeleteEvents(UdpDeleteEvent, (ClientData)statePtr->channel);

    /* remove the statePtr from the list */
    for (tmp = p = sockList; p != NULL; tmp = p, p = p->next) {
	if (p->sock == sock) {
	    UDPTRACE("Remove %d from the list\n", p->sock);
	    if (p == sockList) {
		sockList = sockList->next;
	    } else {
		tmp->next = p->next;
	    }
	}
    }
#endif /* ! _WIN32 */

    /*
     * If there are multicast groups added they should be dropped.
     */
    if (statePtr->groupsObj) {
	Tcl_Obj *dupGroupList = Tcl_DuplicateObj(statePtr->groupsObj);
	Tcl_IncrRefCount(dupGroupList);
	Tcl_ListObjGetElements(interp, dupGroupList, &objc, &objv);
	for (Tcl_Size n = 0; n < objc; n++) {
	    if (statePtr->ss_family==AF_INET) {
		UdpMulticast(statePtr, interp, Tcl_GetString(objv[n]), IP_DROP_MEMBERSHIP);
	    } else {
		UdpMulticast(statePtr, interp, Tcl_GetString(objv[n]), IPV6_LEAVE_GROUP);
	    }
	}
	Tcl_DecrRefCount(dupGroupList);
	Tcl_DecrRefCount(statePtr->groupsObj);
    }

    /* No - doing this causes a infinite recursion. Let Tcl handle this.
     *   Tcl_UnregisterChannel(interp, statePtr->channel);
     */
    if (closesocket(sock) < 0) {
	errorCode = errno;
    }
    ckfree((char *) statePtr);
    if (errorCode != 0) {
	static char errBuf[256];

#ifndef _WIN32
	snprintf(errBuf, 255, "udp_close: %d, error: %d\n", sock, errorCode);
#else
	snprintf(errBuf, 255, "udp_close: " SOCKET_PRINTF_FMT ", error: %d\n", sock, GetLastError());
#endif
	UDPTRACE("UDP error - close %d", sock);
    } else {
	UDPTRACE("Close socket %d\n", sock);
    }

#ifdef _WIN32
    SetEvent(sockListLock);
#endif

    return errorCode;
}

/*
 * ----------------------------------------------------------------------
 * udpClose2 --
 *  Called from the channel driver code to cleanup and close
 *  the socket.
 *
 * Results:
 *  0 if successful, the value of errno if failed.
 *
 * Side effects:
 *  The socket is closed.
 *
 * ----------------------------------------------------------------------
 */
static int udpClose2(ClientData instanceData, Tcl_Interp *interp, int flags) {
#ifdef _WIN32
    SOCKET sock;
    int shut_rd = SD_RECEIVE;
    int shut_wr = SD_SEND;
#else
    int sock;
    int shut_rd = SHUT_RD;
    int shut_wr = SHUT_WR;
#endif
    UdpState *statePtr = (UdpState *) instanceData;
    int readError = 0, writeError = 0;

    if ((flags & (TCL_CLOSE_READ|TCL_CLOSE_WRITE)) == 0) {
	return udpClose(instanceData, interp);
    }

    sock = statePtr->sock;
    if (flags & TCL_CLOSE_READ) {
	readError = shutdown(sock, shut_rd);
    }
    if (flags & TCL_CLOSE_WRITE) {
	writeError = shutdown(sock, shut_wr);
    }
    return (readError != 0) ? readError : writeError;
}

/*
 * ----------------------------------------------------------------------
 * udpWatch --
 * ----------------------------------------------------------------------
 */
static void udpWatch(ClientData instanceData, int mask) {
#ifndef _WIN32
    UdpState *statePtr = (UdpState *) instanceData;

    statePtr->mask = mask;
    if (mask) {
	UDPTRACE("Tcl_CreateFileHandler\n");
	Tcl_CreateFileHandler(statePtr->sock, mask, (Tcl_FileProc *) Tcl_NotifyChannel,
		(ClientData) statePtr->channel);
    } else {
	UDPTRACE("Tcl_DeleteFileHandler\n");
	Tcl_DeleteFileHandler(statePtr->sock);
    }
#endif
}

/*
 * ----------------------------------------------------------------------
 * udpGetHandle --
 *   Called from the channel driver to get a handle to the socket.
 *
 * Results:
 *   Puts the socket into handlePtr and returns TCL_OK;
 *
 * Side Effects:
 *   None
 * ----------------------------------------------------------------------
 */
static int udpGetHandle(ClientData instanceData, int direction, ClientData *handlePtr) {
    UdpState *statePtr = (UdpState *) instanceData;

    UDPTRACE("udpGetHandle %ld\n", (long)statePtr->sock);

#ifndef _WIN32
    *handlePtr = (ClientData) (intptr_t) statePtr->sock;
#else
    *handlePtr = (ClientData) statePtr->sock;
#endif
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpOutput--
 * ----------------------------------------------------------------------
 */
static int udpOutput(ClientData instanceData, const char *buf, int toWrite, int *errorCode) {
    UdpState *statePtr = (UdpState *) instanceData;
    int written, socksize;
    struct addrinfo hints, *result;

    if (toWrite > MAXBUFFERSIZE) {
	UDPTRACE("UDP error - MAXBUFFERSIZE");
	return -1;
    }

     if (statePtr->ss_family == AF_INET6) {
	struct sockaddr_in6 sendaddrv6;
	socksize = sizeof(sendaddrv6);
	memset(&sendaddrv6, 0, socksize);
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	if (getaddrinfo(statePtr->remotehost, NULL, &hints, &result) != 0) {
	    UDPTRACE("UDP error - getaddrinfo failed");
	    return -1;
	}
	memcpy (&sendaddrv6, result->ai_addr, result->ai_addrlen);
	freeaddrinfo(result);

	sendaddrv6.sin6_family = AF_INET6;
	sendaddrv6.sin6_port = statePtr->remoteport;
	written = sendto(statePtr->sock, buf, toWrite, 0, (struct sockaddr *)&sendaddrv6, socksize);

    } else {
	struct sockaddr_in sendaddrv4;
	struct hostent *name;
	socksize = sizeof(sendaddrv4);
	memset(&sendaddrv4, 0, socksize);
#ifdef _WIN32
	/* MinGW, at least, on Windows doesn't grok aton */
	sendaddrv4.sin_addr.s_addr = inet_addr(statePtr->remotehost);

	if (sendaddrv4.sin_addr.s_addr == -1) {
	    name = gethostbyname(statePtr->remotehost);
	    if (name == NULL) {
		UDPTRACE("UDP error - gethostbyname");
		return -1;
	    }
	    memcpy(&sendaddrv4.sin_addr, name->h_addr, sizeof(sendaddrv4.sin_addr));
	}
	sendaddrv4.sin_family = AF_INET;
	sendaddrv4.sin_port = statePtr->remoteport;
	written = sendto(statePtr->sock, buf, toWrite, 0, (struct sockaddr *)&sendaddrv4, socksize);

#else
	struct in_addr remote_addr;

	if(inet_aton(statePtr->remotehost,&remote_addr)==0) {
	    name = gethostbyname(statePtr->remotehost);
	    if (name == NULL) {
		UDPTRACE("UDP error - gethostbyname");
		return -1;
	    }
	    memcpy(&sendaddrv4.sin_addr, name->h_addr, sizeof(sendaddrv4.sin_addr));
	} else {
	    sendaddrv4.sin_addr=remote_addr;
	}
	sendaddrv4.sin_family = AF_INET;
	sendaddrv4.sin_port = statePtr->remoteport;
	written = sendto(statePtr->sock, buf, toWrite, 0, (struct sockaddr *)&sendaddrv4, socksize);
#endif
    }

    if (written < 0) {
	UDPTRACE("UDP error - sendto");
	return -1;
    }

    UDPTRACE("Send %d to %s:%d through %d\n", written, statePtr->remotehost,
	ntohs(statePtr->remoteport), statePtr->sock);

    return written;
}

/*
 * ----------------------------------------------------------------------
 * udpInput
 *    buf is allocated in UDP_CheckProc with MAXBUFFERSIZE+1
 *    bufSize comes from Tcl default size
 * ----------------------------------------------------------------------
 */
static int udpInput(ClientData instanceData, char *buf, int bufSize, int *errorCode) {
    UdpState *statePtr = (UdpState *) instanceData;
    int bytesRead;

#ifdef _WIN32
    PacketList *packets;
#else /* ! _WIN32 */
    socklen_t socksize;
    int buffer_size = MAXBUFFERSIZE;
    int sock = statePtr->sock;
    address recvaddr;
#endif /* ! _WIN32 */

    UDPTRACE("In udpInput\n");

    /*
     * The caller of this function is looking for a stream oriented
     * system, so it keeps calling the function until no bytes are
     * returned, and then appends all the characters together.  This
     * is not what we want from UDP, so we fake it by returning a
     * blank every other call.  whenever the doread variable is 1 do
     * a normal read, otherwise just return -1 to indicate that we want
     * to receive data again.
     */
    if (statePtr->doread == 0) {
	statePtr->doread = 1;  /* next time we want to behave normally */
	*errorCode = EAGAIN;   /* pretend that we would block */
	UDPTRACE("Pretend we would block\n");
	return -1;
    }

    *errorCode = 0;
    errno = 0;

    if (bufSize == 0) {
	return 0;
    }

#ifdef _WIN32
    packets = statePtr->packets;
    UDPTRACE("udp_recv\n");

    if (--statePtr->packetNum <= 0) {
	statePtr->packetNum = 0;
	SetEvent(waitForSock);
    }

    if (packets == NULL) {
	UDPTRACE("packets is NULL\n");
	*errorCode = EAGAIN;
	return -1;
    }

    if (packets->actual_size > bufSize) {
        packets->actual_size = bufSize;
    }
    memcpy(buf, packets->message, packets->actual_size);
    /* VERY TRICKY: add null-terminating byte, we reserved MAXBUFFERSIZE+1 */ 
    if (packets->actual_size <= bufSize) {
	buf[packets->actual_size] = '\0';
    }
    ckfree((char *) packets->message);
    UDPTRACE("udp_recv message with %d bytes", packets->actual_size);

    bufSize = packets->actual_size;
    strcpy(statePtr->peerhost, packets->r_host);
    statePtr->peerport = packets->r_port;
    statePtr->packets = packets->next;
    ckfree((char *) packets);
    bytesRead = bufSize;
#else /* ! _WIN32 */
    socksize = sizeof(recvaddr);
    memset(&recvaddr, 0, socksize);

    if (buffer_size > bufSize) {
        buffer_size = bufSize;
    }
    bytesRead = recvfrom(sock, buf, buffer_size, 0, (struct sockaddr *)&recvaddr, &socksize);
    if (bytesRead < 0) {
	UDPTRACE("UDP error - recvfrom %d\n", sock);
	*errorCode = errno;
	return -1;
    }

    if (statePtr->ss_family == AF_INET6) {
	inet_ntop(AF_INET6, &recvaddr.sa6.sin6_addr, statePtr->peerhost, sizeof(statePtr->peerhost));
	statePtr->peerport = ntohs(recvaddr.sa6.sin6_port);
    } else {
	inet_ntop(AF_INET, &recvaddr.sa4.sin_addr, statePtr->peerhost, sizeof(statePtr->peerhost));
	statePtr->peerport = ntohs(recvaddr.sa4.sin_port);
    }

    UDPTRACE("remotehost: %s:%d\n", statePtr->peerhost, statePtr->peerport);
#endif /* ! _WIN32 */

    /* we don't want to return anything next time */
    if (bytesRead > 0) {
        if (bytesRead < bufSize) {
	    buf[bytesRead] = '\0';
	}
	statePtr->doread = 0;
    }

    UDPTRACE("udpInput end: %d, %s\n", bytesRead, buf);

    if (bytesRead == 0) {
	*errorCode = EAGAIN;
	return -1;
    }

#ifdef _WIN32
    if (bytesRead > -1) {
	return bytesRead;
    }

    *errorCode = errno;
    return -1;
#else
    return bytesRead;
#endif
}

/*
 * ----------------------------------------------------------------------
 * udpGetBroadcastOption --
 *
 *  Handle get broadcast configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpGetBroadcastOption(UdpState *statePtr, Tcl_Interp *interp, int* value) {
    int result = TCL_OK;
    socklen_t optlen = sizeof(int);

    result = getsockopt(statePtr->sock, SOL_SOCKET, SO_BROADCAST, (char*)value, &optlen);
    if (result < 0) {
	Tcl_SetObjResult(interp, ErrorToObj("error getting -broadcast"));
	return TCL_ERROR;
    }

    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpSetBroadcastOption --
 *
 *  Handle set broadcast configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetBroadcastOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result;
    int tmp = 1;

    if (Tcl_GetBoolean(interp, newValue, &tmp) != TCL_OK) {
	return TCL_ERROR;
    }

    result = setsockopt(statePtr->sock, SOL_SOCKET, SO_BROADCAST, (const char *)&tmp, sizeof(int));
    if (result == 0) {
	Tcl_SetObjResult(interp, Tcl_NewIntObj(tmp));
    } else {
	Tcl_SetObjResult(interp, ErrorToObj("error setting -broadcast"));
	return TCL_ERROR;
    }
    return result;
}

/*
 * ----------------------------------------------------------------------
 * udpGetMcastloopOption --
 *
 *  Handle get multi-cast loop configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpGetMcastloopOption(UdpState *statePtr, Tcl_Interp *interp, unsigned char *value) {
    int result = 0;
    socklen_t optlen = sizeof(int);

    if (statePtr->ss_family == AF_INET) {
	result = getsockopt(statePtr->sock, IPPROTO_IP, IP_MULTICAST_LOOP, value, &optlen);
    } else {
	result = getsockopt(statePtr->sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, value, &optlen);
    }

    if (result < 0) {
	Tcl_SetObjResult(interp, ErrorToObj("error getting -mcastloop"));
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpSetMcastloopOption --
 *
 *  Set loop back multicast datagrams if local host is part of multicast group
 *
 * ----------------------------------------------------------------------
 */
static int udpSetMcastloopOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result = 0;
    int tmp = 1;

    if (Tcl_GetBoolean(interp, newValue, &tmp) == TCL_OK) {
	if (statePtr->ss_family == AF_INET) {
	    result = setsockopt(statePtr->sock, IPPROTO_IP, IP_MULTICAST_LOOP, 
		(const char *)&tmp, sizeof(tmp));
	} else {
	    result = setsockopt(statePtr->sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 
		(const char *)&tmp, sizeof(tmp));
	}
    } else {
	return TCL_ERROR;
    }

    if (result == 0) {
	Tcl_SetObjResult(interp, Tcl_NewIntObj(tmp));
    } else {
	Tcl_SetObjResult(interp, ErrorToObj("error setting -mcastloop"));
	return TCL_ERROR;
    }
    return TCL_OK;
}

#ifndef _WIN32
/*
 * ----------------------------------------------------------------------
 * udpSetMulticastIFOption --
 *
 *  Specify the default gateway interface for multicast
 *
 * ----------------------------------------------------------------------
 */
static int udpSetMulticastIFOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    if (statePtr->ss_family == AF_INET) {
	struct in_addr interface_addr;

	if (inet_aton(newValue, &interface_addr) == 0) {
	    Tcl_SetObjResult(interp, ErrorToObj("error setting -mcastif (bad IP)"));
	    return TCL_ERROR;
	}

	if (setsockopt(statePtr->sock, IPPROTO_IP, IP_MULTICAST_IF, (const char*)&interface_addr, sizeof(interface_addr)) < 0) {
	    Tcl_SetObjResult(interp, ErrorToObj("error setting -mcastif"));
	    return TCL_ERROR;
	}
    } else {
	struct in6_addr interface_addr;

	if (inet_pton(AF_INET6, newValue, &interface_addr)==0) {
	    Tcl_SetObjResult(interp, ErrorToObj("error setting -mcastif (bad IP)"));
	    return TCL_ERROR;
	}
	
	if (setsockopt(statePtr->sock, IPPROTO_IP, IPV6_MULTICAST_IF, (const char*)&interface_addr, sizeof(interface_addr)) < 0) {
	    Tcl_SetObjResult(interp, ErrorToObj("error setting -mcastif"));
	    return TCL_ERROR;
	}
    }
    return TCL_OK;
}
#endif

/* ----------------------------------------------------------------------
 *
 * LSearch --
 *
 * 	Find a string item in a list or return -1 if not found.
 * ----------------------------------------------------------------------
 */

static Tcl_Size LSearch(Tcl_Obj *listObj, const char *group) {
    Tcl_Size objc, n;
    Tcl_Obj **objv;
    Tcl_ListObjGetElements(NULL, listObj, &objc, &objv);
    for (n = 0; n < objc; n++) {
	if (strcmp(group, Tcl_GetString(objv[n])) == 0) {
	    return n;
	}
    }
    return -1;
}

/*
 * ----------------------------------------------------------------------
 *
 * UdpMulticast --
 *
 *	Action should be IP_ADD_MEMBERSHIP | IPV6_JOIN_GROUP
 *  or IP_DROP_MEMBERSHIP | IPV6_LEAVE_GROUP
 *
 * ----------------------------------------------------------------------
 */

static int UdpMulticast(UdpState *statePtr, Tcl_Interp *interp, const char *grp, int action) {
    Tcl_Obj *tcllist , *multicastgrp , *nw_interface;
    Tcl_Size len;
    int nwinterface_index =-1;
#ifndef _WIN32
    struct ifreq ifreq;
#endif /* ! _WIN32 */

    /*
     * Parameter 'grp' can be:
     *  Windows: <multicast group> or {<multicast group> <network interface index>}
     *  Not Windows: <multicast group> or {<multicast group> <network interface name>}
     */
    tcllist = Tcl_NewStringObj(grp, -1);
    Tcl_IncrRefCount(tcllist);
    if (Tcl_ListObjLength(interp, tcllist, &len) == TCL_OK) {
	if (len==2) {
	    Tcl_ListObjIndex(interp, tcllist, 0, &multicastgrp);
	    Tcl_ListObjIndex(interp, tcllist, 1, &nw_interface);
#ifdef _WIN32
	    if (Tcl_GetIntFromObj(interp,nw_interface,&nwinterface_index) == TCL_ERROR ||
		    nwinterface_index < 1) {
		Tcl_SetResult(interp, "not a valid network interface index; should start with 1", TCL_STATIC);
		Tcl_DecrRefCount(tcllist);
		return TCL_ERROR;
	    }
#else
	    Tcl_Size lenPtr = -1;
	    char *name = Tcl_GetStringFromObj(nw_interface,&lenPtr);
	    if (lenPtr > IFNAMSIZ ) {
		Tcl_SetResult(interp, "network interface name too long", TCL_STATIC);
		Tcl_DecrRefCount(tcllist);
		return TCL_ERROR;
	    }

	    if (statePtr->ss_family == AF_INET) {
		/* For IPv4, we need the network interface address. */
		strcpy(ifreq.ifr_name, name);
		if (ioctl(statePtr->sock, SIOCGIFADDR, &ifreq) < 0 ) {
		Tcl_SetResult(interp, "unknown network interface", TCL_STATIC);
		Tcl_DecrRefCount(tcllist);
		return TCL_ERROR;
		}
	    }
	    nwinterface_index = if_nametoindex(name);
	    if (nwinterface_index == 0 ) {
		Tcl_SetResult(interp, "unknown network interface", TCL_STATIC);
		Tcl_DecrRefCount(tcllist);
		return TCL_ERROR;
	    }
#endif /* ! _WIN32 */
	} else if (len==1) {
	    Tcl_ListObjIndex(interp, tcllist, 0, &multicastgrp);
	} else {
	    Tcl_SetResult(interp, "multicast group and/or local network interface not specified", TCL_STATIC);
	    Tcl_DecrRefCount(tcllist);
	    return TCL_ERROR;
	}
    }

    if (statePtr->ss_family == AF_INET) {
	struct ip_mreq mreq;
	struct hostent *name;

	memset(&mreq, 0, sizeof(mreq));

	mreq.imr_multiaddr.s_addr = inet_addr(Tcl_GetString(multicastgrp));
	if (mreq.imr_multiaddr.s_addr == -1) {
	    name = gethostbyname(Tcl_GetString(multicastgrp));
	    if (name == NULL) {
		if (interp != NULL) {
		    Tcl_SetResult(interp, "invalid group name", TCL_STATIC);
		}
		Tcl_DecrRefCount(tcllist);
		return TCL_ERROR;
	    }
	    memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, sizeof(mreq.imr_multiaddr));
	}

	if (nwinterface_index==-1) {
	    /* No interface index specified. Let the system use the default interface. */
	    mreq.imr_interface.s_addr = INADDR_ANY;
	} else {
#ifdef _WIN32
	    /* Using an interface index of x is indicated by 0.0.0.x */
	    mreq.imr_interface.s_addr = htonl(nwinterface_index);
#else
	    memcpy(&mreq.imr_interface, &((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr, sizeof(struct in_addr));
#endif
	}

	if (setsockopt(statePtr->sock, IPPROTO_IP, action, (const char*)&mreq, sizeof(mreq)) < 0) {
	    if (interp != NULL) {
		Tcl_SetObjResult(interp, ErrorToObj("error changing multicast group"));
	    }
	    Tcl_DecrRefCount(tcllist);
	    return TCL_ERROR;
	}
    } else {
	struct ipv6_mreq mreq6;
	struct addrinfo hints;
	struct addrinfo *gai_ret = NULL;
	int r;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = statePtr->ss_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	r = getaddrinfo(Tcl_GetString(multicastgrp), NULL, &hints, &gai_ret);

	if (r != 0 ) {
	    if (interp != NULL) {
		Tcl_SetResult(interp, "invalid group name", TCL_STATIC);
	    }
            freeaddrinfo(gai_ret);
	    Tcl_DecrRefCount(tcllist);
	    return TCL_ERROR;
	} else {
	    memcpy(&mreq6.ipv6mr_multiaddr, &((struct sockaddr_in6*)(gai_ret->ai_addr))->sin6_addr,sizeof(mreq6.ipv6mr_multiaddr));
	    freeaddrinfo(gai_ret);
	}

	if (nwinterface_index == -1) {
	    /* Let the system choose the default multicast network interface. */
	    mreq6.ipv6mr_interface = 0;
	} else {
	    /* Use the specified network interface. */
	    mreq6.ipv6mr_interface = nwinterface_index;
	}

	if (setsockopt(statePtr->sock, IPPROTO_IPV6, action, (const char*)&mreq6, sizeof(mreq6)) < 0) {
	    if (interp != NULL) {
		Tcl_SetObjResult(interp, ErrorToObj("error changing multicast group"));
	    }
	    Tcl_DecrRefCount(tcllist);
	    return TCL_ERROR;
	}
    }
    Tcl_DecrRefCount(tcllist);

    if (action == IP_ADD_MEMBERSHIP || action == IPV6_JOIN_GROUP) {
	Tcl_Size ndx = LSearch(statePtr->groupsObj, grp);
	if (ndx == -1) {
	    Tcl_Obj *newPtr;
	    statePtr->multicast++;
	    if (Tcl_IsShared(statePtr->groupsObj)) {
		newPtr = Tcl_DuplicateObj(statePtr->groupsObj);
		Tcl_DecrRefCount(statePtr->groupsObj);
		Tcl_IncrRefCount(newPtr);
		statePtr->groupsObj = newPtr;
	    }
	    Tcl_ListObjAppendElement(interp, statePtr->groupsObj,
		Tcl_NewStringObj(grp,-1));
	}
    } else {
	Tcl_Size ndx = LSearch(statePtr->groupsObj, grp);
	if (ndx != -1) {
	    Tcl_Obj *old, *ptr;
	    int dup = 0;
	    old = ptr = statePtr->groupsObj;
	    statePtr->multicast--;
	    if ((dup = Tcl_IsShared(ptr))) {
		ptr = Tcl_DuplicateObj(ptr);
	    }
	    Tcl_ListObjReplace(interp, ptr, ndx, 1, 0, NULL);
	    if (dup) {
		statePtr->groupsObj = ptr;
		Tcl_IncrRefCount(ptr);
		Tcl_DecrRefCount(old);
	    }
	}
    }
    if (interp != NULL) {
	Tcl_SetObjResult(interp, statePtr->groupsObj);
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpSetMulticastAddOption --
 *
 *  Handle multicast add configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetMulticastAddOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result;

    if (statePtr->ss_family == AF_INET) {
	result = UdpMulticast(statePtr, interp, (const char *)newValue, IP_ADD_MEMBERSHIP);
    } else {
	result = UdpMulticast(statePtr, interp, (const char *)newValue, IPV6_JOIN_GROUP);
    }
    return result;
}

/*
 * ----------------------------------------------------------------------
 * udpSetMulticastDropOption --
 *
 *  Handle multicast drop configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetMulticastDropOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result;

    if (statePtr->ss_family == AF_INET) {
	result = UdpMulticast(statePtr, interp, (const char *)newValue, IP_DROP_MEMBERSHIP);
    } else {
	result = UdpMulticast(statePtr, interp, (const char *)newValue, IPV6_LEAVE_GROUP);
    }
    return result;
}

/*
 * ----------------------------------------------------------------------
 * udpSetRemoteOption --
 *
 *  Handle remote port/host configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetRemoteOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result = TCL_OK;
    Tcl_Obj *valPtr;
    Tcl_Size len;

    valPtr = Tcl_NewStringObj(newValue, -1);
    Tcl_IncrRefCount(valPtr);

    if (Tcl_ListObjLength(interp, valPtr, &len) != TCL_OK) {
	Tcl_DecrRefCount(valPtr);
	return TCL_ERROR;
    }

    if (len < 1 || len > 2) {
	Tcl_WrongNumArgs(interp, 0, NULL, "?hostname? ?port?");
	Tcl_DecrRefCount(valPtr);
	return TCL_ERROR;

    } else {
	Tcl_Obj *hostPtr, *portPtr;

	Tcl_ListObjIndex(interp, valPtr, 0, &hostPtr);
	strncpy(statePtr->remotehost, Tcl_GetString(hostPtr), sizeof(statePtr->remotehost));
	statePtr->remotehost[sizeof(statePtr->remotehost)-1] = '\0';

	if (len == 2) {
	    Tcl_ListObjIndex(interp, valPtr, 1, &portPtr);
	    result = udpGetService(interp, Tcl_GetString(portPtr), &(statePtr->remoteport));
	}
    }

    if (result == TCL_OK) {
	Tcl_SetObjResult(interp, valPtr);
    }
    Tcl_DecrRefCount(valPtr);
    return result;
}

/*
 * ----------------------------------------------------------------------
 * udpGetTtlOption --
 *
 *  Handle get ttl configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpGetTtlOption(UdpState *statePtr, Tcl_Interp *interp, unsigned int *value) {
    int result = 0;
    int cmd;
    socklen_t optlen = sizeof(unsigned int);

    if (statePtr->ss_family==AF_INET) {
	if (statePtr->multicast > 0) {
	    cmd = IP_MULTICAST_TTL;
	} else {
	    cmd = IP_TTL;
	}
	result = getsockopt(statePtr->sock, IPPROTO_IP, cmd, (char*)value, &optlen);
    } else {
	if (statePtr->multicast > 0) {
	    cmd = IPV6_MULTICAST_HOPS;
	} else {
	    cmd = IPV6_UNICAST_HOPS;
	}
	result = getsockopt(statePtr->sock, IPPROTO_IPV6, cmd, (char*)value, &optlen);
    }

    if (result < 0) {
	Tcl_SetObjResult(interp, ErrorToObj("error getting -ttl"));
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpSetTtlOption --
 *
 *  Handle set ttl configuration requests.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetTtlOption(UdpState *statePtr, Tcl_Interp *interp, const char *newValue) {
    int result = 0;
    int tmp = 0;
    int cmd;
    
    /* range: 0 to 255, use default = -1 */
    if (Tcl_GetInt(interp, newValue, &tmp) != TCL_OK) {
	return TCL_ERROR;
    }

    if (statePtr->ss_family==AF_INET) {
	if (statePtr->multicast > 0) {
	    cmd = IP_MULTICAST_TTL;
	} else {
	    cmd = IP_TTL;
	}
	result = setsockopt(statePtr->sock,IPPROTO_IP,cmd,(const char *)&tmp,sizeof(unsigned int));

    } else {
	if (statePtr->multicast > 0) {
	    cmd = IPV6_MULTICAST_HOPS;
	} else {
	    cmd = IPV6_UNICAST_HOPS;
	}
	result = setsockopt(statePtr->sock,IPPROTO_IPV6,cmd,(const char *)&tmp,sizeof(unsigned int));
    }

    if (result == 0) {
	Tcl_SetObjResult(interp, Tcl_NewIntObj(tmp));
    } else {
	Tcl_SetObjResult(interp, ErrorToObj("error setting -ttl"));
	return TCL_ERROR;
    }
    return TCL_OK;
}

/*
* ----------------------------------------------------------------------
* udpGetOption --
* ----------------------------------------------------------------------
*/
static int udpGetOption(ClientData instanceData, Tcl_Interp *interp, const char *optionName,
	Tcl_DString *optionValue) {
    UdpState *statePtr = (UdpState *)instanceData;
    int r = TCL_OK, opt = -1;

    Tcl_ResetResult(interp);

    if (optionName == NULL) {
	Tcl_DString ds;

	for (opt = _opt_broadcast; opt <= _opt_ttl; opt++) {
	    if (cfg_opts[opt] != NULL) {
		Tcl_DStringInit(&ds);
		Tcl_DStringSetLength(&ds, 0);
		if (udpGetOption(instanceData, interp, cfg_opts[opt], &ds) != TCL_ERROR) {
		    Tcl_DStringAppend(optionValue, " ", 1);
		    Tcl_DStringAppend(optionValue, cfg_opts[opt], -1);
		    Tcl_DStringAppend(optionValue, " ", 1);
		    Tcl_DStringAppendElement(optionValue, Tcl_DStringValue(&ds));
		}
		Tcl_DStringFree(&ds);
	    }
	}

    } else {
	Tcl_DString ds, dsInt;

	Tcl_Obj *nameObj = Tcl_NewStringObj(optionName, -1);
	Tcl_IncrRefCount(nameObj);

	if (Tcl_GetIndexFromObj(interp, nameObj, cfg_opts, "option", 0, &opt) != TCL_OK) {
	    return TCL_ERROR;
	}

	Tcl_DStringInit(&ds);
	Tcl_DStringInit(&dsInt);

	switch(opt) {
	case _opt_broadcast:
	    int tmp = 1;
	    if ((r = udpGetBroadcastOption(statePtr,interp,&tmp)) == TCL_OK) {
		Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
		sprintf(Tcl_DStringValue(&ds), "%d", tmp);
	    }
	    break;

	case _opt_family:
	    if (statePtr->ss_family == AF_INET6) {
		Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
		Tcl_DStringAppendElement(&ds, "ipv6");
	    } else {
		Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
		Tcl_DStringAppendElement(&ds, "ipv4");
	    }
	    break;

	case _opt_mcastgroups:
	    Tcl_Size objc, n;
	    Tcl_Obj **objv;
	    Tcl_ListObjGetElements(interp, statePtr->groupsObj, &objc, &objv);
	    for (n = 0; n < objc; n++) {
		Tcl_DStringAppendElement(&ds, Tcl_GetString(objv[n]));
	    }
	    break;

	case _opt_mcastloop:
	    unsigned char str = 0;
	    if ((r = udpGetMcastloopOption(statePtr, interp, &str)) == TCL_OK) {
		Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
		sprintf(Tcl_DStringValue(&ds), "%d", (int)str);
	    }
	    break;

	case _opt_myport:
	    Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
	    sprintf(Tcl_DStringValue(&ds), "%u", ntohs(statePtr->localport));
	    break;

	case _opt_peer:
	   if (*statePtr->peerhost) {
		Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
		sprintf(Tcl_DStringValue(&dsInt), "%u", statePtr->peerport);
		Tcl_DStringAppendElement(&ds, statePtr->peerhost);
		Tcl_DStringAppendElement(&ds, Tcl_DStringValue(&dsInt));
	   }
	    break;

	case _opt_remote:
	    if (*statePtr->remotehost) {
		Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
		sprintf(Tcl_DStringValue(&dsInt), "%u", ntohs(statePtr->remoteport));
		Tcl_DStringAppendElement(&ds, statePtr->remotehost);
		Tcl_DStringAppendElement(&ds, Tcl_DStringValue(&dsInt));
	    }
	    break;

	case _opt_ttl:
	    unsigned int ttl = 0;
	    if ((r = udpGetTtlOption(statePtr, interp, &ttl)) == TCL_OK) {
		Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
		sprintf(Tcl_DStringValue(&ds), "%u", ttl);
	    }
	    break;
	
	default:
	    Tcl_AppendResult(interp, "set only option \"", optionName, "\"", NULL);
	    r = TCL_ERROR;
	}

	if (r == TCL_OK) {
	    Tcl_DStringAppend(optionValue, Tcl_DStringValue(&ds), -1);
	}
	Tcl_DStringFree(&dsInt);
	Tcl_DStringFree(&ds);
    }
    return r;
}

/*
 * ----------------------------------------------------------------------
 * udpSetOption --
 *
 *  Handle channel configuration requests from the generic layer.
 *
 * ----------------------------------------------------------------------
 */
static int udpSetOption(ClientData instanceData, Tcl_Interp *interp, const char *optionName,
	const char *newValue) {
    UdpState *statePtr = (UdpState *)instanceData;
    int r = TCL_OK, opt;

    Tcl_Obj *nameObj = Tcl_NewStringObj(optionName,-1);
    Tcl_IncrRefCount(nameObj);
	
    Tcl_ResetResult(interp);

    if (Tcl_GetIndexFromObj(interp, nameObj, cfg_opts, "option", 0, &opt) != TCL_OK) {
	Tcl_DecrRefCount(nameObj);
	return TCL_ERROR;
    }
    Tcl_DecrRefCount(nameObj);

    switch(opt) {
    case _opt_broadcast:
	r = udpSetBroadcastOption(statePtr, interp, (const char*) newValue);
	break;

    case _opt_mcastadd:
	r = udpSetMulticastAddOption(statePtr, interp, (const char *)newValue);
	break;

    case _opt_mcastdrop:
	r = udpSetMulticastDropOption(statePtr, interp, (const char *)newValue);
	break;

#ifndef _WIN32
    case _opt_mcastif:
	r = udpSetMulticastIFOption(statePtr,interp,(const char *)newValue);
	break;
#endif

    case _opt_mcastloop:
	r = udpSetMcastloopOption(statePtr, interp, (const char*) newValue);
	break;

    case _opt_remote:
	r = udpSetRemoteOption(statePtr,interp,(const char *)newValue);
	break;

    case _opt_ttl:
	r = udpSetTtlOption(statePtr, interp, (const char*) newValue);
	break;
	
    default:
	Tcl_AppendResult(interp, "get only option \"", optionName, "\"", NULL);
	r = TCL_ERROR;
    }
    return r;
}

/*
 *---------------------------------------------------------------------------
 *
 * udpThreadAction --
 *
 *   Called from the channel driver to detach/attach from/to thread.
 *
 * Results:
 *   None
 *
 * Side Effects:
 *   None
 *
 *---------------------------------------------------------------------------
 */

static void
udpThreadAction(ClientData instanceData, int action) {
    UdpState *statePtr = (UdpState *) instanceData;

    switch (action) {
      case TCL_CHANNEL_THREAD_REMOVE:
#ifdef _WIN32
	statePtr->threadId = NULL;
#else
	if (statePtr->mask > 0) {
	    UDPTRACE("Tcl_DeleteFileHandler\n");
	    Tcl_DeleteFileHandler(statePtr->sock);
	}
#endif
	break;
      case TCL_CHANNEL_THREAD_INSERT:
#ifdef _WIN32
	statePtr->threadId = Tcl_GetCurrentThread();
#else
	if (statePtr->mask > 0) {
	    UDPTRACE("Tcl_CreateFileHandler\n");
	    Tcl_CreateFileHandler(statePtr->sock, statePtr->mask,
		(Tcl_FileProc *) Tcl_NotifyChannel, (ClientData) statePtr->channel);
	}
#endif
	break;
    }
}

/*
 * This structure describes the channel type for accessing UDP.
 */
static Tcl_ChannelType Udp_ChannelType = {
    "udp",                 /* Type name.                                    */
    TCL_CHANNEL_VERSION_5, /* v5 channel */
    udpClose,              /* Close channel, clean instance data            */
    udpInput,              /* Handle read request                           */
    udpOutput,             /* Handle write request                          */
    NULL,                  /* Seek proc.                          NULL'able */
    udpSetOption,          /* Set options.                        NULL'able */
    udpGetOption,          /* Get options.                        NULL'able */
    udpWatch,              /* Initialize notifier                           */
    udpGetHandle,          /* Get OS handle from the channel.               */
    udpClose2,		   /* close2proc                          NULL'able */
    NULL,     		   /* Set blocking/nonblocking mode.      NULL'able */
    NULL,		   /* Flush proc.                         NULL'able */
    NULL,		   /* Handling of events bubbling up.     NULL'able */
    NULL,		   /* Wide seek proc.                     NULL'able */
    udpThreadAction,	   /* Thread action.                      NULL'able */
    NULL,		   /* Truncate.                           NULL'able */
};



/*
 * Commands
 */


static const char *open_opts[] = {
    "ipv4", "ipv6", "reuse", NULL};

enum _open_opts {
    _open_ipv4, _open_ipv6, _open_reuse
};

/*
 * ----------------------------------------------------------------------
 * udpOpen --
 *
 *  opens a UDP socket and adds the file descriptor to the tcl
 *  interpreter
 * ----------------------------------------------------------------------
 */
int udpOpen(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
#ifdef _WIN32
    SOCKET sock;
#else
    int sock;
#endif
    char channelName[20];
    UdpState *statePtr;
    uint16_t localport = 0;
    int reuse = 0, port;
    Tcl_Size opt;
    address addr,sockaddr;
    socklen_t addr_len, len;
    short ss_family = AF_INET; /* Default ipv4 */

    Tcl_ResetResult(interp);

    if (objc < 1 || objc > 4) {
	Tcl_WrongNumArgs(interp, 1, objv, "?localport? ?ipv6? ?reuse?");
	return TCL_ERROR;
    }

    /* Get opts */
    for (int i = 1; i < objc; i++) {
	if (Tcl_GetIndexFromObj(interp, objv[i], open_opts, "option", TCL_EXACT, &opt) != TCL_OK) {
	    Tcl_ResetResult(interp);
	    if (Tcl_GetIntFromObj(NULL, objv[i], &port) == TCL_OK) {
		if (port < 0) {
		    Tcl_AppendResult(interp, "couldn't open socket: port number too low", (char *) NULL);
		    return TCL_ERROR;
		} else if (port > 65535) {
		    Tcl_AppendResult(interp, "couldn't open socket: port number too high", (char *) NULL);
		    return TCL_ERROR;
		} else {
		    localport = htons((uint16_t)port);
		}
	    } else {
		/* Port could be a service name */
		if (udpGetService(interp, Tcl_GetString(objv[i]), &localport) != TCL_OK) {
		    return TCL_ERROR;
		}
	    }

	} else {
	    switch(opt) {
	    case _open_ipv4:
		ss_family = AF_INET;
		break;
	    case _open_ipv6:
		ss_family = AF_INET6;
		break;
	    case _open_reuse:
		reuse = 1;
		break;
	    }
	}
    }

    memset(channelName, 0, sizeof(channelName));

    sock = socket(ss_family, SOCK_DGRAM, 0);
    if (sock < 0) {
	Tcl_AppendResult(interp, "failed to create socket", (char *) NULL);
	return TCL_ERROR;
    }

    /*
     * bug #1477669: avoid socket inheritance after exec
     */
#ifndef _WIN32
#if HAVE_FLAG_FD_CLOEXEC
    fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
    fcntl(sock, F_SETFL, O_NONBLOCK);
#else
    if (SetHandleInformation((HANDLE)sock, HANDLE_FLAG_INHERIT, 0) == 0) {
	Tcl_AppendResult(interp, "failed to set close-on-exec bit", (char *) NULL);
	closesocket(sock);
	return TCL_ERROR;
    } else {
        int one = 1;
        ioctlsocket(sock, FIONBIO, &one);
    }
#endif /* _WIN32 */

    if (reuse) {
	int one = 1;
#ifdef SO_REUSEPORT
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, sizeof(one)) < 0)
#else
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one)) < 0)
#endif
	{
	    Tcl_SetObjResult(interp, ErrorToObj("error setting socket option"));
	    closesocket(sock);
	    return TCL_ERROR;
	}
    }

    memset(&addr, 0, sizeof(addr));
    if (ss_family == AF_INET6) {
	addr.sa6.sin6_family = AF_INET6;
	addr.sa6.sin6_port = localport;
	addr_len = sizeof(struct sockaddr_in6);
    } else {
	addr.sa4.sin_family = AF_INET;
	addr.sa4.sin_port = localport;
	addr_len = sizeof(struct sockaddr_in);
    }
    if (bind(sock,(struct sockaddr *)&addr, addr_len) < 0) {
	Tcl_SetObjResult(interp, ErrorToObj("failed to bind socket to port"));
	closesocket(sock);
	return TCL_ERROR;
    }

    if (localport == 0) {
	len = sizeof(sockaddr);
	getsockname(sock, (struct sockaddr *)&sockaddr, &len);
	if (ss_family == AF_INET6) {
	    localport = sockaddr.sa6.sin6_port;
	} else {
	    localport = sockaddr.sa4.sin_port;
	}
    }

    UDPTRACE("Open socket %d. Bind socket to port %d\n", sock, ntohs(localport));

    statePtr = (UdpState *) ckalloc((unsigned) sizeof(UdpState));
    memset(statePtr, 0, sizeof(UdpState));
    statePtr->sock = sock;
    sprintf(channelName, "sock" SOCKET_PRINTF_FMT, statePtr->sock);
    statePtr->channel = Tcl_CreateChannel(&Udp_ChannelType, channelName,
	(ClientData) statePtr, (TCL_READABLE | TCL_WRITABLE | TCL_MODE_NONBLOCKING));
    Tcl_SetChannelBufferSize(statePtr->channel, MAXBUFFERSIZE);
    statePtr->doread = 1;
    statePtr->multicast = 0;
    statePtr->groupsObj = Tcl_NewListObj(0, NULL);
    Tcl_IncrRefCount(statePtr->groupsObj);
    statePtr->localport = localport;
    statePtr->ss_family = ss_family;
    Tcl_RegisterChannel(interp, statePtr->channel);
#ifdef _WIN32
    statePtr->threadId = Tcl_GetCurrentThread();
    statePtr->packetNum = 0;
    statePtr->next = NULL;
    statePtr->packets = NULL;
    statePtr->packetsTail = NULL;
#else
    statePtr->mask = 0;
#endif
    /* Tcl_SetChannelOption(interp, statePtr->channel, "-blocking", "0"); */
    Tcl_AppendResult(interp, channelName, (char *) NULL);
#ifdef _WIN32
    WaitForSingleObject(sockListLock, INFINITE);
    statePtr->next = sockList;
    sockList = statePtr;

    UDPTRACE("Added %d to sockList\n", statePtr->sock);
    SetEvent(sockListLock);
    SetEvent(waitForSock);
#endif
    return TCL_OK;
}

/*
* -----------------------------------------------------------------------
* udpConf --
* -----------------------------------------------------------------------
*/
int udpConf(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_Channel chan;
    UdpState *statePtr = NULL;
    Tcl_Size opt;

    Tcl_ResetResult(interp);

    if (objc < 3 || objc > 12) {
	Tcl_WrongNumArgs(interp, 1, objv, "chanId [host port]|[-myport|-remote \"host port\"|-peer|-family|-mcastadd \"groupaddr ?netwif?\"|-mcastdrop \"groupaddr ?netwif?\"|-mcastgroups|-mcastloop ?boolean?|-broadcast ?boolean?|-ttl ?count?]");
	return TCL_ERROR;
    }

    /* Get channel */
    if ((chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL)) == NULL) {
	return TCL_ERROR;
    }

    statePtr = (UdpState *) Tcl_GetChannelInstanceData(chan);
    if (statePtr == NULL) {
	return TCL_ERROR;
    }

    /* Get option */
    if (objc == 3) {
	if (Tcl_GetIndexFromObj(interp, objv[2], cfg_opts, "option", 0, &opt) == TCL_OK) {
	    Tcl_DString ds;
	    Tcl_DStringInit(&ds);
	    if (Tcl_GetChannelOption(interp, statePtr->channel, cfg_opts[opt], &ds) == TCL_OK) {
		Tcl_DStringResult(interp, &ds);
		Tcl_DStringFree(&ds);
		return TCL_OK;
	    } else {
		Tcl_DStringFree(&ds);
		return TCL_ERROR;
	    }
	} else {
	    return TCL_ERROR;
	}
    } else if (objc == 4) {
	/* Special case: udp_conf sock host port */
	if (Tcl_GetIndexFromObj(interp, objv[2], cfg_opts, "option", 0, &opt) == TCL_ERROR) {
	    char remoteOptions[255];
	    sprintf(remoteOptions, "%s %s", Tcl_GetString(objv[2]), Tcl_GetString(objv[3]));
	    return Tcl_SetChannelOption(interp, statePtr->channel, "-remote", remoteOptions);
	}
    }

    /* Set option */
    for (int i = 2; i < objc; i++) {
	if (Tcl_GetIndexFromObj(interp, objv[i], cfg_opts, "option", 0, &opt) != TCL_OK) {
	    return TCL_ERROR;
	}

	switch(opt) {
	case _opt_broadcast:
	case _opt_mcastadd:
	case _opt_mcastdrop:
	case _opt_mcastif:
	case _opt_mcastloop:
	case _opt_remote:
	case _opt_ttl:
	    if (i+1 == objc) {
		Tcl_AppendResult(interp, "No value for option \"", cfg_opts[opt], "\"", (char *) NULL);
		return TCL_ERROR;
	    }

	    if (Tcl_SetChannelOption(interp, statePtr->channel, cfg_opts[opt], Tcl_GetString(objv[++i])) != TCL_OK) {
		return TCL_ERROR;
	    }
	    break;

	case _opt_family:
	case _opt_mcastgroups:
	case _opt_myport:
	case _opt_peer:
	    Tcl_AppendResult(interp, "Read-only option \"", cfg_opts[opt], "\"", (char *) NULL);
	    return TCL_ERROR;
	    break;
	}
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpPeek --
 *  peek some data and set the peer information
 * ----------------------------------------------------------------------
 */
int udpPeek(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
#ifndef _WIN32
    int buffer_size = 16;
    int actual_size;
    socklen_t socksize;
    char message[17];
    address recvaddr;
    Tcl_Channel chan;
    UdpState *statePtr;

    Tcl_ResetResult(interp);

    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "sock ?buffersize?");
	return TCL_ERROR;
    }

    /* Get channel */
    if ((chan = Tcl_GetChannel(interp, Tcl_GetString(objv[1]), NULL)) == NULL) {
	return TCL_ERROR;
    }

    statePtr = (UdpState *) Tcl_GetChannelInstanceData(chan);
    if (statePtr == NULL) {
	return TCL_ERROR;
    }

    /* Get buffer size */
    if (objc == 3) {
	if (Tcl_GetIntFromObj(interp, objv[2], &buffer_size) != TCL_OK) {
	    return TCL_ERROR;
	}
	if (buffer_size > 16) {
	    buffer_size = 16;
	}
    }

    memset(message, 0 , sizeof(message));
    actual_size = recvfrom(statePtr->sock, message, buffer_size, MSG_PEEK, 
	(struct sockaddr *)&recvaddr, &socksize);

    if (actual_size < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
	Tcl_SetObjResult(interp, ErrorToObj("udppeek error"));
	return TCL_ERROR;
    }

    if (statePtr->ss_family == AF_INET6) {
	inet_ntop(AF_INET6, &recvaddr.sa6.sin6_addr, statePtr->peerhost, sizeof(statePtr->peerhost));
	statePtr->peerport = ntohs(recvaddr.sa6.sin6_port);
    } else {
	inet_ntop(AF_INET, &recvaddr.sa4.sin_addr, statePtr->peerhost, sizeof(statePtr->peerhost));
	statePtr->peerport = ntohs(recvaddr.sa4.sin_port);
    }

    Tcl_AppendResult(interp, message, (char *) NULL);
    return TCL_OK;
#else /* _WIN32 */
    Tcl_SetResult(interp, "udp_peek not implemented for this platform", TCL_STATIC);
    return TCL_ERROR;
#endif /* ! _WIN32 */
}

/*
 * ----------------------------------------------------------------------
 * Udp_CmdProc --
 *  Provide a user interface similar to the Tcl stock 'socket' command.
 *
 *  udp ?options?
 *  udp ?options? host port
 *  udp -server command ?options? port
 *
 * ----------------------------------------------------------------------
 */
int Udp_CmdProc(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    Tcl_SetResult(interp, "E_NOTIMPL", TCL_STATIC);
    return TCL_ERROR;
}


/*
 * Support Commands
 */


/*
 * Options for address info command
 */
static const char *info_opts[] = {
    "-hostname", "-ipv4", "-ipv6", "-port", "-server", "-service", "-tcp", "-udp", NULL};

enum _info_opts {
    _info_host, _info_ipv4, _info_ipv6, _info_port, _info_server, _info_service, _info_tcp, _info_udp
};

/*
 * ----------------------------------------------------------------------
 * Udp_GetAddrInfo --
 *  Get address info for hostname or address
 *
 * ----------------------------------------------------------------------
 */
int Udp_GetAddrInfo(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    const char *hostname = NULL, *service = NULL, *str;
    struct addrinfo hints, *result, *rp;
    struct protoent *protocol;
    int err, opt;
    Tcl_Obj *resultObj, *listObj;

    memset(&hints, 0 , sizeof(hints));
    hints.ai_flags = (AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_addr = NULL;
    hints.ai_canonname = NULL;
    hints.ai_next = NULL;

    Tcl_ResetResult(interp);

    /* Validate argc */
    if (objc < 2 || objc > 8) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-hostname name? ?-port|-service id? ?-ipv4|-ipv6? ?-server? ?-tcp|-udp?");
	return TCL_ERROR;
    }

    /* Get options */
    for (int i = 1; i < objc; i++) {
	if (Tcl_GetIndexFromObj(interp, objv[i], info_opts, "option", TCL_EXACT, &opt) == TCL_OK) {
	    switch(opt) {
	    case _info_host:
		if (i < objc-1) {
		    hostname = Tcl_GetString(objv[++i]);
		} else {
		    Tcl_AppendResult(interp, "No hostname", (char *) NULL);
		    return TCL_ERROR;
		}
		break;
	    case _info_ipv4:
		hints.ai_family = AF_INET;
		break;
	    case _info_ipv6:
		hints.ai_family = AF_INET6;
		hints.ai_flags = hints.ai_flags | AI_V4MAPPED | AI_ALL;
		break;
	    case _info_port:
	    case _info_service:
		if (i < objc-1) {
		    service = Tcl_GetString(objv[++i]);
		} else {
		    Tcl_AppendResult(interp, "No port/service", (char *) NULL);
		    return TCL_ERROR;
		}
		break;
	    case _info_server:
		hints.ai_flags = hints.ai_flags | AI_PASSIVE;
		break;
	    case _info_tcp:
		hints.ai_socktype = SOCK_STREAM;
		break;
	    case _info_udp:
		hints.ai_socktype = SOCK_DGRAM;
		break;
	    }
	} else {
	    return TCL_ERROR;
	}
    }

    /* Get address info */
    if ((err = getaddrinfo(hostname, service, &hints, &result)) != 0) {
	Tcl_AppendResult(interp, "Get address info returned error: ", gai_strerror(err), (char *) NULL);
	return TCL_ERROR;
    }
    
    /* Parse result */
    resultObj = Tcl_NewListObj(0, NULL);
    for (rp = result; rp != NULL; rp = rp->ai_next) {
	char address[INET6_ADDRSTRLEN];
	unsigned short int port;
	listObj = Tcl_NewListObj(0, NULL);

	/* Socket family */
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("family",-1));
	switch(rp->ai_addr->sa_family) {
	case AF_INET:
	    str = "ipv4";
	    break;
	case AF_INET6:
	    str = "ipv6";
	    break;
	default:
	    str = "other";
	}
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj(str,-1));

	/* IP address and port */
	if (rp->ai_addr->sa_family == AF_INET) {
	    struct sockaddr_in *p = (struct sockaddr_in *)rp->ai_addr;
	    inet_ntop(AF_INET, &p->sin_addr, address, sizeof(address));
	    port = ntohs(p->sin_port);
	} else if (rp->ai_addr->sa_family == AF_INET6) {
	    struct sockaddr_in6 *p = (struct sockaddr_in6 *)rp->ai_addr;
	    inet_ntop(AF_INET6, &p->sin6_addr, address, sizeof(address));
	    port = ntohs(p->sin6_port);
	} else {
	    address[0] = '\0';
	    port = 0;
	}
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("address",-1));
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj(address,-1));
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("port",-1));
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewIntObj((int) port));

	/* Socket type */
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("type",-1));
	switch(rp->ai_socktype) {
	case 0:
	    str = "any";
	    break;
	case SOCK_STREAM:
	    str = "tcp";
	    break;
	case SOCK_DGRAM:
	    str = "udp";
	    break;
	case SOCK_RAW:
	    str = "raw";
	    break;
	default:
	    str = "other";
	}
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj(str,-1));

	/* Protocol: IPPROTO_UDP,  IPPROTO_TCP*/
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("protocol",-1));
	protocol = getprotobynumber(rp->ai_protocol);
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj(protocol->p_name,-1));
	
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj("protocol2",-1));
	switch(rp->ai_protocol) {
	case IPPROTO_TCP:
	    str = "tcp";
	    break;
	case IPPROTO_UDP:
	    str = "udp";
	    break;
	default:
	    str = "other";
	}
	Tcl_ListObjAppendElement(interp, listObj, Tcl_NewStringObj(str,-1));
	Tcl_ListObjAppendElement(interp, resultObj, listObj);
    }

    Tcl_SetObjResult(interp, resultObj);
    freeaddrinfo(result);
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * Udp_GetNameInfo --
 *  Get hostname for address
 *
 * ----------------------------------------------------------------------
 */
int Udp_GetNameInfo(ClientData clientData, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    char hostname[1024] = "";
    int family = AF_INET, err;

    Tcl_ResetResult(interp);

    /* Validate argc */
    if (objc < 2 || objc > 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "address ?ipv6?");
	return TCL_ERROR;
    } else if (objc == 3) {
	family = AF_INET6;
    }

    /* Get input address */
    if (family == AF_INET) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = family;

	if (inet_pton(family, Tcl_GetString(objv[1]), &sa.sin_addr) != 1) {
	    Tcl_AppendResult(interp, "Invalid IPv4 address ", Tcl_GetString(objv[1]), (char *) NULL);
	    return TCL_ERROR;
	}
	err = getnameinfo((const struct sockaddr *)&sa, sizeof(sa), hostname, 1024, NULL, 0, 0);

    } else {
	struct sockaddr_in6 sa;
	sa.sin6_family = family;
	memset(&sa, 0, sizeof(sa));

	if (inet_pton(family, Tcl_GetString(objv[1]), &sa.sin6_addr) != 1) {
	    Tcl_AppendResult(interp, "Invalid IPv6 address ", Tcl_GetString(objv[1]), (char *) NULL);
	    return TCL_ERROR;
	}
	err = getnameinfo((const struct sockaddr *)&sa, sizeof(sa), hostname, 1024, NULL, 0, 0);
    }

    /* Convert to host and service */
    if (err != 0) {
	Tcl_AppendResult(interp, "Get name info returned error: ", gai_strerror(err), (char *) NULL);
	return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, Tcl_NewStringObj(hostname,-1));
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * Build Info Command --
 *
 *	Create command to return build info for package.
 *
 * Results:
 *	A standard Tcl result
 *
 * Side effects:
 *	Created build-info command.
 *
 *----------------------------------------------------------------------
 */
 
#ifndef STRINGIFY
#  define STRINGIFY(x) STRINGIFY1(x)
#  define STRINGIFY1(x) #x
#endif
 
int
BuildInfoCommand(Tcl_Interp* interp) {
    Tcl_CmdInfo info;

    if (Tcl_GetCommandInfo(interp, "::tcl::build-info", &info)) {
	Tcl_CreateObjCommand(interp, "::udp::build-info", info.objProc, (void *)(
		PACKAGE_VERSION "+" STRINGIFY(UDP_VERSION_UUID)
#if defined(__clang__) && defined(__clang_major__)
			    ".clang-" STRINGIFY(__clang_major__)
#if __clang_minor__ < 10
			    "0"
#endif
			    STRINGIFY(__clang_minor__)
#endif
#if defined(__cplusplus) && !defined(__OBJC__)
			    ".cplusplus"
#endif
#ifndef NDEBUG
			    ".debug"
#endif
#if !defined(__clang__) && !defined(__INTEL_COMPILER) && defined(__GNUC__)
			    ".gcc-" STRINGIFY(__GNUC__)
#if __GNUC_MINOR__ < 10
			    "0"
#endif
			    STRINGIFY(__GNUC_MINOR__)
#endif
#ifdef __INTEL_COMPILER
			    ".icc-" STRINGIFY(__INTEL_COMPILER)
#endif
#ifdef TCL_MEM_DEBUG
			    ".memdebug"
#endif
#if defined(_MSC_VER)
			    ".msvc-" STRINGIFY(_MSC_VER)
#endif
#ifdef USE_NMAKE
			    ".nmake"
#endif
#ifndef TCL_CFG_OPTIMIZED
			    ".no-optimize"
#endif
#ifdef __OBJC__
			    ".objective-c"
#if defined(__cplusplus)
			    "plusplus"
#endif
#endif
#ifdef TCL_CFG_PROFILED
			    ".profile"
#endif
#ifdef PURIFY
			    ".purify"
#endif
#ifdef STATIC_BUILD
			    ".static"
#endif
		), NULL);
    }
    return TCL_OK;
}

/*
 *----------------------------------------------------------------------------
 *
 * udpInit --
 *
 *	This procedure is the main initialization point of the UDP
 *	extension.
 *
 * Results:
 *	Returns a standard Tcl completion code, and leaves an error
 *	message in the interp's result if an error occurs.
 *
 * Side effects:
 *	Adds a command to the Tcl interpreter.
 *
 *----------------------------------------------------------------------------
 */

#if TCL_MAJOR_VERSION > 8
#define MIN_VERSION "9.0"
#else
#define MIN_VERSION "8.5"
#endif

int Udp_Init(Tcl_Interp *interp) {
#ifdef _WIN32
    ThreadSpecificData *tsdPtr;
#elif defined(DEBUG)
    dbg = fopen("udp.dbg", "wt");
#endif

#ifdef USE_TCL_STUBS
    if (Tcl_InitStubs(interp, MIN_VERSION, 0) == NULL) {
	return TCL_ERROR;
    }
#endif
    if (Tcl_PkgRequire(interp, "Tcl", MIN_VERSION, 0) == NULL) {
	return TCL_ERROR;
    }

#ifdef _WIN32
    if (Udp_WinHasSockets(interp) != TCL_OK) {
	return TCL_ERROR;
    }

    tsdPtr = (ThreadSpecificData *) Tcl_GetThreadData(&dataKey, sizeof(ThreadSpecificData));
    if (!tsdPtr->sourceInit) {
	tsdPtr->sourceInit = 1;
    Tcl_CreateEventSource(UDP_SetupProc, UDP_CheckProc, NULL);
	Tcl_CreateThreadExitHandler(UDP_ExitProc, NULL);
    }

    /* Exit handler */
    Tcl_CreateExitHandler(ExitSockets, NULL);
#endif

    /* Create namespace */
    Tcl_CreateNamespace(interp, "::udp", NULL, NULL);

    /* Create package commands */
    Tcl_CreateObjCommand(interp, "udp_open", udpOpen, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "udp_conf", udpConf, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "udp_peek", udpPeek, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "udp", Udp_CmdProc, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "::udp::getaddrinfo", Udp_GetAddrInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateObjCommand(interp, "::udp::getnameinfo", Udp_GetNameInfo, (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);

    BuildInfoCommand(interp);

    return Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);
}

int Udp_SafeInit(Tcl_Interp *interp) {
    Tcl_SetResult(interp, "permission denied", TCL_STATIC);
    return TCL_ERROR;
}


/*
 * ----------------------------------------------------------------------
 *
 * Local variables:
 * mode: c
 * indent-tabs-mode: nil
 * End:
 */
