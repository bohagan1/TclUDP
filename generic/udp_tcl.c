/******************************************************************************
 * UDP Extension for Tcl 8.4
 *
 * Copyright 1999-2000 by Columbia University; all rights reserved
 *
 * Written by Xiaotao Wu
 * Last modified: 11/03/2000
 *
 * $Id: udp_tcl.c,v 1.14.2.2 2004/02/15 01:36:56 patthoyts Exp $
 ******************************************************************************/

#if defined(_DEBUG) && !defined(DEBUG)
#define DEBUG
#endif

#include "udp_tcl.h"

#define TCLUDP_PACKAGE_NAME    "udp"
#define TCLUDP_PACKAGE_VERSION VERSION

#ifdef WIN32
#include <stdlib.h>
#include <malloc.h>
typedef int socklen_t;
#else /* ! WIN32 */
#if defined(HAVE_SYS_IOCTL_H)
#include <sys/ioctl.h>
#elif defined(HAVE_SYS_FILIO_H)
#include <sys/filio.h>
#else
#error "Neither sys/ioctl.h nor sys/filio.h found. We need ioctl()"
#endif
#endif /* WIN32 */

/* Tcl 8.4 CONST support */
#ifndef CONST84
#define CONST84
#endif

/* define some Win32isms for Unix */
#ifndef WIN32
#define SOCKET int
#define INVALID_SOCKET -1
#define closesocket close
#define ioctlsocket ioctl
#endif /* WIN32 */

#ifdef DEBUG
#define UDPTRACE UdpTrace
#else
#define UDPTRACE 1 ? ((void)0) : UdpTrace
#endif

FILE *dbg;

#define MAXBUFFERSIZE 4096

static char errBuf[256];

/*
 * Channel handling procedures 
 */
static Tcl_DriverOutputProc    udpOutput;
static Tcl_DriverInputProc     udpInput;
static Tcl_DriverCloseProc     udpClose;
static Tcl_DriverWatchProc     udpWatch;
static Tcl_DriverGetHandleProc udpGetHandle;
static Tcl_DriverSetOptionProc udpSetOption;
static Tcl_DriverGetOptionProc udpGetOption;

/*
 * Tcl command procedures
 */
int Udp_CmdProc(ClientData, Tcl_Interp *, int, Tcl_Obj *CONST []);
int UdpPeek(ClientData , Tcl_Interp *, int , CONST84 char * []);

Tcl_Channel Tcl_OpenUdpSocket(Tcl_Interp *interp, CONST char *myaddr,
			      unsigned short myport);
Tcl_Channel Tcl_MakeUdpChannel(SOCKET sock);

/*
 * internal functions
 */
static void UdpTrace(const char *format, ...);
static SOCKET UdpCreateSock(int protocol);
static int  udpGetService(Tcl_Interp *interp, const char *service,
                          unsigned short *servicePort);
static int UdpGetProtocolFromObj(Tcl_Interp *interp, 
                                 Tcl_Obj *objPtr, int *resultPtr);

/*
 * Windows specific functions
 */
#ifdef WIN32

static int  UdpEventProc(Tcl_Event *evPtr, int flags);
static void UDP_SetupProc(ClientData data, int flags);
static void UDP_CheckProc(ClientData data, int flags);
static int  Udp_WinHasSockets(Tcl_Interp *interp);

/* FIX ME - these should be part of a thread/package specific structure */
static HANDLE waitForSock;
static HANDLE waitSockRead;
static HANDLE sockListLock;
static UdpState *sockList;
static UdpState *sockTail;

#endif /* ! WIN32 */

/*
 * This structure describes the channel type for accessing UDP.
 */
static Tcl_ChannelType Udp_ChannelType = {
    "udp",                 /* Type name.                                    */
    NULL,                  /* Set blocking/nonblocking behaviour. NULL'able */
    udpClose,              /* Close channel, clean instance data            */
    udpInput,              /* Handle read request                           */
    udpOutput,             /* Handle write request                          */
    NULL,                  /* Move location of access point.      NULL'able */
    udpSetOption,          /* Set options.                        NULL'able */
    udpGetOption,          /* Get options.                        NULL'able */
    udpWatch,              /* Initialize notifier                           */
    udpGetHandle,          /* Get OS handle from the channel.               */
};

/*
 * Package initialization:
 * tcl_findLibrary basename version patch initScript enVarName varName
 */

static char initScript[] =
    "tcl_findLibrary udp " TCLUDP_PACKAGE_VERSION " " TCLUDP_PACKAGE_VERSION
    " udp.tcl TCLUDP_LIBRARY udp_library";

/*
 * ----------------------------------------------------------------------
 * udpInit
 * ----------------------------------------------------------------------
 */
int
Udp_Init(Tcl_Interp *interp)
{
    int r = TCL_OK;
#if defined(DEBUG) && !defined(WIN32)
    dbg = fopen("udp.dbg", "wt");
#endif

#ifdef USE_TCL_STUBS
    Tcl_InitStubs(interp, "8.1", 0);
#endif

#ifdef WIN32
    if (Udp_WinHasSockets(interp) != TCL_OK) {
        return TCL_ERROR;
    }

    Tcl_CreateEventSource(UDP_SetupProc, UDP_CheckProc, NULL);
#endif

    Tcl_CreateCommand(interp, "udp_peek", UdpPeek , 
	(ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    
    Tcl_CreateObjCommand(interp, "udp", Udp_CmdProc,
	(ClientData)NULL, (Tcl_CmdDeleteProc *)NULL);
    
    Tcl_PkgProvide(interp, TCLUDP_PACKAGE_NAME, TCLUDP_PACKAGE_VERSION);

    return Tcl_Eval(interp, initScript);
}

/*
 * ----------------------------------------------------------------------
 * Udp_CmdProc --
 *  Provide a user interface similar to the Tcl stock 'socket' command.
 *
 *  udp ?options? ?port?
 *
 *  Options (from socket):
 *    -myaddr addr  which interface to create the socket on.
 *    -myport port  specify a port to use (0 or omitted means system chooses).
 *
 *    -reuseaddr    is specfied, permit address reuse.
 * ----------------------------------------------------------------------
 */
int
Udp_CmdProc(
    ClientData clientData,	/* Not used */
    Tcl_Interp *interp,		/* Current interpreter */
    int objc,			/* Number of arguments */
    Tcl_Obj *CONST objv[])	/* Arguments */
{
    static CONST char *options[] = {
	"-myaddr", "-myport", "-reuseaddr", "-protocol", "--", (char *)NULL
    };
    enum {
	OPT_MYADDR, OPT_MYPORT, OPT_REUSEADDR, OPT_PROTOCOL, OPT_END,
    };
    CONST char *myaddr = NULL;
    uint16_t myport = 0;
    int protocol = AF_INET;
    int reuseaddr = 0, index, i, r = TCL_OK;

    for (i = 1; r == TCL_OK && i < objc; i++) {
	if (Tcl_GetIndexFromObj(interp, objv[i], options,
	    "option", 0, &index) != TCL_OK) {
	    return TCL_ERROR;
	}
	
	switch (index) {
	    case OPT_MYADDR:
		++i;
		if (objc == i) {
		    Tcl_WrongNumArgs(interp, 1, objv, "-myaddr address");
		    r = TCL_ERROR;
		} else {
		    myaddr = Tcl_GetString(objv[i]);
		}
		break;

	    case OPT_MYPORT:
		++i;
		if (objc == i) {
		    Tcl_WrongNumArgs(interp, 1, objv, "-myport port");
		    r = TCL_ERROR;
		} else {
		    r = udpGetService(interp, Tcl_GetString(objv[i]), &myport);
		}
		break;

	    case OPT_REUSEADDR:
		++i;
		if (objc == i) {
		    Tcl_WrongNumArgs(interp, 1, objv, "-reuseaddr boolean");
		    r = TCL_ERROR;
		} else {
		    r = Tcl_GetBooleanFromObj(interp, objv[i], &reuseaddr);
		}
		break;

            case OPT_PROTOCOL:
                ++i;
		if (objc == i) {
		    Tcl_WrongNumArgs(interp, 1, objv, "-protocol ipv4|ipv6");
		    r = TCL_ERROR;
		} else {
		    r = UdpGetProtocolFromObj(interp, objv[i], &protocol);
		}
                break;

	    case OPT_END:
		break;

	    default:
		Tcl_ResetResult(interp);
		Tcl_AppendResult(interp, "bad option \"", 
		    Tcl_GetString(objv[i]), "\": must be -myaddr, -myport, "
		    "-reuseaddr or --", (char *)NULL);
		r = TCL_ERROR;
	}

	if (i == OPT_END) {
	    break;
	}
    }

    if (r == TCL_OK) {
	Tcl_Channel channel = NULL;
	SOCKET sock = UdpCreateSock(protocol);
	if (sock == INVALID_SOCKET) {
	    r = TCL_ERROR;
	} else {
	    channel =  Tcl_MakeUdpChannel(sock);
	    if (channel == NULL) {
		closesocket(sock);
		r = TCL_ERROR;
	    }
	}

	if (r == TCL_OK) {
	    Tcl_RegisterChannel(interp, channel);
	    Tcl_SetObjResult(interp, 
		Tcl_NewStringObj(Tcl_GetChannelName(channel), -1));
	}
    }
    return r;
}


static int
UdpGetProtocolFromObj(Tcl_Interp *interp, Tcl_Obj *objPtr, int *resultPtr)
{
    /* Odd values are AF_INET6 */
    static const char *protocolStrings[] = {
        "ipv4", "ipv6", "inet", "inet6", "4", "6", NULL
    };
    int af = 0;
    int r = Tcl_GetIndexFromObj(interp, objPtr, 
                                protocolStrings, "protocol", 0, &af);
    if (r == TCL_OK) {
        if (af & 1) {
            *resultPtr = AF_INET6;
        } else {
            *resultPtr = AF_INET;
        }
    }
    return r;
}

/*
 * ----------------------------------------------------------------------
 * UdpCreateSock --
 *
 *	Create a UDP socket and optionally specify the local address.
 *
 * ----------------------------------------------------------------------
 */

SOCKET
UdpCreateSock(int protocol)
{
    SOCKET sock;
    unsigned long nonblocking = 1;

    sock = socket(protocol, SOCK_DGRAM, 0);

    /* Make this a non-blocking socket */
    ioctlsocket(sock, FIONBIO, &nonblocking);
    return sock;
}

/*
 * UdpGetAddressFromObj --
 * Convert a Tcl object into a sockaddr_in socket name.
 * The Tcl object may be just a hostname, or a list
 * made up of {hostname port} where port can be the
 * service name or the port number.
 * Returns:
 * A standard tcl result.
 */

int
UdpGetAddressFromObj(
    Tcl_Interp *interp,
    Tcl_Obj *objPtr,
    struct sockaddr *saddr)
{
    int len, r = TCL_OK;
    unsigned short port = 0;
    CONST char *hostname = NULL;
    struct hostent *hostent;

    r = Tcl_ListObjLength(interp, objPtr, &len);
    if (r == TCL_OK) {
        if (len < 1 || len > 2) {
            Tcl_SetResult(interp, "wrong # args", TCL_STATIC);
            r = TCL_ERROR;
        } else {
            Tcl_Obj *hostPtr, *portPtr;
            
            Tcl_ListObjIndex(interp, objPtr, 0, &hostPtr);
            hostname = Tcl_GetString(hostPtr);
            
            if (len == 2) {
                Tcl_ListObjIndex(interp, objPtr, 1, &portPtr);            
                r = udpGetService(interp, Tcl_GetString(portPtr), &port);
            }
        }
    }

    if (r == TCL_OK) {

        if (saddr->sa_family == AF_INET6) {

            struct sockaddr_in6 * addr = (struct sockaddr_in6 *)saddr;

#if HAVE_GETADDRINFO
            char service[TCL_INTEGER_SPACE];
            struct addrinfo ai;
            struct addrinfo *pai = 0;

            sprintf(service, "%u", ntohs(port));
            memset(&ai, 0, sizeof(ai));
            ai.ai_family = PF_INET6;
            ai.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(hostname, service, &ai, &pai) == 0)
                memcpy(&addr->sin6_addr, pai->ai_addr, pai->ai_addrlen);
            freeaddrinfo(pai);
            
#elif HAVE_INET_PTON
            int n, errnum;
            n = inet_pton(AF_INET6, hostname, &addr->sin6_addr);
            if (n <= 0) {
                name = getipnodebyname(hostname, AF_INET6, AI_DEFAULT, &errnum);
            }
#endif
	    addr->sin6_family = AF_INET6;
	    addr->sin6_port = port;

        } else {

            struct sockaddr_in *addr = (struct sockaddr_in *)saddr;
	    addr->sin_family = AF_INET;
	    addr->sin_port = port;
	    if (hostname == NULL) {
	        addr->sin_addr.s_addr = INADDR_ANY;
	    } else {
	        addr->sin_addr.s_addr = inet_addr(hostname);
	        if (addr->sin_addr.s_addr == INADDR_NONE) {
		    hostent = gethostbyname(hostname);
		    if (hostent != NULL) {
		        memcpy(&addr->sin_addr, hostent->h_addr, 
			    (size_t)hostent->h_length);
		    } else {
		        Tcl_SetResult(interp, "host not found", TCL_STATIC);
		        return TCL_ERROR;
		    }
                }
	    }
	}
    }

    return r;
};

int
UdpGetObjFromAddress(
    Tcl_Interp *interp,
    struct sockaddr *saddr,
    Tcl_Obj **objPtrPtr)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)saddr;
    Tcl_Obj *parts[2];

    if (addr->sin_addr.s_addr == INADDR_NONE) {
        parts[0] = Tcl_NewStringObj(NULL, 0);
    } else {
        parts[0] = Tcl_NewStringObj(inet_ntoa(addr->sin_addr), -1);
    }
    parts[1] = Tcl_NewIntObj(ntohs(addr->sin_port));

    *objPtrPtr = Tcl_NewListObj(2, parts);
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 *
 * Tcl_OpenUdpSocket --
 *
 *	Opens a UDP socket and wraps it in a Tcl channel. There is no
 *	difference between client and server UDP sockets except for the
 *	port number. If the port is 0 then the system will select a port
 *	for us, otherwise we use the specified port.
 *
 * Results:
 *	The newly created channel is returned, or NULL. The interpreters
 *	error message will be set in the event of failure.
 *
 * Side effects:
 *	Opens a socket and registers a new channel in interp.
 *
 * ----------------------------------------------------------------------
 */

Tcl_Channel
Tcl_OpenUdpSocket(
    Tcl_Interp *interp,		/* May be NULL - used for returning errors */
    CONST char *myaddr,		/* Client-side address */
    unsigned short myport)	/* Client-side port in network byte order */
{
    /* FIX ME: can probably tell from the address info what protocol */
    Tcl_Channel chan = NULL;
    SOCKET sock = UdpCreateSock(AF_INET);
    if (sock != INVALID_SOCKET) {
	chan = Tcl_MakeUdpChannel(sock);
    }
    return chan;
}

/*
 * ----------------------------------------------------------------------
 * 
 * Tcl_MakeUdpChannel --
 *
 *	Creates a Tcl_Channel from an existing UDP socket.
 *
 * Results:
 *	Wraps a system socket in a Tcl_Channel structure.
 *
 * Side effects:
 *	Under Win32, the channel instance data is appended to the list
 *	of available listeners. For all platforms, a new channel is 
 *	registered.
 *
 * ----------------------------------------------------------------------
 */

Tcl_Channel
Tcl_MakeUdpChannel(SOCKET sock)
{
    UdpState *statePtr;
    char channelName[TCL_INTEGER_SPACE + 5];
    sockaddr_t name;
    int len = sizeof(sockaddr_t);
    
    statePtr = (UdpState *) ckalloc((unsigned) sizeof(UdpState));
    memset(statePtr, 0, sizeof(UdpState));
    statePtr->sock = sock;

    getsockname(sock, (struct sockaddr *)&name, &len);
    if (name.ss_family == AF_INET) {
        statePtr->saddr_local.ipv4.sin_addr.s_addr = INADDR_NONE;
        statePtr->saddr_remote.ipv4.sin_addr.s_addr = INADDR_NONE;
        statePtr->saddr_peer.ipv4.sin_addr.s_addr = INADDR_NONE;
    }

    sprintf(channelName, "sock%d", statePtr->sock);
    statePtr->channel = Tcl_CreateChannel(&Udp_ChannelType,
	channelName, (ClientData) statePtr,
	(TCL_READABLE | TCL_WRITABLE | TCL_MODE_NONBLOCKING));
    statePtr->doread = 1;

    len = sizeof(sockaddr_t);
    getsockname(sock, (struct sockaddr *)&statePtr->saddr_local, &len);

#ifdef WIN32
    statePtr->threadId = Tcl_GetCurrentThread();    
    statePtr->packetNum = 0;
    statePtr->next = NULL;
    statePtr->packets = NULL;
    statePtr->packetsTail = NULL;

    WaitForSingleObject(sockListLock, INFINITE);
    if (sockList == NULL) {
        sockList = sockTail = statePtr;
    } else {
        sockTail->next = statePtr;
        sockTail = statePtr;
    }

    UDPTRACE("Append %d to sockList\n", statePtr->sock);
    SetEvent(sockListLock);
    SetEvent(waitForSock);
#endif

    return statePtr->channel;
}

/*
 * ----------------------------------------------------------------------
 * UdpPeek --
 *  peek some data and set the peer information
 * ----------------------------------------------------------------------
 */
int
UdpPeek(ClientData clientData, Tcl_Interp *interp,
        int argc, CONST84 char * argv[])
{
#ifndef WIN32
    int buffer_size = 16;
    int actual_size, socksize;
    int sock;
    char message[17];
    sockaddr_t recvaddr;
    Tcl_Channel chan;
    UdpState *statePtr;
    
    chan = Tcl_GetChannel(interp, (char *)argv[1], NULL);
    if (chan == (Tcl_Channel) NULL) {
        return TCL_ERROR;
    }
    statePtr = (UdpState *) Tcl_GetChannelInstanceData(chan);
    sock = Tcl_GetChannelHandle (chan, (TCL_READABLE | TCL_WRITABLE), NULL);
    
    if (argc > 2) {
        buffer_size = atoi(argv[2]);
        if (buffer_size > 16) buffer_size = 16;
    }

    socksize = sizeof(sockaddr_t);
    actual_size = recvfrom(sock, message, buffer_size, MSG_PEEK,
                           (struct sockaddr *)&recvaddr, &socksize);
    
    if (actual_size < 0) {
        sprintf(errBuf, "udppeek error");
        Tcl_AppendResult(interp, errBuf, (char *)NULL);
        return TCL_ERROR;
    }
    memcpy(&statePtr->saddr_peer, &recvaddr, sizeof(recvaddr));
    message[actual_size]='\0';
    
    Tcl_ResetResult(interp);
    Tcl_AppendResult(interp, message, (char *)NULL);
    return TCL_OK;

#else /* WIN32 */
    Tcl_SetResult(interp, "udp_peek not implemented for this platform",
                  TCL_STATIC);
    return TCL_ERROR;
#endif /* ! WIN32 */
}

#ifdef WIN32
/*
 * ----------------------------------------------------------------------
 * UdpEventProc --
 *
 *  Raise an event from the UDP read thread to notify the Tcl interpreter
 *  that something has happened.
 *
 * ----------------------------------------------------------------------
 */
int
UdpEventProc(Tcl_Event *evPtr, int flags)
{
    UdpEvent *eventPtr = (UdpEvent *) evPtr;
    int mask = 0;
    
    mask |= TCL_READABLE;
    UDPTRACE("UdpEventProc\n");
    Tcl_NotifyChannel(eventPtr->chan, mask);
    return 1;
}

/*
 * ----------------------------------------------------------------------
 * UDP_SetupProc - called in Tcl_SetEventSource to do the setup step
 * ----------------------------------------------------------------------
 */
static void 
UDP_SetupProc(ClientData data, int flags) 
{
    UdpState *statePtr;
    Tcl_Time blockTime = { 0, 0 };
    
    /* UDPTRACE("setupProc\n"); */
    
    if (!(flags & TCL_FILE_EVENTS)) {
        return;
    }
    
    WaitForSingleObject(sockListLock, INFINITE);
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
        if (statePtr->packetNum > 0) {
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
void 
UDP_CheckProc(ClientData data, int flags) 
{
    UdpState *statePtr;
    UdpEvent *evPtr;
    int actual_size, socksize;
    int buffer_size = MAXBUFFERSIZE;
    char *message;
    sockaddr_t recvaddr;
    PacketList *p;
    
    /* synchronized */
    WaitForSingleObject(sockListLock, INFINITE);
    
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
        if (statePtr->packetNum > 0) {
            UDPTRACE("UDP_CheckProc\n");
            /* Read the data from socket and put it into statePtr */
            socksize = sizeof(recvaddr);
            memset(&recvaddr, 0, socksize);

            message = (char *)calloc(1, MAXBUFFERSIZE);
            if (message == NULL) {
                UDPTRACE("calloc error\n");
                exit(1);
            }
            
            actual_size = recvfrom(statePtr->sock, message, buffer_size, 0,
                                   (struct sockaddr *)&recvaddr, &socksize);
            SetEvent(waitSockRead);
            
            if (actual_size < 0) {
                UDPTRACE("UDP error - recvfrom %d\n", statePtr->sock);
                free(message);
            } else {
                p = (PacketList *)calloc(1, sizeof(struct PacketList));
                p->message = message;
                p->actual_size = actual_size;
                memcpy(&p->peer, &recvaddr, sizeof(recvaddr));
                p->next = NULL;
                
                if (statePtr->packets == NULL) {
                    statePtr->packets = p;
                    statePtr->packetsTail = p;
                } else {
                    statePtr->packetsTail->next = p;
                    statePtr->packetsTail = p;
                }
                
                UDPTRACE("Received %d bytes from through %d\n",
                         p->actual_size, statePtr->sock);
                //UDPTRACE("%s\n", p->message);
            }
            
            statePtr->packetNum--;
            statePtr->doread = 1;
            UDPTRACE("packetNum is %d\n", statePtr->packetNum);
            
            if (actual_size >= 0) {
                evPtr = (UdpEvent *) ckalloc(sizeof(UdpEvent));
                evPtr->header.proc = UdpEventProc;
                evPtr->chan = statePtr->channel;
                Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
                UDPTRACE("socket %d has data\n", statePtr->sock);
            }
        }
    }
    
    SetEvent(sockListLock);
}

/*
 * ----------------------------------------------------------------------
 * InitSockets
 * ----------------------------------------------------------------------
 */
static int
InitSockets() 
{
    WSADATA wsaData;

    /*
     * Load the socket DLL and initialize the function table.
     */
    
    if (WSAStartup(0x0002, &wsaData))
        return 0;
    
    return 1;
}

/*
 * ----------------------------------------------------------------------
 * SocketThread
 * ----------------------------------------------------------------------
 */
static DWORD WINAPI
SocketThread(LPVOID arg) 
{
    fd_set readfds; /* variable used for select */
    struct timeval timeout;
    UdpState *statePtr;
    int found;
    int sockset;
    
    FD_ZERO(&readfds);
    
    UDPTRACE("In socket thread\n");
    
    while (1) {
        FD_ZERO(&readfds);
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;
        /* synchronized */
        WaitForSingleObject(sockListLock, INFINITE);
        
        /* no socket, just wait, use event */
        if (sockList == NULL) {
            SetEvent(sockListLock);
            UDPTRACE("Wait for adding socket\n");
            WaitForSingleObject(waitForSock, INFINITE);
            /* synchronized */
            WaitForSingleObject(sockListLock, INFINITE);
        }
        
        /* set each socket for select */
        for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
            FD_SET((SOCKET)statePtr->sock, &readfds);
            /* UDPTRACE("SET sock %d\n", statePtr->sock); */
        }
        
        SetEvent(sockListLock);
        /* UDPTRACE("Wait for select\n"); */
        /* block here */
        found = select(0, &readfds, NULL, NULL, &timeout);
        /* UDPTRACE("select end\n"); */
        
        if (found <= 0) {
            /* We closed the socket during select or time out */
            continue;
        }
        
        UDPTRACE("Packet comes in\n");
        
        WaitForSingleObject(sockListLock, INFINITE);
        sockset = 0;
        for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
            if (FD_ISSET(statePtr->sock, &readfds)) {
                statePtr->packetNum++;
                sockset++;
                UDPTRACE("sock %d is set\n", statePtr->sock);
                break;
            }
        }
        SetEvent(sockListLock);
        
        /* wait for the socket data was read */
        if (sockset > 0) {
            UDPTRACE( "Wait sock read\n");
            /* alert the thread to do event checking */
            Tcl_ThreadAlert(statePtr->threadId);
            WaitForSingleObject(waitSockRead, INFINITE);
            UDPTRACE("Sock read finished\n");
        }
    }
}

/*
 * ----------------------------------------------------------------------
 * Udp_WinHasSockets --
 * ----------------------------------------------------------------------
 */
int
Udp_WinHasSockets(Tcl_Interp *interp)
{
    static int initialized = 0; /* 1 if the socket sys has been initialized. */
    static int hasSockets = 0;  /* 1 if the system supports sockets. */
    HANDLE socketThread;
    DWORD id;
    
    if (!initialized) {
        OSVERSIONINFO info;
        
        initialized = 1;
        
        /*
         * Find out if we're running on Win32s.
         */
        
        info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        GetVersionEx(&info);
        
        /*
         * Check to see if Sockets are supported on this system.  Since
         * win32s panics if we call WSAStartup on a system that doesn't
         * have winsock.dll, we need to look for it on the system first.
         * If we find winsock, then load the library and initialize the
         * stub table.
         */
        
        if ((info.dwPlatformId != VER_PLATFORM_WIN32s)
            || (SearchPath(NULL, "WINSOCK", ".DLL", 0, NULL, NULL) != 0)) {
            hasSockets = InitSockets();
        }
        
        /*
         * Start the socketThread window and set the thread priority of the
         * socketThread as highest
         */
        
        sockList = NULL;
        sockTail = NULL;
        waitForSock  = CreateEvent(NULL, FALSE, FALSE, NULL);
        waitSockRead = CreateEvent(NULL, FALSE, FALSE, NULL);
        sockListLock = CreateEvent(NULL, FALSE, TRUE, NULL);
        
        socketThread = CreateThread(NULL, 8000, SocketThread, NULL, 0, &id);
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
        Tcl_AppendResult(interp, "sockets are not available on this system",
                         NULL);
    }
    return TCL_ERROR;
}

#endif /* ! WIN32 */

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
static int 
udpClose(ClientData instanceData, Tcl_Interp *interp)
{
    int sock;
    int errorCode = 0;
    UdpState *statePtr = (UdpState *) instanceData;
#ifdef WIN32
    UdpState *p, *q;
#endif /* ! WIN32 */
    
    sock = statePtr->sock;

#ifdef WIN32
    /* remove the statePtr from the list */
    WaitForSingleObject(sockListLock, INFINITE);

    for (p = q = sockList; p != NULL; q = p, p = p->next) {
	if (p->sock == sock) {
	    UDPTRACE("Remove sock%d from list\n", sock);
	    if (p == sockList) {
		sockList = q = p->next;
	    } else {
		q->next = p->next;
	    }
	    if (p == sockTail) {
		sockTail = q;
	    }
	    break;
	}
    }

#endif /* ! WIN32 */
    
    if (closesocket(sock) < 0) {
        errorCode = errno;
    }
    ckfree((char *) statePtr);
    if (errorCode != 0) {
#ifndef WIN32
        sprintf(errBuf, "udpClose: %d, error: %d\n", sock, errorCode);
#else
        sprintf(errBuf, "udpClose: %d, error: %d\n", sock, WSAGetLastError());
#endif
        UDPTRACE("UDP error - close %d", sock);
    } else {
        UDPTRACE("Close socket %d\n", sock);
    }
    
#ifdef WIN32
    SetEvent(sockListLock);
#endif
    
    return errorCode;
}
 
/*
 * ----------------------------------------------------------------------
 * udpWatch --
 * ----------------------------------------------------------------------
 */
static void 
udpWatch(ClientData instanceData, int mask)
{
#ifndef WIN32
    UdpState *statePtr = (UdpState *) instanceData;
    if (mask) {
        UDPTRACE("Tcl_CreateFileHandler\n");
        Tcl_CreateFileHandler(statePtr->sock, mask,
                              (Tcl_FileProc *) Tcl_NotifyChannel,
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
static int
udpGetHandle(ClientData instanceData, int direction, ClientData *handlePtr)
{
    UdpState *statePtr = (UdpState *) instanceData;
    UDPTRACE("udpGetHandle %ld\n", (long)statePtr->sock);
    *handlePtr = (ClientData) statePtr->sock;
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpOutput--
 * ----------------------------------------------------------------------
 */
static int
udpOutput(ClientData instanceData, CONST84 char *buf, int toWrite, int *errorCode)
{
    UdpState *statePtr = (UdpState *) instanceData;
    int written;
    int socksize = sizeof(sockaddr_t);
    sockaddr_t name;
    
    *errorCode = 0;
    errno = 0;
    
    if (toWrite > MAXBUFFERSIZE) {
        UDPTRACE("UDP error - MAXBUFFERSIZE");
        return -1;
    }

    getsockname(statePtr->sock, (struct sockaddr *)&name, &socksize);

    if ((name.ss_family == AF_INET
	&& statePtr->saddr_remote.ipv4.sin_addr.s_addr == INADDR_NONE)
#ifdef SIPC_IPV6
	|| (name.ss_family == AF_INET6 
            && IN6_IS_ADDR_UNSPECIFIED(&statePtr->saddr_remote.ipv6.sin6_addr))
#endif
	) {
        UDPTRACE("UDP error - no host set");
        return -1;
    }

    socksize = sizeof(statePtr->saddr_remote);
    written = sendto(statePtr->sock, buf, toWrite, 0,
                     (const struct sockaddr *)&statePtr->saddr_remote, socksize);
    if (written < 0) {
        UDPTRACE("UDP error - sendto");
        return -1;
    }

    UDPTRACE("Send %d through socket %u\n", written, statePtr->sock);
    
    return written;
}

/*
 * ----------------------------------------------------------------------
 * udpInput
 * ----------------------------------------------------------------------
 */
static int 
udpInput(ClientData instanceData, char *buf, int bufSize, int *errorCode) 
{
    UdpState *statePtr = (UdpState *) instanceData;
    int bytesRead;

#ifdef WIN32
    PacketList *packets;
#else /* ! WIN32 */
    int socksize;
    int port;
    int buffer_size = MAXBUFFERSIZE;
    char *remotehost;
    int sock = statePtr->sock;
    char number[128];
    sockaddr_t recvaddr;
#endif /* ! WIN32 */
    
    UDPTRACE("In udpInput\n");
    
    /*
     * The caller of this function is looking for a stream oriented
     * system, so it keeps calling the function until no bytes are
     * returned, and then appends all the characters together.  This
     * is not what we want from UDP, so we fake it by returning a
     * blank every other call.  whenever the doread variable is 1 do
     * a normal read, otherwise just return 0.
     */
    if (statePtr->doread == 0) {
        statePtr->doread = 1;  /* next time we want to behave normally */
        *errorCode = EAGAIN;   /* pretend that we would block */
        UDPTRACE("Pretend we would block\n");
        return 0;
    }
    
    *errorCode = 0;
    errno = 0;
    
    if (bufSize == 0) {
        return 0;
    }
    
#ifdef WIN32
    packets = statePtr->packets;
    UDPTRACE("udp_recv\n");

    if (packets == NULL) {
        UDPTRACE("packets is NULL\n");
        return 0;
    }
    memcpy(buf, packets->message, packets->actual_size);
    free((char *) packets->message);
    UDPTRACE("udp_recv message\n%s", buf);
    bufSize = packets->actual_size;
    memcpy(&statePtr->saddr_peer, &packets->peer, sizeof(packets->peer));
    statePtr->packets = packets->next;
    free((char *) packets);
    bytesRead = bufSize;
#else /* ! WIN32 */
    socksize = sizeof(recvaddr);
    memset(number, 0, 128);
    memset(&recvaddr, 0, socksize);
    
    bytesRead = recvfrom(sock, buf, buffer_size, 0,
                         (struct sockaddr *)&recvaddr, &socksize);
    if (bytesRead < 0) {
        UDPTRACE("UDP error - recvfrom %d\n", sock);
        *errorCode = errno;
        return -1;
    }
    memcpy(&statePtr->saddr_peer, &recvaddr, sizeof(recvaddr));
    
#ifdef SIPC_IPV6
    inet_ntop(recvaddr.ipv6.sin_family,
              &statePtr->saddr_peer.ipv6.sin_addr, 
              number, 128);
#else
    inet_ntop(statePtr->saddr_peer.ipv4.sin_family, 
              &statePtr->saddr_peer.ipv4.sin_addr, 
              number, 128);
#endif

    UDPTRACE("remotehost: %s:%d\n", number, ntohs(recvaddr.ipv6.sin6_port));

#endif /* ! WIN32 */
    
    /* we don't want to return anything next time */
    if (bytesRead > 0) {
        buf[bytesRead] = '\0';
        statePtr->doread = 0;
    }
    
    UDPTRACE("udpInput end: %d, %s\n", bytesRead, buf);
    
    if (bytesRead > -1) {
        return bytesRead;
    }
    
    *errorCode = errno;
    return -1;
}

/*
 * ----------------------------------------------------------------------
 *
 * UdpMulticast --
 *
 * Action should be IP_ADD_MEMBERSHIP | IP_DROP_MEMBERSHIP 
 *
 */
int
UdpMulticast(Tcl_Interp *interp,
    SOCKET sock, CONST84 char *grp, int action)
{
    struct ip_mreq mreq;
    struct hostent *name;

    memset(&mreq, 0, sizeof(mreq));

    mreq.imr_multiaddr.s_addr = inet_addr(grp);
    if (mreq.imr_multiaddr.s_addr == -1) {
        name = gethostbyname(grp);
        if (name == NULL) {
            Tcl_SetResult(interp, "invalid hostname", TCL_STATIC);
            return TCL_ERROR;
        }
        memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, 
               sizeof(mreq.imr_multiaddr));
    }
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(sock, IPPROTO_IP, action,
                   (const char*)&mreq, sizeof(mreq)) < 0) {
	Tcl_SetResult(interp, "error changind multicast group", TCL_STATIC);
        return TCL_ERROR;
    }
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpGetOption --
 * ----------------------------------------------------------------------
 */
static int 
udpGetOption(ClientData instanceData, Tcl_Interp *interp,
             CONST84 char *optionName, Tcl_DString *optionValue)
{
    UdpState *statePtr = (UdpState *)instanceData;
    CONST84 char * options = 
        "sockname remote peer broadcast reuseaddr";
    int r = TCL_OK;

    if (optionName == NULL) {

        Tcl_DStringAppend(optionValue, " -sockname ", -1);
        udpGetOption(instanceData, interp, "-sockname", optionValue);
        Tcl_DStringAppend(optionValue, " -remote ", -1);
        udpGetOption(instanceData, interp, "-remote", optionValue);
        Tcl_DStringAppend(optionValue, " -peer ", -1);
        udpGetOption(instanceData, interp, "-peer", optionValue);
        Tcl_DStringAppend(optionValue, " -broadcast ", -1);
        udpGetOption(instanceData, interp, "-broadcast", optionValue);
        Tcl_DStringAppend(optionValue, " -reuseaddr ", -1);
        udpGetOption(instanceData, interp, "-reuseaddr", optionValue);

    } else {

        Tcl_DString ds, dsInt;
        Tcl_DStringInit(&ds);
        Tcl_DStringInit(&dsInt);

        if (!strcmp("-sockname", optionName)) {

            Tcl_Obj *nameObj;
            UdpGetObjFromAddress(interp, (struct sockaddr *)&statePtr->saddr_local, &nameObj);
            Tcl_DStringAppend(&ds, Tcl_GetString(nameObj), -1);

        } else if (!strcmp("-remote", optionName)) {

            Tcl_Obj *nameObj;
            UdpGetObjFromAddress(interp, (struct sockaddr *)&statePtr->saddr_remote, &nameObj);
            Tcl_DStringAppend(&ds, Tcl_GetString(nameObj), -1);

        } else if (!strcmp("-peer", optionName)) {

            Tcl_Obj *nameObj;
            UdpGetObjFromAddress(interp, (struct sockaddr *)&statePtr->saddr_peer, &nameObj);
            Tcl_DStringAppend(&ds, Tcl_GetString(nameObj), -1);

        } else if (!strcmp("-broadcast", optionName)) {

            int tmp = 1;
            socklen_t optlen = sizeof(int);
            if (getsockopt(statePtr->sock, SOL_SOCKET, SO_BROADCAST, 
                           (char *)&tmp, &optlen)) {
                Tcl_SetResult(interp, "error in setsockopt SO_BROADCAST", TCL_STATIC);
                r = TCL_ERROR;
            } else {
                Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
                sprintf(Tcl_DStringValue(&ds), "%d", tmp);
            }

        } else if (!strcmp("-reuseaddr", optionName)) {

            int tmp = 1;
            socklen_t optlen = sizeof(int);
            if (getsockopt(statePtr->sock, SOL_SOCKET, SO_REUSEADDR, 
                           (char *)&tmp, &optlen)) {
                Tcl_SetResult(interp, "error in setsockopt SO_REUSEADDR", TCL_STATIC);
                r = TCL_ERROR;
            } else {
                Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
                sprintf(Tcl_DStringValue(&ds), "%d", tmp);
            }

        } else {
            r = Tcl_BadChannelOption(interp, optionName, options);
        }
        
        if (r == TCL_OK) {
            Tcl_DStringAppendElement(optionValue, Tcl_DStringValue(&ds));
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
static int
udpSetOption(ClientData instanceData, Tcl_Interp *interp,
             CONST84 char *optionName, CONST84 char *newValue)
{
    UdpState *statePtr = (UdpState *)instanceData;
    CONST84 char * options = "sockname remote mcastadd mcastdrop broadcast reuseaddr";
    int r = TCL_OK;

    if (!strcmp("-sockname", optionName)) {
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));

	r = UdpGetAddressFromObj(interp, Tcl_NewStringObj(newValue, -1),
	    (struct sockaddr *)&addr);
	if (r == TCL_OK) {
	    int e = bind(statePtr->sock, (struct sockaddr *)&addr,
		sizeof(struct sockaddr_in));
	    if (e < 0) {
		Tcl_SetErrno(e);
                Tcl_SetResult(interp, "bind error", TCL_STATIC);
		r = TCL_ERROR;
	    } else {
		int len = sizeof(statePtr->saddr_local);
                getsockname(statePtr->sock, (struct sockaddr *)&statePtr->saddr_local, &len);
	    }
	}

    } else if (!strcmp("-remote", optionName)) {

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));

	r = UdpGetAddressFromObj(interp, Tcl_NewStringObj(newValue, -1),
	    (struct sockaddr *)&addr);
	if (r == TCL_OK) {
	    memcpy(&statePtr->saddr_remote, &addr, sizeof(addr));
	}

    } else if (!strcmp("-mcastadd", optionName)) {

        r = UdpMulticast(interp, statePtr->sock, newValue, IP_ADD_MEMBERSHIP);

    } else if (!strcmp("-mcastdrop", optionName)) {

        r = UdpMulticast(interp, statePtr->sock, newValue, IP_DROP_MEMBERSHIP);

    } else if (!strcmp("-broadcast", optionName)) {

        int tmp = 1;
        r = Tcl_GetInt(interp, newValue, &tmp);
        if (r == TCL_OK) {
            if (setsockopt(statePtr->sock, SOL_SOCKET, SO_BROADCAST, 
                           (const char *)&tmp, sizeof(int))) {
                UDPTRACE("UDP error - setsockopt\n");
                Tcl_SetResult(interp, "udp - setsockopt SO_BROADCAST", TCL_STATIC);
                r = TCL_ERROR;
            } else {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(tmp));
            }
        }

    } else if (!strcmp("-reuseaddr", optionName)) {
        /*
         * FIX ME: this doesn't work here.
         * what we want is a udp command and to be able to specify this to that
         * command. This will only work if re-attaching a client socket.
         * (if we can do that)
         */
        int tmp = 1;
        r = Tcl_GetInt(interp, newValue, &tmp);
        if (r == TCL_OK) {
            if (setsockopt(statePtr->sock, SOL_SOCKET, SO_REUSEADDR, 
                           (const char *)&tmp, sizeof(int))) {
                UDPTRACE("UDP error - setsockopt\n");
                Tcl_SetResult(interp, "udp - setsockopt SO_REUSEADDR", TCL_STATIC);
                r = TCL_ERROR;
            } else {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(tmp));
            }
        }

    } else {

        r = Tcl_BadChannelOption(interp, optionName, options);

    }

    return r;
}

/*
 * ----------------------------------------------------------------------
 * UdpTrace --
 * ----------------------------------------------------------------------
 */
static void
UdpTrace(const char *format, ...)
{
    va_list args;
    
#ifdef WIN32

    static char buffer[1024];
    va_start (args, format);
    _vsnprintf(buffer, 1023, format, args);
    OutputDebugString(buffer);

#else /* ! WIN32 */

    va_start (args, format);
    vfprintf(dbg, format, args);
    fflush(dbg);

#endif /* ! WIN32 */

    va_end(args);
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
static int
udpGetService(Tcl_Interp *interp, const char *service,
              unsigned short *servicePort)
{
    struct servent *sv = NULL;
    char *remainder = NULL;
    int r = TCL_OK;

    sv = getservbyname(service, "udp");
    if (sv != NULL) {
        *servicePort = sv->s_port;
    } else {
        *servicePort = htons((unsigned short)strtol(service, &remainder, 0));
        if (remainder == service) {
            Tcl_ResetResult(interp);
            Tcl_AppendResult(interp, "invalid service name: \"", service,
                             "\" could not be converted to a port number",
                             TCL_STATIC);
            r = TCL_ERROR;
        }
    }
    return r;
}

/*
 * ----------------------------------------------------------------------
 *
 * Local variables:
 * mode: c
 * indent-tabs-mode: nil
 * End:
 */
