/******************************************************************************
 * UDP Extension for Tcl 8.4
 *
 * Copyright 1999-2000 by Columbia University; all rights reserved
 *
 * Written by Xiaotao Wu
 * Last modified: 11/03/2000
 *
 * $Id: udp_tcl.c,v 1.10 2004/02/09 12:02:32 patthoyts Exp $
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
#define UDPTRACE udpTrace
#else
#define UDPTRACE 1 ? ((void)0) : udpTrace
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
int udpOpen(ClientData , Tcl_Interp *, int , CONST84 char * []);
int udpConf(ClientData , Tcl_Interp *, int , CONST84 char * []);
int udpPeek(ClientData , Tcl_Interp *, int , CONST84 char * []);

/*
 * internal functions
 */
static void udpTrace(const char *format, ...);
static int  udpGetService(Tcl_Interp *interp, const char *service,
                          unsigned short *servicePort);

/*
 * Windows specific functions
 */
#ifdef WIN32

int  UdpEventProc(Tcl_Event *evPtr, int flags);
static void UDP_SetupProc(ClientData data, int flags);
void UDP_CheckProc(ClientData data, int flags);
int  Udp_WinHasSockets(Tcl_Interp *interp);

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
#ifdef SIPC_IPV6
    "udp6",                /* Type name.                                    */
#else 
    "udp",                 /* Type name.                                    */
#endif 
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
#endif

    Tcl_CreateCommand(interp, "udp_open", udpOpen , 
                      (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateCommand(interp, "udp_conf", udpConf , 
                      (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    Tcl_CreateCommand(interp, "udp_peek", udpPeek , 
                      (ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
    
    r = Tcl_PkgProvide(interp, TCLUDP_PACKAGE_NAME, TCLUDP_PACKAGE_VERSION);
    return r;
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
int
Udp_CmdProc(ClientData clientData, Tcl_Interp *interp,
            int objc, Tcl_Obj *CONST objv[])
{
    Tcl_SetResult(interp, "E_NOTIMPL", TCL_STATIC);
    return TCL_ERROR;
}

/*
 * Probably we should provide an equivalent to the C API for TCP.
 *
 * Tcl_Channel Tcl_OpenUdpClient(interp, port, host, myaddr, myport, async);
 * Tcl_Channel Tcl_OpenUdpServer(interp, port, myaddr, proc, clientData);
 * Tcl_Channel Tcl_MakeUdpClientChannel(sock);
 */

/*
 * ----------------------------------------------------------------------
 * udpOpen --
 *
 *  opens a UDP socket and addds the file descriptor to the tcl
 *  interpreter
 * ----------------------------------------------------------------------
 */
int
udpOpen(ClientData clientData, Tcl_Interp *interp,
        int argc, CONST84 char * argv[]) 
{
    int sock;
    char channelName[20];
    UdpState *statePtr;
    uint16_t localport = 0;
#ifdef SIPC_IPV6
    struct sockaddr_in6  addr, sockaddr;
#else
    struct sockaddr_in  addr, sockaddr;
#endif
    unsigned long status = 1;
    int len;
    
    /*
     *    Tcl_ChannelType *Udp_ChannelType;
     *    Udp_ChannelType = (Tcl_ChannelType *) ckalloc((unsigned) sizeof(Tcl_ChannelType));
     *    memset(Udp_ChannelType, 0, sizeof(Tcl_ChannelType));
     * #ifdef SIPC_IPV6
     *    Udp_ChannelType->typeName = strdup("udp6");
     *#else 
     *    Udp_ChannelType->typeName = strdup("udp");
     *#endif
     *    Udp_ChannelType->blockModeProc = NULL;
     *    Udp_ChannelType->closeProc = udpClose;
     *    Udp_ChannelType->inputProc = udpInput;
     *    Udp_ChannelType->outputProc = udpOutput;
     *    Udp_ChannelType->seekProc = NULL;
     *    Udp_ChannelType->setOptionProc = udpSetOption;
     *    Udp_ChannelType->getOptionProc = udpGetOption;
     *    Udp_ChannelType->watchProc = udpWatch;
     *    Udp_ChannelType->getHandleProc = udpGetHandle;
     *    Udp_ChannelType->close2Proc = NULL;
     */

    if (argc >= 2) {
        if (udpGetService(interp, argv[1], &localport) != TCL_OK)
            return TCL_ERROR;
    }
    
    memset(channelName, 0, sizeof(channelName));
    
#ifdef SIPC_IPV6
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
#else
    sock = socket(AF_INET, SOCK_DGRAM, 0);
#endif
    if (sock < 0) {
        sprintf(errBuf,"%s","udp - socket");
        UDPTRACE("UDP error - socket\n");
        Tcl_AppendResult(interp, errBuf, (char *)NULL);
        return TCL_ERROR;
    }
    memset(&addr, 0, sizeof(addr));
#ifdef SIPC_IPV6
    addr.sin6_family = AF_INET6;
    addr.sin6_port = localport;
#else
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = localport;
#endif
    if (bind(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sprintf(errBuf,"%s","udp - bind");
        UDPTRACE("UDP error - bind\n");
        Tcl_AppendResult(interp, errBuf, (char *)NULL);
        return TCL_ERROR;
    }

    ioctlsocket(sock, FIONBIO, &status);

    if (localport == 0) {
        len = sizeof(sockaddr);
        getsockname(sock, (struct sockaddr *)&sockaddr, &len);
#ifdef SIPC_IPV6
        localport = sockaddr.sin6_port;
#else
        localport = sockaddr.sin_port;
#endif
    }
    
    UDPTRACE("Open socket %d. Bind socket to port %d\n", 
             sock, ntohs(localport));

    statePtr = (UdpState *) ckalloc((unsigned) sizeof(UdpState));
    memset(statePtr, 0, sizeof(UdpState));
    statePtr->sock = sock;
    sprintf(channelName, "sock%d", statePtr->sock);
    statePtr->channel = Tcl_CreateChannel(&Udp_ChannelType, channelName,
                                          (ClientData) statePtr,
                                          (TCL_READABLE | TCL_WRITABLE | TCL_MODE_NONBLOCKING));
    statePtr->doread = 1;
    statePtr->localport = localport;
    Tcl_RegisterChannel(interp, statePtr->channel);
#ifdef WIN32
    statePtr->threadId = Tcl_GetCurrentThread();    
    statePtr->packetNum = 0;
    statePtr->next = NULL;
    statePtr->packets = NULL;
    statePtr->packetsTail = NULL;
    Tcl_CreateEventSource(UDP_SetupProc, UDP_CheckProc, NULL);
#endif
    /* Tcl_SetChannelOption(interp, statePtr->channel, "-blocking", "0"); */
    Tcl_AppendResult(interp, channelName, (char *)NULL);
#ifdef WIN32
    WaitForSingleObject(sockListLock, INFINITE);
    if (sockList == NULL) {
        sockList = statePtr;
        sockTail = statePtr;
    } else {
        sockTail->next = statePtr;
        sockTail = statePtr;
    }

    UDPTRACE("Append %d to sockList\n", statePtr->sock);
    SetEvent(sockListLock);
    SetEvent(waitForSock);
#endif
    return TCL_OK;
}

/*
 * ----------------------------------------------------------------------
 * udpConf --
 * ----------------------------------------------------------------------
 */
int
udpConf(ClientData clientData, Tcl_Interp *interp,
        int argc, CONST84 char * argv[]) 
{
    Tcl_Channel chan;
    UdpState *statePtr;
    char *result;
    char buf[128];
    struct hostent *name;
    struct ip_mreq mreq;
    struct sockaddr_in maddr;
    int sock;
    
    if (argc != 4 && argc != 3) {
        result = "udpConf fileId [-mcastadd] [-mcastdrop] groupaddr | udpConf fileId remotehost remoteport | udpConf fileId [-myport] [-remote] [-peer]";
        Tcl_SetResult (interp, result, NULL);
        return TCL_ERROR;
    }
    chan = Tcl_GetChannel(interp, (char *)argv[1], NULL);
    if (chan == (Tcl_Channel) NULL) {
        return TCL_ERROR;
    }
    statePtr = (UdpState *) Tcl_GetChannelInstanceData(chan);
    sock = statePtr->sock;
    
    if (argc == 3) {
        if (!strcmp(argv[2], "-myport")) {
            sprintf(buf, "%d", ntohs(statePtr->localport));
            Tcl_AppendResult(interp, buf, (char *)NULL);
        } else if (!strcmp(argv[2], "-remote")) {
            if (statePtr->remotehost && *statePtr->remotehost) {
                sprintf(buf, "%s", statePtr->remotehost);
                Tcl_AppendResult(interp, buf, (char *)NULL);
                sprintf(buf, "%d", ntohs(statePtr->remoteport));
                Tcl_AppendElement(interp, buf);
            }
        } else if (!strcmp(argv[2], "-peer")) {
            if (statePtr->peerhost && *statePtr->peerhost) {
                sprintf(buf, "%s", statePtr->peerhost);
                Tcl_AppendResult(interp, buf, (char *)NULL);
                sprintf(buf, "%d", statePtr->peerport);
                Tcl_AppendElement(interp, buf);
            }
        } else {
            result = "udpConf fileId [-mcastadd] [-mcastdrop] groupaddr | udpConf fileId remotehost remoteport | udpConf fileId [-myport] [-remote] [-peer]";
            Tcl_SetResult (interp, result, NULL);
            return TCL_ERROR;
        }
        return TCL_OK;
    } else if (argc == 4) {
        if (!strcmp(argv[2], "-mcastadd")) {
            if (strlen(argv[3]) >= sizeof(statePtr->remotehost)) {
                result = "hostname too long";
                Tcl_SetResult (interp, result, NULL);
                return TCL_ERROR;
            }
            mreq.imr_multiaddr.s_addr = inet_addr(argv[3]);
            if (mreq.imr_multiaddr.s_addr == -1) {
                name = gethostbyname(argv[3]);
                if (name == NULL) {
                    UDPTRACE("UDP error - gethostbyname");
                    return TCL_ERROR;
                }
                memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, sizeof(mreq.imr_multiaddr.s_addr));
            }
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)) < 0) {
                UDPTRACE("UDP error - setsockopt - IP_ADD_MEMBERSHIP");
                return TCL_ERROR;
            }
            maddr.sin_addr.s_addr = htonl(INADDR_ANY);
            return TCL_OK;
        } else if (!strcmp(argv[2], "-mcastdrop")) {
            if (strlen(argv[3]) >= sizeof(statePtr->remotehost)) {
                result = "hostname too long";
                Tcl_SetResult (interp, result, NULL);
                return TCL_ERROR;
            }
            mreq.imr_multiaddr.s_addr = inet_addr(argv[3]);
            if (mreq.imr_multiaddr.s_addr == -1) {
                name = gethostbyname(argv[3]);
                if (name == NULL) {
                    UDPTRACE("UDP error - gethostbyname");
                    return TCL_ERROR;
                }
                memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, sizeof(mreq.imr_multiaddr.s_addr));
            }
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
            if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char*)&mreq, sizeof(mreq)) < 0) {
                UDPTRACE("UDP error - setsockopt - IP_DROP_MEMBERSHIP");
                return TCL_ERROR;
            }
            return TCL_OK;
        } else {
            if (strlen(argv[2]) >= sizeof(statePtr->remotehost)) {
                result = "hostname too long";
                Tcl_SetResult (interp, result, NULL);
                return TCL_ERROR;
            }
            strcpy(statePtr->remotehost, argv[2]);
            return udpGetService(interp, argv[3], &(statePtr->remoteport));
        }
    } else {
        result = "udpConf fileId [-mcastadd] [-mcastdrop] groupaddr | udpConf fileId remotehost remoteport | udpConf fileId [-myport] [-remote] [-peer]";
        Tcl_SetResult (interp, result, NULL);
        return TCL_ERROR;
    }
}

/*
 * ----------------------------------------------------------------------
 * udpPeek --
 *  peek some data and set the peer information
 * ----------------------------------------------------------------------
 */
int
udpPeek(ClientData clientData, Tcl_Interp *interp,
        int argc, CONST84 char * argv[])
{
#ifndef WIN32
    int buffer_size = 16;
    int actual_size, socksize;
    int sock;
    char message[17];
    /*struct hostent *name;*/
#ifdef SIPC_IPV6
    char *remotehost;
    struct sockaddr_in6 recvaddr;
#else
    struct sockaddr_in recvaddr;
#endif
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
    actual_size = recvfrom(sock, message, buffer_size, MSG_PEEK,
                           (struct sockaddr *)&recvaddr, &socksize);
    
    if (actual_size < 0) {
        sprintf(errBuf, "udppeek error");
        Tcl_AppendResult(interp, errBuf, (char *)NULL);
        return TCL_ERROR;
    }
#ifdef SIPC_IPV6
    remotehost = (char *)inet_ntop(AF_INET6, &recvaddr.sin_addr, statePtr->peerhost, sizeof(statePtr->peerhost) );
    statePtr->peerport = ntohs(recvaddr.sin_port);
#else
    strcpy(statePtr->peerhost, (char *)inet_ntoa(recvaddr.sin_addr));
    statePtr->peerport = ntohs(recvaddr.sin_port);
#endif
    message[16]='\0';
    
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
    
    UDPTRACE("setupProc\n");
    
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
#ifdef SIPC_IPV6
    char number[128], *remotehost;
    struct sockaddr_in6 recvaddr;
#else
    char number[32];
    struct sockaddr_in recvaddr;
#endif
    PacketList *p;
    
    UDPTRACE("checkProc\n");
    
    //synchronized
    WaitForSingleObject(sockListLock, INFINITE);
    
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
        if (statePtr->packetNum > 0) {
            UDPTRACE("UDP_CheckProc\n");
            //Read the data from socket and put it into statePtr
            socksize = sizeof(recvaddr);
#ifdef SIPC_IPV6
            memset(number, 0, 128);
#else
            memset(number, 0, 32);
#endif
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
            } else {
                p = (PacketList *)calloc(1, sizeof(struct PacketList));
                p->message = message;
                p->actual_size = actual_size;
#ifdef SIPC_IPV6
                remotehost = (char *)inet_ntoa(AF_INET6, &recvaddr.sin6_addr, p->r_host, sizeof(p->r_host));
                p->r_port = ntohs(recvaddr.sin6_port);
#else
                strcpy(p->r_host, (char *)inet_ntoa(recvaddr.sin_addr));
                p->r_port = ntohs(recvaddr.sin_port);
#endif
                p->next = NULL;
                
#ifdef SIPC_IPV6
                remotehost = (char *)inet_ntoa(AF_INET6, &recvaddr.sin6_addr, statePtr->peerhost, sizeof(statePtr->peerhost) );
                statePtr->peerport = ntohs(recvaddr.sin6_port);
#else
                strcpy(statePtr->peerhost, (char *)inet_ntoa(recvaddr.sin_addr));
                statePtr->peerport = ntohs(recvaddr.sin_port);
#endif
                
                if (statePtr->packets == NULL) {
                    statePtr->packets = p;
                    statePtr->packetsTail = p;
                } else {
                    statePtr->packetsTail->next = p;
                    statePtr->packetsTail = p;
                }
                
                UDPTRACE("Received %d bytes from %s:%d through %d\n",
                         p->actual_size, p->r_host, p->r_port, statePtr->sock);
                UDPTRACE("%s\n", p->message);
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
    
    if (WSAStartup(0x0101, &wsaData))
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
    fd_set readfds; //variable used for select
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
        //synchronized
        WaitForSingleObject(sockListLock, INFINITE);
        
        //no socket, just wait, use event
        if (sockList == NULL) {
            SetEvent(sockListLock);
            UDPTRACE("Wait for adding socket\n");
            WaitForSingleObject(waitForSock, INFINITE);
            //synchronized
            WaitForSingleObject(sockListLock, INFINITE);
        }
        
        //set each socket for select
        for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
            FD_SET(statePtr->sock, &readfds);
            UDPTRACE("SET sock %d\n", statePtr->sock);
        }
        
        SetEvent(sockListLock);
        UDPTRACE("Wait for select\n");
        //block here
        found = select(0, &readfds, NULL, NULL, &timeout);
        UDPTRACE("select end\n");
        
        if (found <= 0) {
            //We closed the socket during select or time out
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
        
        //wait for the socket data was read
        if (sockset > 0) {
            UDPTRACE( "Wait sock read\n");
            //alert the thread to do event checking
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
        waitForSock = CreateEvent(NULL, FALSE, FALSE, NULL);
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
    UdpState *statePre;
    
    WaitForSingleObject(sockListLock, INFINITE);
#endif /* ! WIN32 */
    
    sock = statePtr->sock;
    
#ifdef WIN32
    /* remove the statePtr from the list */
    for (statePtr = sockList, statePre = sockList;
         statePtr != NULL;
         statePre=statePtr, statePtr=statePtr->next) {
        if (statePtr->sock == sock) {
            UDPTRACE("Remove %d from the list\n", sock);
            if (statePtr == sockList) {
                sockList = statePtr->next;
            } else {
                statePre->next = statePtr->next;
                if (sockTail == statePtr)
                    sockTail = statePre;
            }
        }
    }
#endif /* ! WIN32 */
    
    ckfree((char *) statePtr);
    if (closesocket(sock) < 0) {
        errorCode = errno;
    }
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
    UdpState *fsPtr = (UdpState *) instanceData;
    if (mask) {
        UDPTRACE("Tcl_CreateFileHandler\n");
        Tcl_CreateFileHandler(fsPtr->sock, mask,
                              (Tcl_FileProc *) Tcl_NotifyChannel,
                              (ClientData) fsPtr->channel);
    } else {
        UDPTRACE("Tcl_DeleteFileHandler\n");
        Tcl_DeleteFileHandler(fsPtr->sock);
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
    int socksize;
    struct hostent *name;
#ifdef SIPC_IPV6
    struct sockaddr_in6 sendaddr;
    int n, errnum;
#else
    struct sockaddr_in sendaddr;
#endif
    
    *errorCode = 0;
    errno = 0;
    
    if (toWrite > MAXBUFFERSIZE) {
        UDPTRACE("UDP error - MAXBUFFERSIZE");
        return -1;
    }
    socksize = sizeof(sendaddr);
    memset(&sendaddr, 0, socksize);
    
#ifdef SIPC_IPV6
    n = inet_pton(AF_INET6, statePtr->remotehost, &sendaddr.sin6_addr);
    if (n <= 0) {
        name = getipnodebyname(statePtr->remotehost, AF_INET6,
                               AI_DEFAULT, &errnum);
#else
        sendaddr.sin_addr.s_addr = inet_addr(statePtr->remotehost);
        if (sendaddr.sin_addr.s_addr == -1) {
            name = gethostbyname(statePtr->remotehost);
#endif
            if (name == NULL) {
                UDPTRACE("UDP error - gethostbyname");
                return -1;
            }
#ifdef SIPC_IPV6
            memcpy(&sendaddr.sin6_addr, name->h_addr, sizeof(sendaddr.sin6_addr));
        }
        sendaddr.sin6_family = AF_INET6;
        sendaddr.sin6_port = statePtr->remoteport;
#else
        memcpy(&sendaddr.sin_addr, name->h_addr, sizeof(sendaddr.sin_addr));
    }
    sendaddr.sin_family = AF_INET;
    sendaddr.sin_port = statePtr->remoteport;
#endif
    written = sendto(statePtr->sock, buf, toWrite, 0,
                     (struct sockaddr *)&sendaddr, socksize);
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
#ifdef SIPC_IPV6
    char number[128];
    struct sockaddr_in6 recvaddr;
#else /* ! SIPC_IPV6 */
    char number[32];
    struct sockaddr_in recvaddr;
#endif /* ! SIPC_IPV6 */
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
    strcpy(statePtr->peerhost, packets->r_host);
    statePtr->peerport = packets->r_port;
    statePtr->packets = packets->next;
    free((char *) packets);
    bytesRead = bufSize;
#else /* ! WIN32 */
    socksize = sizeof(recvaddr);
#ifdef SIPC_IPV6
    memset(number, 0, 128);
#else
    memset(number, 0, 32);
#endif
    memset(&recvaddr, 0, socksize);
    
    bytesRead = recvfrom(sock, buf, buffer_size, 0,
                         (struct sockaddr *)&recvaddr, &socksize);
    if (bytesRead < 0) {
        UDPTRACE("UDP error - recvfrom %d\n", sock);
        *errorCode = errno;
        return -1;
    }
    
#ifdef SIPC_IPV6
    remotehost = (char *)inet_ntop(AF_INET6,
                                   &recvaddr.sin6_addr, statePtr->peerhost,
                                   sizeof(statePtr->peerhost));
    port = ntohs(recvaddr.sin6_port);
#else
    remotehost = (char *)inet_ntoa(recvaddr.sin_addr);
    port = ntohs(recvaddr.sin_port);
    strcpy(statePtr->peerhost, remotehost);
#endif
    
    UDPTRACE("remotehost: %s:%d\n", remotehost, port);
    statePtr->peerport = port;
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
 * udpGetOption --
 * ----------------------------------------------------------------------
 */
static int 
udpGetOption(ClientData instanceData, Tcl_Interp *interp,
             CONST84 char *optionName, Tcl_DString *optionValue)
{
    UdpState *statePtr = (UdpState *)instanceData;
    CONST84 char * options = "myport remote peer mcastadd mcastdrop";
    int r = TCL_OK;

    if (optionName == NULL) {

        Tcl_DStringAppend(optionValue, " -myport ", -1);
        udpGetOption(instanceData, interp, "-myport", optionValue);
        Tcl_DStringAppend(optionValue, " -remote ", -1);
        udpGetOption(instanceData, interp, "-remote", optionValue);
        Tcl_DStringAppend(optionValue, " -peer ", -1);
        udpGetOption(instanceData, interp, "-peer", optionValue);
        Tcl_DStringAppend(optionValue, " -mcastadd ", -1);
        udpGetOption(instanceData, interp, "-mcastadd", optionValue);
        Tcl_DStringAppend(optionValue, " -mcastdrop ", -1);
        udpGetOption(instanceData, interp, "-mcastdrop", optionValue);

    } else {

        Tcl_DString ds, dsInt;
        Tcl_DStringInit(&ds);
        Tcl_DStringInit(&dsInt);

        if (!strcmp("-myport", optionName)) {

            Tcl_DStringSetLength(&ds, TCL_INTEGER_SPACE);
            sprintf(Tcl_DStringValue(&ds), "%u", ntohs(statePtr->localport));

        } else if (!strcmp("-remote", optionName)) {

            Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
            sprintf(Tcl_DStringValue(&dsInt), "%u", 
                    ntohs(statePtr->remoteport));
            Tcl_DStringAppendElement(&ds, statePtr->remotehost);
            Tcl_DStringAppendElement(&ds, Tcl_DStringValue(&dsInt));

        } else if (!strcmp("-peer", optionName)) {

            Tcl_DStringSetLength(&dsInt, TCL_INTEGER_SPACE);
            sprintf(Tcl_DStringValue(&dsInt), "%u", statePtr->peerport);
            Tcl_DStringAppendElement(&ds, statePtr->peerhost);
            Tcl_DStringAppendElement(&ds, Tcl_DStringValue(&dsInt));

        } else if (!strcmp("-mcastadd", optionName)) {
            ;
        } else if (!strcmp("-mcastdrop", optionName)) {
            ;
        } else {
            r = Tcl_BadChannelOption(interp, optionName, options);
        }
        
        Tcl_DStringAppendElement(optionValue, Tcl_DStringValue(&ds));
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
    CONST84 char * options = "remote mcastadd mcastdrop";
    int r = TCL_OK;

    if (!strcmp("-remote", optionName)) {

        Tcl_Obj *valPtr;
        int len;

        valPtr = Tcl_NewStringObj(newValue, -1);
        r = Tcl_ListObjLength(interp, valPtr, &len);
        if (r == TCL_OK) {
            if (len < 1 || len > 2) {
                Tcl_SetResult(interp, "wrong # args", TCL_STATIC);
                r = TCL_ERROR;
            } else {
                Tcl_Obj *hostPtr, *portPtr;
                
                Tcl_ListObjIndex(interp, valPtr, 0, &hostPtr);
                strcpy(statePtr->remotehost, Tcl_GetString(hostPtr));
                
                if (len == 2) {
                    Tcl_ListObjIndex(interp, valPtr, 1, &portPtr);            
                    r = udpGetService(interp, Tcl_GetString(portPtr),
                                      &(statePtr->remoteport));
                }
            }
        }

    } else if (!strcmp("-mcastadd", optionName)) {

        Tcl_SetResult(interp, "E_NOTIMPL", TCL_STATIC);
        r = TCL_ERROR;

    } else if (!strcmp("-mcastdrop", optionName)) {

        Tcl_SetResult(interp, "E_NOTIMPL", TCL_STATIC);
        r = TCL_ERROR;

    } else {

        r = Tcl_BadChannelOption(interp, optionName, options);

    }

    return r;
}

/*
 * ----------------------------------------------------------------------
 * udpTrace --
 * ----------------------------------------------------------------------
 */
static void
udpTrace(const char *format, ...)
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
