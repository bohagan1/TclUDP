/******************************************************************************
 * UDP Extension for Tcl 8.4
 *
 * Copyright 1999-2000 by Columbia University; all rights reserved
 *
 * Written by Xiaotao Wu
 * Last modified: 11/03/2000
 ******************************************************************************/
#include "udp_tcl.h"

#ifdef WIN32
#include <stdlib.h>
#include <tcl.h>
#include <winsock.h>
#include <stdio.h>
#else
#ifdef LINUX
#include <sys/ioctl.h>
#else
#include <sys/filio.h>
#endif
#endif

#ifdef DEBUG
FILE *dbg;
#endif

#define MAXBUFFERSIZE 4096

static char errBuf[256];

EXTERN int Udp_Init(Tcl_Interp *);

int udpOpen(ClientData , Tcl_Interp *, int , char *[]);
int udpConf(ClientData , Tcl_Interp *, int , char *[]);
int udpPeek(ClientData , Tcl_Interp *, int , char *[]);

static int udpGet(ClientData instanceData,int direction,ClientData *handlePtr);
static void udpWatch(ClientData instanceData, int mask);
static int udpOutput(ClientData instanceData, char *buf, int toWrite, int *errorCode);
static int udpInput(ClientData instanceData, char *buf, int bufSize, int *errorCode);
static int udpClose(ClientData instanceData, Tcl_Interp *interp);

#ifdef WIN32
static HANDLE waitForSock;
static HANDLE waitSockRead;
static HANDLE sockListLock;
static UdpState *sockList;
static UdpState *sockTail;
#endif

/*
 * udpClose
 */
int udpClose(ClientData instanceData, Tcl_Interp *interp) {
  int sock;
  int errorCode = 0;
  UdpState *statePtr = (UdpState *) instanceData;
#ifdef WIN32
  UdpState *statePre;

  WaitForSingleObject(sockListLock, INFINITE);
#endif

  sock = statePtr->sock;

#ifdef WIN32
  //remove the statePtr from the list
  for (statePtr = sockList, statePre = sockList; statePtr != NULL; statePre=statePtr, statePtr=statePtr->next) {
    if (statePtr->sock == sock) {
#ifdef DEBUG
      fprintf(dbg, "Remove %d from the list\n", sock);
      fflush(dbg);
#endif
      if (statePtr == sockList) {
        sockList = statePtr->next;
      } else {
        statePre->next = statePtr->next;
        if (sockTail == statePtr)
          sockTail = statePre;
      }
    }
  }
#endif

  ckfree((char *) statePtr);
#ifndef WIN32
  if (close(sock) < 0) {
#else
  if (closesocket(sock) < 0) {
#endif
    errorCode = errno;
  }
  if (errorCode != 0) {
#ifndef WIN32
    sprintf(errBuf, "udpClose: %d, error: %d\n", sock, errorCode);
#else
    sprintf(errBuf, "udpClose: %d, error: %d\n", sock, WSAGetLastError());
#endif
#ifdef DEBUG
    fprintf(dbg, "UDP error - close %d", sock);
    fflush(dbg);
#endif
  } else {
#ifdef DEBUG
    fprintf(dbg, "Close socket %d\n", sock);
    fflush(dbg);
#endif
  }

#ifdef WIN32
  SetEvent(sockListLock);
#endif

  return errorCode;
}
 
/*
 * udpWatch
 */
static void udpWatch(ClientData instanceData, int mask) {
#ifndef WIN32
  UdpState *fsPtr = (UdpState *) instanceData;
  if (mask) {
#ifdef DEBUG
    fprintf(dbg, "Tcl_CreateFileHandler\n");
    fflush(dbg);
#endif
    Tcl_CreateFileHandler(fsPtr->sock, mask,
	(Tcl_FileProc *) Tcl_NotifyChannel,
	(ClientData) fsPtr->channel); 
  } else {
#ifdef DEBUG
    fprintf(dbg, "Tcl_DeleteFileHandler\n");
    fflush(dbg);
#endif
    Tcl_DeleteFileHandler(fsPtr->sock);
  }
#endif
}

/*
 * udpGet
 */
static int udpGet(ClientData instanceData,int direction,ClientData *handlePtr) {
  UdpState *statePtr = (UdpState *) instanceData;
#ifdef DEBUG
  fprintf(dbg, "UDP_get %d\n", statePtr->sock);
  fflush(dbg);
#endif
  return statePtr->sock;
}

/*
 * udpPeek -  peek some data and set the peer information
 */
int udpPeek(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]) {
#ifndef WIN32
  int buffer_size = 16;
  int actual_size, socksize, port;
  int sock;
  char message[17];
  char *remotehost;
  struct hostent *name;
#ifdef SIPC_IPV6
  struct sockaddr_in6 recvaddr;
#else
  struct sockaddr_in recvaddr;
#endif
  Tcl_Channel chan;
  UdpState *statePtr;

  chan = Tcl_GetChannel(interp, argv[1], NULL);
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
#endif
  return TCL_OK;
}

/*
 * udpConf
 */
int udpConf(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]) {
  Tcl_Channel chan;
  UdpState *statePtr;
  char *result;
  char buf[128];
  struct hostent *name;
  struct ip_mreq mreq;
  struct sockaddr_in maddr;
  int sock, ret;

  if (argc != 4 && argc != 3) {
    result = "udpConf fileId [-mcastadd] [-mcastdrop] groupaddr | udpConf fileId remotehost remoteport | udpConf fileId [-myport] [-remote] [-peer]";
    Tcl_SetResult (interp, result, NULL);
    return TCL_ERROR;
  }
  chan = Tcl_GetChannel(interp, argv[1], NULL);
  if (chan == (Tcl_Channel) NULL) {
    return TCL_ERROR;
  }
  statePtr = (UdpState *) Tcl_GetChannelInstanceData(chan);
  sock = statePtr->sock;
  
  if (argc == 3) {
    if (!strcmp(argv[2], "-myport")) {
      sprintf(buf, "%d", statePtr->localport);
      Tcl_AppendResult(interp, buf, (char *)NULL);
    } else if (!strcmp(argv[2], "-remote")) {
      sprintf(buf, "%s", statePtr->remotehost);
      Tcl_AppendResult(interp, buf, (char *)NULL);
      sprintf(buf, "%d", statePtr->remoteport);
      Tcl_AppendElement(interp, buf);
    } else if (!strcmp(argv[2], "-peer")) {
      sprintf(buf, "%s", statePtr->peerhost);
      Tcl_AppendResult(interp, buf, (char *)NULL);
      sprintf(buf, "%d", statePtr->peerport);
      Tcl_AppendElement(interp, buf);
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
#ifdef DEBUG
          fprintf(dbg, "UDP error - gethostbyname");
          fflush(dbg);
#endif
          return TCL_ERROR;
        }
        memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, sizeof(mreq.imr_multiaddr.s_addr));
      }
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
#ifdef DEBUG
        fprintf(dbg, "UDP error - setsockopt - IP_ADD_MEMBERSHIP");
        fflush(dbg);
#endif
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
#ifdef DEBUG
          fprintf(dbg, "UDP error - gethostbyname");
          fflush(dbg);
#endif
          return TCL_ERROR;
        }
        memcpy(&mreq.imr_multiaddr.s_addr, name->h_addr, sizeof(mreq.imr_multiaddr.s_addr));
      }
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
#ifdef DEBUG
        fprintf(dbg, "UDP error - setsockopt - IP_DROP_MEMBERSHIP");
        fflush(dbg);
#endif
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
      statePtr->remoteport = atoi(argv[3]);
      return TCL_OK;
    }
  } else {
    result = "udpConf fileId [-mcastadd] [-mcastdrop] groupaddr | udpConf fileId remotehost remoteport | udpConf fileId [-myport] [-remote] [-peer]";
    Tcl_SetResult (interp, result, NULL);
    return TCL_ERROR;
  }
}

#ifdef WIN32
/*
 * UdpEventProc --
 */
int UdpEventProc(Tcl_Event *evPtr, int flags) {
  UdpEvent *eventPtr = (UdpEvent *) evPtr;
  int mask = 0;

  mask |= TCL_READABLE;
#ifdef DEBUG
  fprintf(dbg, "UdpEventProc\n");
  fflush(dbg);
#endif
  Tcl_NotifyChannel(eventPtr->chan, mask);
  return 1;
}

/*
 * UDP_SetupProc - called in Tcl_SetEventSource to do the setup step
 */
static void UDP_SetupProc(ClientData data, int flags) {
  UdpState *statePtr;
  Tcl_Time blockTime = { 0, 0 };

#ifdef DEBUG
      fprintf(dbg, "setupProc\n");
      fflush(dbg);
#endif

  if (!(flags & TCL_FILE_EVENTS)) {
    return;
  }

  WaitForSingleObject(sockListLock, INFINITE);
  for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
    if (statePtr->packetNum > 0) {
#ifdef DEBUG
      fprintf(dbg, "UDP_SetupProc\n");
      fflush(dbg);
#endif
      Tcl_SetMaxBlockTime(&blockTime);
      break;
    }
  }
  SetEvent(sockListLock);
}

/*
 * UDP_CheckProc --
 */
void UDP_CheckProc(ClientData data, int flags) {
  UdpState *statePtr;
  UdpEvent *evPtr;
  int actual_size, socksize, reply;
  int buffer_size = MAXBUFFERSIZE;
  int port;
  struct hostent *name;
  char *remotehost, *message;
#ifdef SIPC_IPV6
  char number[128];
  struct sockaddr_in6 recvaddr;
#else
  char number[32];
  struct sockaddr_in recvaddr;
#endif
  PacketList *p;

#ifdef DEBUG
  fprintf(dbg, "checkProc\n");
  fflush(dbg);
#endif

  //synchronized
  WaitForSingleObject(sockListLock, INFINITE);

  for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
    if (statePtr->packetNum > 0) {

#ifdef DEBUG
      fprintf(dbg, "UDP_CheckProc\n");
      fflush(dbg);
#endif
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
#ifdef DEBUG
        fprintf(dbg, "calloc error\n");
        fflush(dbg);
#endif
        exit(1);
      }

      actual_size = recvfrom(statePtr->sock, message, buffer_size, 0,
        (struct sockaddr *)&recvaddr, &socksize);
      SetEvent(waitSockRead);

      if (actual_size < 0) {
        if (WSAGetLastError() == WSAEMSGSIZE) {
          actual_size = buffer_size;
        }
      }

      if (actual_size < 0) {
#ifdef DEBUG
        fprintf(dbg, "UDP error - recvfrom %d\n", statePtr->sock);
        fflush(dbg);
#endif
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
      
#ifdef DEBUG
        fprintf(dbg, "Received %d bytes from %s:%d through %d\n", p->actual_size, p->r_host, p->r_port, statePtr->sock);
        fwrite(p->message, 1, p->actual_size, dbg);
        fflush(dbg);
#endif
      }

      statePtr->packetNum--;
      statePtr->doread = 1;
#ifdef DEBUG
      fprintf(dbg, "packetNum is %d\n", statePtr->packetNum);
      fflush(dbg);
#endif
      if (actual_size >= 0) {
        evPtr = (UdpEvent *) ckalloc(sizeof(UdpEvent));
        evPtr->header.proc = UdpEventProc;
        evPtr->chan = statePtr->channel;
        Tcl_QueueEvent((Tcl_Event *) evPtr, TCL_QUEUE_TAIL);
#ifdef DEBUG
        fprintf(dbg, "socket %d has data\n", statePtr->sock);
        fflush(dbg);
#endif
      }
    }
  }

  SetEvent(sockListLock);
}
#endif

/*
 *----------------------------------------------------------------------
 * udpOpen -  opens a UDP socket and addds the file descriptor to the
 *             tcl interpreter
 *----------------------------------------------------------------------
 */
int udpOpen(ClientData clientData, Tcl_Interp *interp, int argc, char *argv[]) {
  int sock;
  char channelName[20];
  UdpState *statePtr;
  char * result;
  uint16_t localport = 0;
#ifdef SIPC_IPV6
  struct sockaddr_in6  addr, sockaddr;
#else
  struct sockaddr_in  addr, sockaddr;
#endif
  unsigned long status = 1;
  int len;
#ifdef WIN32
  UdpState *tmp;
  static initd = 0;
#endif

  Tcl_ChannelType *Udp_ChannelType;
  Udp_ChannelType = (Tcl_ChannelType *) ckalloc((unsigned) sizeof(Tcl_ChannelType));
#ifdef SIPC_IPV6
  Udp_ChannelType->typeName = strdup("udp6");
#else 
  Udp_ChannelType->typeName = strdup("udp");
#endif
  Udp_ChannelType->blockModeProc = NULL;
  Udp_ChannelType->closeProc = udpClose;
  Udp_ChannelType->inputProc = udpInput;
  Udp_ChannelType->outputProc = udpOutput;
  Udp_ChannelType->seekProc = NULL;
  Udp_ChannelType->setOptionProc = NULL;
  Udp_ChannelType->getOptionProc = NULL;
  Udp_ChannelType->watchProc = udpWatch;
  Udp_ChannelType->getHandleProc = udpGet;
  Udp_ChannelType->close2Proc = NULL;

  if (argc >= 2) {
   localport = atoi(argv[1]);
  }

  memset(channelName, 0, sizeof(channelName));

#ifdef SIPC_IPV6
  if ((sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
#else
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
#endif
    sprintf(errBuf,"%s","udp - socket");
#ifdef DEBUG
    fprintf(dbg, "UDP error - socket\n");
    fflush(dbg);
#endif
    Tcl_AppendResult(interp, errBuf, (char *)NULL);
    return TCL_ERROR;
  }
  memset(&addr, 0, sizeof(addr));
#ifdef SIPC_IPV6
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(localport);
#else
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = 0;
  addr.sin_port = htons(localport);
#endif
  if (bind(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0) {
    sprintf(errBuf,"%s","udp - bind");
#ifdef DEBUG
    fprintf(dbg, "UDP error - bind\n");
    fflush(dbg);
#endif
    Tcl_AppendResult(interp, errBuf, (char *)NULL);
    return TCL_ERROR;
  }
#ifdef WIN32
  ioctlsocket(sock, FIONBIO, &status);
#else
  ioctl(sock, (int) FIONBIO, &status);
#endif
  if (localport == 0) {
    len = sizeof(sockaddr);
    getsockname(sock, (struct sockaddr *)&sockaddr, &len);
#ifdef SIPC_IPV6
    localport = ntohs(sockaddr.sin6_port);
#else
    localport = ntohs(sockaddr.sin_port);
#endif
  }
#ifdef DEBUG
  fprintf(dbg, "Open socket %d. Bind socket to port %d\n", sock, localport);
  fflush(dbg);
#endif

  statePtr = (UdpState *) ckalloc((unsigned) sizeof(UdpState));
  statePtr->sock = sock;
  sprintf(channelName, "sock%d", statePtr->sock);
  statePtr->channel = Tcl_CreateChannel(Udp_ChannelType, channelName,
    (ClientData) statePtr, (TCL_READABLE | TCL_WRITABLE | TCL_MODE_NONBLOCKING));
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
//  Tcl_SetChannelOption(interp, statePtr->channel, "-blocking", "0");
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
#ifdef DEBUG
  fprintf(dbg, "Append %d to sockList\n", statePtr->sock);
  fflush(dbg);
  for (tmp = sockList; tmp != NULL; tmp = tmp->next) {
    fprintf(dbg, "%d --> ", tmp->sock);
    fflush(dbg);
  }
  fprintf(dbg, "NULL\n");
  fflush(dbg);
#endif
  SetEvent(sockListLock);
  SetEvent(waitForSock);
#endif
  return TCL_OK;
}

#ifdef WIN32

/*
 * InitSockets
 */
static int InitSockets() {
    WSADATA wsaData;
    WNDCLASS class;
    HINSTANCE handle;

    /*
     * Load the socket DLL and initialize the function table.
     */

    if (WSAStartup(0x0101, &wsaData))
        return 0;

    return 1;
}

/*
 * SocketThread
 */
static DWORD WINAPI SocketThread(LPVOID arg) {
  fd_set readfds; //variable used for select
  struct timeval timeout;
  UdpState *statePtr;
  int found;
  int sockset;

  FD_ZERO(&readfds);

#ifdef DEBUG
  fprintf(dbg, "In socket thread\n");
  fflush(dbg);
#endif
  while (1) {
    FD_ZERO(&readfds);
    timeout.tv_sec  = 1;
    timeout.tv_usec = 0;
    //synchronized
    WaitForSingleObject(sockListLock, INFINITE);

    //no socket, just wait, use event
    if (sockList == NULL) {
      SetEvent(sockListLock);
#ifdef DEBUG
      fprintf(dbg, "Wait for adding socket\n");
      fflush(dbg);
#endif
      WaitForSingleObject(waitForSock, INFINITE);
      //synchronized
      WaitForSingleObject(sockListLock, INFINITE);
    }

    //set each socket for select
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
      FD_SET(statePtr->sock, &readfds);
#ifdef DEBUG
      fprintf(dbg, "SET sock %d\n", statePtr->sock);
      fflush(dbg);
#endif
    }

    SetEvent(sockListLock);

#ifdef DEBUG
    fprintf(dbg, "Wait for select\n");
    fflush(dbg);
#endif
    //block here
    found = select(0, &readfds, NULL, NULL, &timeout);
#ifdef DEBUG
    fprintf(dbg, "select end\n");
    fflush(dbg);
#endif

    if (found <= 0) {
      //We closed the socket during select or time out
      continue;
    }

#ifdef DEBUG
    fprintf(dbg, "Packet comes in\n");
    fflush(dbg);
#endif

    WaitForSingleObject(sockListLock, INFINITE);
    sockset = 0;
    for (statePtr = sockList; statePtr != NULL; statePtr=statePtr->next) {
      if (FD_ISSET(statePtr->sock, &readfds)) {
        statePtr->packetNum++;
        sockset++;
#ifdef DEBUG
        fprintf(dbg, "sock %d is set\n", statePtr->sock);
        fflush(dbg);
#endif
        break;
      }
    }
    SetEvent(sockListLock);

    //wait for the socket data was read
    if (sockset > 0) {
#ifdef DEBUG
      fprintf(dbg, "Wait sock read\n");
      fflush(dbg);
#endif
      //alert the thread to do event checking
      Tcl_ThreadAlert(statePtr->threadId);
      WaitForSingleObject(waitSockRead, INFINITE);
#ifdef DEBUG
      fprintf(dbg, "Sock read finished\n");
      fflush(dbg);
#endif
    }
  }
}

/*
 * Udp_WinHasSockets --
 */
int Udp_WinHasSockets(Tcl_Interp *interp) {
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
    * Start the socketThread windows and set the thread priority of the
    * socketThread as highest
    */

    sockList = NULL;
    sockTail = NULL;
	  waitForSock = CreateEvent(NULL, FALSE, FALSE, NULL);
	  waitSockRead = CreateEvent(NULL, FALSE, FALSE, NULL);
	  sockListLock = CreateEvent(NULL, FALSE, TRUE, NULL);

    socketThread = CreateThread(NULL, 8000, SocketThread, NULL, 0, &id);
    SetThreadPriority(socketThread, THREAD_PRIORITY_HIGHEST); 

#ifdef DEBUG
      fprintf(dbg, "Initialize socket thread\n");
      fflush(dbg);
#endif

    if (socketThread == NULL) {
#ifdef DEBUG
      fprintf(dbg, "Failed to create thread\n");
      fflush(dbg);
#endif
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

#endif

/*
 * udpInit
 */
int Udp_Init(Tcl_Interp *interp) {
#ifdef DEBUG
    dbg = fopen("udp.dbg", "wb");
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
  return TCL_OK;
}

/*
 * udpOutput--
 */
static int udpOutput(ClientData instanceData, char *buf, int toWrite, int *errorCode) {
  UdpState *statePtr = (UdpState *) instanceData;
  int written;
  int socksize;
  struct hostent *name;
#ifdef SIPC_IPV6
  struct sockaddr_in6 sendaddr;
  struct in6_addr inp;
  int n, errnum;
#else
  struct sockaddr_in sendaddr;
  struct in_addr inp;
#endif

  *errorCode = 0;
  errno = 0;

  if (toWrite > MAXBUFFERSIZE) {
#ifdef DEBUG
    fprintf(dbg, "UDP error - MAXBUFFERSIZE");
    fflush(dbg);
#endif
    return -1;
  }
  socksize = sizeof(sendaddr);
  memset(&sendaddr, 0, socksize);

#ifdef SIPC_IPV6
  n = inet_pton(AF_INET6, statePtr->remotehost, &sendaddr.sin6_addr);
  if (n <= 0) {
    name = getipnodebyname(statePtr->remotehost, AF_INET6, AI_DEFAULT, &errnum);
#else
  sendaddr.sin_addr.s_addr = inet_addr(statePtr->remotehost);
  if (sendaddr.sin_addr.s_addr == -1) {
    name = gethostbyname(statePtr->remotehost);
#endif
    if (name == NULL) {
#ifdef DEBUG
      fprintf(dbg, "UDP error - gethostbyname");
      fflush(dbg);
#endif
      return -1;
    }
#ifdef SIPC_IPV6
    memcpy(&sendaddr.sin6_addr, name->h_addr, sizeof(sendaddr.sin6_addr));
  }
  sendaddr.sin6_family = AF_INET6;
  sendaddr.sin6_port = htons(statePtr->remoteport);
#else
    memcpy(&sendaddr.sin_addr, name->h_addr, sizeof(sendaddr.sin_addr));
  }
  sendaddr.sin_family = AF_INET;
  sendaddr.sin_port = htons(statePtr->remoteport);
#endif
  written = sendto(statePtr->sock, buf, toWrite, 0, (struct sockaddr *)&sendaddr, socksize);
  if (written < 0) {
#ifdef DEBUG
      fprintf(dbg, "UDP error - sendto");
      fflush(dbg);
#endif
    return -1;
  }

#ifdef DEBUG
  fprintf(dbg, "Send %d to %s:%d through %d\n", written, statePtr->remotehost, statePtr->remoteport, statePtr->sock);
  fflush(dbg);
#endif

  return written;
}

/*
 * udpInput
 */
static int udpInput(ClientData instanceData, char *buf, int bufSize, int *errorCode) {
  UdpState *statePtr = (UdpState *) instanceData;
  int bytesRead;
  int actual_size, socksize, reply;
  int buffer_size = MAXBUFFERSIZE;
  int port;
  char *remotehost;
  struct hostent *name;
#ifdef SIPC_IPV6
  char number[128];
  struct sockaddr_in6 recvaddr;
#else
  char number[32];
  struct sockaddr_in recvaddr;
#endif
  int sock = statePtr->sock;
  int i;
#ifdef WIN32
  PacketList *packets;
#endif

#ifdef DEBUG
  fprintf(dbg, "In udpInput\n");
  fflush(dbg);
#endif

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
    *errorCode = EAGAIN;    /* pretend that we would block */
#ifdef DEBUG
  fprintf(dbg, "Pretend we would block\n");
  fflush(dbg);
#endif
    return 0;
  }

  *errorCode = 0;
  errno = 0;

  if (bufSize == 0) {
    return 0;
  }

#ifdef WIN32
  packets = statePtr->packets;
#ifdef DEBUG
  fprintf(dbg, "udp_recv\n");
  fflush(dbg);
#endif
  if (packets == NULL) {
#ifdef DEBUG
    fprintf(dbg, "packets is NULL\n");
    fflush(dbg);
#endif
    return 0;
  }
  memcpy(buf, packets->message, packets->actual_size);
  free((char *) packets->message);
#ifdef DEBUG
  fprintf(dbg, "udp_recv message\n");
  fwrite(buf, 1, packets->actual_size, dbg);
  fflush(dbg);
#endif
  bufSize = packets->actual_size;
  strcpy(statePtr->peerhost, packets->r_host);
  statePtr->peerport = packets->r_port;
  statePtr->packets = packets->next;
  free((char *) packets);
  bytesRead = bufSize;
#else
  // else for Unix/Linux
  socksize = sizeof(recvaddr);
#ifdef SIPC_IPV6
  memset(number, 0, 128);
#else
  memset(number, 0, 32);
#endif
  memset(&recvaddr, 0, socksize);

  bytesRead = recvfrom(sock, buf, buffer_size, 0, (struct sockaddr *)&recvaddr, &socksize);
  if (bytesRead < 0) {
#ifdef DEBUG
    fprintf(dbg, "UDP error - recvfrom %d\n", sock);
    fflush(dbg);
#endif
    *errorCode = errno;
    return -1;
  }

#ifdef SIPC_IPV6
  remotehost = (char *)inet_ntop(AF_INET6, &recvaddr.sin6_addr, statePtr->peerhost, sizeof(statePtr->peerhost));
  port = ntohs(recvaddr.sin6_port);
#else
  remotehost = (char *)inet_ntoa(recvaddr.sin_addr);
  port = ntohs(recvaddr.sin_port);
  strcpy(statePtr->peerhost, remotehost);
#endif

#ifdef DEBUG
  fprintf(dbg, "remotehost: %s\n", remotehost);
  fflush(dbg);
#endif
  statePtr->peerport = port;
#endif

   /* we don't want to return anything next time */
   if (bytesRead > 0) { buf[bytesRead] = '\0'; statePtr->doread = 0; }

#ifdef DEBUG
  fprintf(dbg, "udpInput end: %d, %s\n", bytesRead, buf);
  fflush(dbg);
#endif

   if (bytesRead > -1) {
     return bytesRead;
   }

   *errorCode = errno;
   return -1;
}

