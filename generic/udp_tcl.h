/*
 *----------------------------------------------------------------------
 * UDP Extension for Tcl 8.4
 *
 * Copyright 1999-2000 by Columbia University; all rights reserved
 *
 * Written by Xiaotao Wu
 * Modifications by Pat Thoyts
 *
 * $Id: udp_tcl.h,v 1.5.2.2 2004/02/16 02:40:28 patthoyts Exp $
 *----------------------------------------------------------------------
 */

#ifndef UDP_TCL_H
#define UDP_TCL_H

#ifdef HAVE_CONFIG_H
#  include "../config.h"
#endif

#if STDC_HEADERS
#  include <stdlib.h>
#endif

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

#ifdef WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  if HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  endif
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif /* WIN32 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include "tcl.h"

#ifdef BUILD_udp
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif /* BUILD_udp */


#ifdef SIPC_IPV6
typedef struct sockaddr_storage sockaddr_t;
#else
typedef struct sockaddr_in sockaddr_t;
#endif

/* Constants to specify hostname or service name sizes */
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
#define NI_MAXSERVE 32
#endif


#ifdef WIN32

typedef u_short uint16_t;

typedef struct {
    Tcl_Event         header;	/* Information that is standard for */
    Tcl_Channel       chan;	/* Socket descriptor that is ready  */
} UdpEvent;

typedef struct PacketList {
    char              *message;
    int               actual_size;
    sockaddr_t        peer;
    struct PacketList *next;
} PacketList;

#endif /* WIN32 */

typedef struct UdpState {
    Tcl_Channel       channel;
    int               sock;
    int               doread;
    sockaddr_t        saddr_local;
    sockaddr_t        saddr_remote;
    sockaddr_t        saddr_peer;
#ifdef WIN32
    HWND              hwnd;
    PacketList        *packets;
    PacketList        *packetsTail;
    int               packetNum;
    struct UdpState   *next;
    Tcl_ThreadId      threadId;	/* for Tcl_ThreadAlert */
#endif
} UdpState;


EXTERN int Udp_Init(Tcl_Interp *interp);

#endif
