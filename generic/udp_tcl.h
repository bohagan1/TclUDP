/*
 *----------------------------------------------------------------------
 * UDP Extension for Tcl 8.4
 *
 * Copyright 1999-2000 by Columbia University; all rights reserved
 *
 * Written by Xiaotao Wu
 * Last modified: 11/03/2000
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

#ifdef WIN32
#  include <winsock.h>
#else
#  if HAVE_UNISTD_H
#    include <unistd.h>
#  endif
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  endif
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif

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

#ifdef WIN32

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

#endif // WIN32

typedef struct UdpState {
  Tcl_Channel       channel;
  int               sock;
  char              remotehost[256]; /* send packets to */
  uint16_t          remoteport;
  char              peerhost[256];   /* receive packets from */
  uint16_t          peerport;
  uint16_t          localport;
  int               doread;
#ifdef WIN32
  HWND              hwnd;
  PacketList        *packets;
  PacketList        *packetsTail;
  int               packetNum;
  struct UdpState   *next;
  Tcl_ThreadId      threadId;        /* for Tcl_ThreadAlert */
#endif
} UdpState;


EXTERN int Udp_Init(Tcl_Interp *interp);

#endif
