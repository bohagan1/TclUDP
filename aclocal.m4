#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

AC_DEFUN(TEA_IPV6_SUPPORT, [
    dnl ***********************Checking for availability of IPv6*******************
    AC_MSG_CHECKING([for IPv6])
    AC_ARG_ENABLE(ipv6, [  --enable-ipv6=[yes/no] enable IPv6 support],, enable_ipv6=yes)
    if test $enable_ipv6 = yes; then
      have_ipv6=no
      AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/socket.h>], [
        struct sockaddr_storage ss;
        socket(AF_INET6, SOCK_STREAM, 0);
        ],
        [have_ipv6=yes],
        [have_ipv6=no]
      )
      AC_MSG_RESULT($have_ipv6)
    
      if test $have_ipv6 = yes; then
        AC_DEFINE([SIPC_IPV6], [], [IPv6 support])
    
        have_getaddrinfo=no
        AC_CHECK_FUNC(getaddrinfo, have_getaddrinfo=yes)
        if test $have_getaddrinfo != yes; then
          for lib in bsd socket inet; do
            AC_CHECK_LIB($lib, getaddrinfo, [LIBS="$LIBS -l$lib";have_getaddrinfo=yes;break])
          done
        fi
    
        if test $have_getaddrinfo = yes; then
          AC_DEFINE([HAVE_GETADDRINFO], [], [Define if getaddrinfo available])
        fi

        have_inet_ntop=no
        AC_CHECK_FUNC(inet_ntop, have_inet_ntop=yes)
        if test $have_inet_ntop != yes; then
          for lib in bsd socket inet; do
            AC_CHECK_LIB($lib, inet_ntop, [LIBS="$LIBS -l$lib";have_inet_ntop=yes;break])
          done
        fi
    
        if test $have_inet_ntop = yes; then
          AC_DEFINE([HAVE_INET_NTOP], [], [Define if inet_ntop available])
        fi


      fi
    fi 
    
    dnl ******************************End IPv6 checks******************************    
])
