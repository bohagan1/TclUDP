# multicast.tcl - Copyright (C) 2004 Pat Thoyts <patthoyts@users.sf.net>
#
# Demonstrate the use of IPv4 multicast UDP sockets.
#
# You can send to ths using netcat:
#  echo HELLO | nc -u 224.5.1.21 7771
#
# $Id: multicast.tcl,v 1.1 2004/11/22 23:48:47 patthoyts Exp $

package require udp 1.0.6

proc udpEvent {chan} {
    set data [read $chan]
    set peer [fconfigure $chan -peer]
    puts "$peer [string length $data] '$data'"
    if {[string match "QUIT*" $data]} {
        close $chan
        set ::forever 1
    }
    return
}

# Select a multicast group and the port number.
set group 224.5.1.21
set port  7771

# Create a listening socket and configure for sending too.
set s [udp_open $port]
fconfigure $s -buffering none -blocking 0
fconfigure $s -mcastadd $group -remote [list $group $port]
fileevent $s readable [list udpEvent $s]

# Announce our presence and run
puts -nonewline $s "hello, world"
set forever 0
vwait ::forever

exit
