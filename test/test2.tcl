#!/home/xiaotaow/tcl83/bin/tclsh

global gotcha;

proc handleSock {sock} {
  global gotcha;

  set content [udp_read $sock]
  puts $content
  set gotcha 1
}

load "../unix/libudp.so"

set sock [udp_open 38880]

if {$sock > 0} {
#  udp_conf $sock 204.198.76.55 5061
  udp_conf $sock minsk.clic.cs.columbia.edu 5061
  puts "We will send testtest"
  puts $sock "testtest"
  flush $sock
  close $sock
}

