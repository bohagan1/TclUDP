#!/home/xiaotaow/tcl83/bin/tclsh

global gotcha;

proc handleSock {sock} {
  global gotcha;

  set content [gets $sock]
  puts "Received $content"
  puts "Peer [udp_conf $sock -peer]"
  set gotcha 1
}

load "../unix/libudp.so"

set sock [udp_open 5061]
puts "Myport: [udp_conf $sock -myport]"

if {$sock > 0} {
  fileevent $sock readable "handleSock $sock"
  udp_conf $sock 204.198.76.59 5061
#  udp_conf $sock minsk.clic.cs.columbia.edu 5060
  puts -nonewline $sock "test"
  flush $sock
  vwait gotcha
  close $sock
}
