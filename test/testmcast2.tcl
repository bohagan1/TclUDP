global gotcha;

load "../unix/libudp.so"

# Since the socket is bound to the local
# port when it is created then we must set
# this value to the port number that is used
# by the multicast group. For instance foe SAP
# announcements this should be 9875
set sock [udp_open 9875]

# joins the multicast group
udp_conf $sock 224.2.127.254 9875
udp_conf $sock -mcastadd 224.2.127.254
if {$sock > 0} {
  puts "Will send testtest"
  puts $sock "testtest"
  flush $sock
  # leaves the multicast group
  udp_conf $sock -mcastdrop 224.2.127.254
  close $sock
}

