
namespace eval udp {
    namespace export udp_open udp_conf
}

proc ::udp::udp_open {{port -1}} {
    set s [udp]
    if {$port != -1} {
        fconfigure $s -sockname [list {} $port]
    }
    return $s
}

# udpConf fileId [-mcastadd] [-mcastdrop] groupaddr
# udpConf fileId remotehost remoteport
# udpConf fileId [-myport] [-remote] [-peer]
proc ::udp::udp_conf {s args} {
    if {[llength $args] < 1 || [llength $args] > 2} {
        return -code error "wrong \# args: should be \
            udp_conf socket ?option ...?"
    }

    while {[string match -* [set option [lindex $args 0]]]} {
        switch -exact -- $option {
            -myport    { return [lindex [fconfigure $s -sockname] 1] }
            -remote    { return [fconfigure $s -remote] }
            -peer      { return [fconfigure $s -peer] }
            -mcastadd  { return [fconfigure $f -mcastadd [Pop args 1]] }
            -mcastdrop { return [fconfigure $f -mcastdrop [Pop args 1]] }
            --    { Pop args ; break }
            default {
                return -code error "bad option $option: must be one of\
                    -mcastadd, -mcastdrop, -myport, -remote, or -peer"
            }
        }
        Pop args
    }

    if {[llength $args] == 2} {
        return [fconfigure $s -remote $args]
    } else {
        return -code error "wrong \# args: should be\
            udp_conf socket ?option ...?"
    }
}

proc ::udp::Pop {varname {nth 0}} {
    upvar $varname args
    set r [lindex $args $nth]
    set args [lreplace $args $nth $nth]
    return $r
}
