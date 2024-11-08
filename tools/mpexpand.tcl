#!/usr/bin/env tclsh


lappend auto_path [file dirname [file dirname [info script]]]

if 0 {
    puts auto_path=\n\t[join $auto_path \n\t]
    catch {puts tcl_pkgPath=\n\t[join $tcl_pkgPath \n\t]}
    catch {puts tcl_libPath=\n\t[join $tcl_libPath \n\t]}

    puts [package require doctools]
    exit
}

package require doctools



# ---------------------------------------------------------------------
#  1. Handle command line options, input and output
#  2. Initialize a doctools object.
#  3. Run the input through the object.
#  4. Write output.
# ---------------------------------------------------------------------

proc usage {{exitstate 1}} {
    global argv0
    puts "Usage: $argv0\
	    ?-h|--help|-help|-??\
	    ?-help-fmt|--help-fmt?\
	    ?-module module?\
	    ?-deprecated?\
	    ?-copyright text?\
	    format in|- ?out|-?"
    exit $exitstate
}

# ---------------------------------------------------------------------

proc fmthelp {} {
    # Tcllib FR #527029: short reference of formatting commands.

    global argv0
    puts "$argv0 [doctools::help]"
    exit 0
}

# ---------------------------------------------------------------------
# 1. Handle command line options, input and output

proc cmdline {} {
    global argv0 argv format in out extmodule deprecated copyright

    set copyright ""
    set extmodule ""
    set deprecated 0

    while {[string match -* [set opt [lindex $argv 0]]]} {
	switch -exact -- $opt {
	    -module {
		set extmodule [lindex $argv 1]
		set argv [lrange $argv 2 end]
		continue
	    }
	    -copyright {
		set copyright [lindex $argv 1]
		set argv [lrange $argv 2 end]
		continue
	    }
	    -deprecated {
		set deprecated 1
		set argv [lrange $argv 1 end]
	    }
	    -help - -h - --help - -? {
		# Tcllib FR #527029
		usage 0
	    }
	    -help-fmt - --help-fmt {
		# Tcllib FR #527029
		fmthelp
	    }
	    default {
		# Unknown option
		usage
	    }
	}
    }

    if {[llength $argv] < 3} {
	usage
    }
    foreach {format in out} $argv break

    if {$format eq {} || $in eq {}} {
	usage
    }
    if {$out eq {}} {set out -}
    return $format
}

# ---------------------------------------------------------------------
#  3. Read input. Also providing the namespace with file information.

proc get_input {} {
    global in
    if {[string equal $in -]} {
	return [read stdin]
    } else {
	set if [open $in r]
	set text [read $if]
	close $if
	return $text
    }
}

# ---------------------------------------------------------------------
# 4. Write output.

proc write_out {text} {
    global out
    if {[string equal $out -]} {
	puts -nonewline stdout $text
    } else {
	set of [open $out w]
	puts -nonewline $of $text
	close $of
    }
}


# ---------------------------------------------------------------------
# Get it all together

proc main {} {
    global format deprecated extmodule in copyright

    #if {[catch {}
	cmdline

	::doctools::new dt -format $format -deprecated $deprecated -file $in
	if {$extmodule ne {}} {
	    dt configure -module $extmodule
	}
	if {$copyright ne {}} {
	    dt configure -copyright $copyright
	}

	write_out [dt format [get_input]]

	set warnings [dt warnings]
	if {[llength $warnings] > 0} {
	    puts stderr [join $warnings \n]
	}

	#{} msg]} {}
	#puts stderr "Execution error: $msg"
    #{}
    return
}


# ---------------------------------------------------------------------
main
exit
