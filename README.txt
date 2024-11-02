TclUDP
======

This package provides UDP sockets for TCL. It supports unicast and multicast
addresses.

INSTALLATION
============

This package uses the TCL Extension Architecture (TEA). Please see the
web page http://www.tcl.tk/doc/tea/ for more information about TEA. It
support all of the standard TCL configure script options.


UNIX BUILD
==========

Building under most UNIX systems is easy, just run the configure script
and then run make. Use ./configure --help to get the supported options. 

Following examples use the tclConfig.sh script. This script comes with the
installation of Tcl and contains useful data about the installation.

Linux
-----

To install Tcl, use e.g. 'apt-get|yum install tcl-devel.<platform> tcllib'.
The tclConfig.sh script is located in the folder /usr/lib/

	$ cd tcludp
	$ ./configure --with-tcl=/usr/lib/
	$ make
	$ make test
	$ make install

MacOSX
------
To install Tcl, use e.g. ActiveState Tcl distribution. The tclConfig.sh script
is located in the folder /Library/Frameworks/Tcl.framework/

	$ cd tcludp
	$ ./configure --with-tcl=/Library/Frameworks/Tcl.framework/
	$ make
	$ make test
	$ make install


WINDOWS BUILD
=============

See the win/README file for details on how to build the extension using 
Visual Studio.

The following minimal example will build and install the extension in the
C:\Tcl\lib directory.

	$ cd tcludp\win
	$ nmake -f makefile.vc realclean all 
	$ nmake -f makefile.vc install INSTALLDIR=C:\Tcl


DOCUMENTATION BUILD
===================

Use the following commands to create the documentation (based on udp.man
file). Ot uses the doctools package from tcllib.

	$ cd tcludp
	$ ./tools/mpexpand.tcl nroff ./doc/udp.man ./doc/udp.n
	$ ./tools/mpexpand.tcl html ./doc/udp.man ./doc/udp.html
	$ nroff -man ./doc/udp.n


FEEDBACK
========

If you have any problem with this extension, please contact Xiaotao Wu

Name  : Xiaotao Wu
Email : xiaotaow@cs.columbia.edu, xw71@columbia.edu
URL   : http://www.cs.columbia.edu/~xiaotaow
Phone : (212)939-7020, (212)939-7133,  Fax: (801)751-0217
SIP   : sip:xiaotaow@conductor.cs.columbia.edu
