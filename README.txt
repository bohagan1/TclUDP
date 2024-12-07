TclUDP
======

This package provides UDP sockets for TCL. It supports unicast and multicast
addresses.

INSTALLATION
============

This package uses the TCL Extension Architecture (TEA). Please see the web page
http://www.tcl.tk/doc/tea/ for more information about TEA. It supports all of
the standard TCL configure script options.

Uncompress and unpack the distribution

   ON UNIX and OS X:
	gzip -cd tcludp<version>.tar.gz | tar xf -

   ON WINDOWS:
	use something like WinZip to unpack the archive.
    
   This will create a subdirectory tcludp<version> with all the files in it.


UNIX BUILD
==========

Building under most UNIX systems is easy, just run the configure script and
then run make. Use ./configure --help to get the supported options. 

The following examples use the tclConfig.sh script. This script comes with the
installation of Tcl and contains useful data about the installation.

UNIX/Linux
----------

To install Tcl, use e.g. 'apt-get|yum install tcl-devel.<platform> tcllib'.
The tclConfig.sh script is located in the /usr/lib64/ directory.

	cd tcludp*
	./configure --enable-64bit --prefix=/usr --libdir=/usr/lib64/tcl --with-tcl=/usr/lib/
	make
	make test	(optional)
	make install

MacOSX
------
To install Tcl, use e.g. ActiveState Tcl distribution. The tclConfig.sh script
is located in the /Library/Frameworks/Tcl.framework/ folder.

	cd tcludp*
	./configure --with-tcl=/Library/Frameworks/Tcl.framework/
	make
	make test	(optional)
	make install


WINDOWS BUILD
=============

Visual Studio
-------------

To build and install TkTable, from the Command Prompt:

	cd tcludp*\win
	set INSTALLDIR=C:\TCL
	set TCL_SRC_DIR=C:\Source\Build\tcl
	set VC_DIR=C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC
	call "%VC_DIR%\vcvarsall.bat" amd64
	set PATH=%VC_DIR%\bin\amd64;%INSTALLDIR%\bin;%PATH%
	nmake -f makefile.vc INSTALLDIR=%INSTALLDIR% TCLDIR=%TCL_SRC_DIR% OPTS=msvcrt,threads,stubs
	nmake -f makefile.vc test INSTALLDIR=%INSTALLDIR%	(optional)
	nmake -f makefile.vc install INSTALLDIR=%INSTALLDIR%

Cygwin
------

Use the same steps as UNIX/Linux.


DOCUMENTATION BUILD
===================

Use the following commands to create the documentation (based on udp.man file).
This uses the doctools package from tcllib, so tcllib must be installed first.

Linux and MacOS
---------------

	cd tcludp*
	make docs
	nroff -man ./doc/udp.n

Windows
-------

	cd tcludp*\win
	nmake -f win/makefile.vc docs INSTALLDIR=%INSTALLDIR%


FEEDBACK
========

If you have any problem with this extension, please contact Xiaotao Wu

Name  : Xiaotao Wu
Email : xiaotaow@cs.columbia.edu, xw71@columbia.edu
URL   : http://www.cs.columbia.edu/~xiaotaow
Phone : (212)939-7020, (212)939-7133,  Fax: (801)751-0217
SIP   : sip:xiaotaow@conductor.cs.columbia.edu
