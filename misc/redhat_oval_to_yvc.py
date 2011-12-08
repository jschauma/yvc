#!/usr/local/bin/python

#
# $Id: redhat_oval_to_yvc.py 71 2011-12-08 01:28:41Z jans $
# $URL: svn+ssh://svn.corp.yahoo.com/yahoo/tools/yvc/branches/outgoing/misc/redhat_oval_to_yvc.py $
#
# Copyright (c) 2009,2011 Yahoo! Inc.
#
# Originally written by Joshua Moskovitz <jmos@yahoo-inc.com> in October 2009.
# Rewritten as a streaming parser bi Jan Schaumann <jans@yahoo-inc.com> in
# December 2011.
#
# This program reads the Open Vulnerability and Assessment Language (OVAL)
# file, available from http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2
# and generates a yvc(1) compatible vlist.

import re
import sys
import os.path
import bz2
import time

# Destination of the oval xml.bz2 file
oval_bz2 = './com.redhat.rhsa-all.xml.bz2'

# Usage
if len(sys.argv) != 2:
    print "Usage: %s %s" % (sys.argv[0], '<4|5>')
    sys.exit(1)


###
### Subroutines
###


# function : print_redhat_yvc
# purpose  : turn oval XML gunk into yvc goodness
# inputs   : numeric string to restrict output by version
# returns  : void, output is printed to stdout

def print_redhat_yvc(version):

    print '# Generated on ' + time.strftime("%a %b %e %H:%M:%S %Z %Y")  # Wed Oct 28 12:05:05 PDT 2009
    arch = bz2.BZ2File(oval_bz2, 'r')

    def_p = re.compile('.*<definition id="(?P<id>[^"]*)"', re.I)
    title_p = re.compile('.*<title>RHSA-[0-9:]*: (?P<title>.*)</title>', re.I)
    platform_p = re.compile('.*<platform>.* Linux (?P<num>[0-9])</platform>', re.I)
    reference_p = re.compile('.*<reference source.*ref_url="(?P<url>.*)"', re.I)
    criterion_p = re.compile('.*<criterion .*comment="(?P<pkg>[^ ]*) is earlier than [0-9]+:(?P<version>[^"]*)"', re.I)
    end_p = re.compile('.*</definition>', re.I)

    found = 0
    id = 0
    title = ""
    platform = 0
    reference = ""
    criteria = []

    lineno = 0

    for line in arch.readlines():
        lineno += 1
        m = def_p.match(line)
        if m:
            found = 1
            id = m.group('id')
            title = ""
            platform = 0
            reference = ""
            criteria = []
            continue

        if not found:
            continue

        m = title_p.match(line)
        if m:
            title = m.group('title')
            continue

        m = platform_p.match(line)
        if m:
            platform = m.group('num')
            continue

        m = reference_p.match(line)
        if m:
            reference = m.group('url')
            continue

        m = criterion_p.match(line)
        if m:
            criteria.append(m.group('pkg') + '<' + m.group('version'))
            continue

        m = end_p.match(line)
        if m:
            if title and platform and reference and len(criteria):
                if platform == version:
                    title = re.sub('[^a-zA-Z0-9]+', '-', title).rstrip('-').lower()
		    for c in criteria:
                        try:
                            c.index("el%s" % version)
                            print "%s\t%s\t%s" % (c, title, reference)
                        except ValueError:
                             pass
            else:
                sys.stderr.write("Incomplete vulnerability encountered in line %d\n" % lineno)
                sys.stderr.write("%s\n%d\n%s\n%s\n" % (title, platform, reference, criteria))
            found = 0
            continue

print_redhat_yvc(sys.argv[1])
sys.exit(0)
