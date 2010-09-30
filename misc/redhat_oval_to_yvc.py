#!/usr/local/bin/python

#
# Copyright (c) 2009,2010 Yahoo! Inc.
#
# Originally written by Joshua Moss <jmos@yahoo-inc.com> in October 2009.
#
# This program reads the Open Vulnerability and Assessment Language (OVAL)
# file, available from http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2
# and generates a yvc(1) compatible vlist.
#

import re
import sys
import socket
import os.path
import xml.dom.minidom
import bz2
import urllib
import time

# Source of the oval xml.bz2 file
oval_url = 'http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2'

# Destination of the oval xml.bz2 file
oval_bz2 = './com.redhat.rhsa-all.xml.bz2'

# Usage
if len(sys.argv) != 2:
    print "Usage: %s %s" % (sys.argv[0], '<4|5>')
    sys.exit(1)


###
### Subroutines
###


# function : download_redhat_oval_bz2
# purpose  : fetches the xml.bz2 file from redhat and write to local dir on disk
# inputs   : none
# returns  : void

def download_redhat_oval_bz2():
    if not os.path.isfile(oval_bz2): # XXX remove this if you want to download every time, rather than handle via make clean
        socket.setdefaulttimeout(45)
        urllib.urlretrieve(oval_url, oval_bz2) # in, out
        urllib.urlcleanup()



# function : print_redhat_yvc
# purpose  : traverses the xml dom for vulnerability information and prints out in the desired
#            format
# inputs   : numeric string, appends to regex search for 'el'
# returns  : void, output is printed to stdout

def print_redhat_yvc(version = '[45]'):

    print '# Generated on ' + time.strftime("%a %b %e %H:%M:%S %Z %Y")  # Wed Oct 28 12:05:05 PDT 2009

    arch = bz2.BZ2File(oval_bz2, 'r')
    document = xml.dom.minidom.parse(arch)

    apps = {} # they seem to keep their tests in chronological order, we only want the latest
    definitions = document.getElementsByTagName('definition')
    for d in definitions:
        #description = d.getElementsByTagName('metadata')[0].getElementsByTagName('description')[0].lastChild.nodeValue # TODO parse descriptions for keywords
        title = d.getElementsByTagName('metadata')[0].getElementsByTagName('title')[0].lastChild.nodeValue.split(': ')[1].replace('\n', '')
        title = re.sub('[^a-zA-Z0-9]+', '-', title).rstrip('-').lower()
        ref_url = d.getElementsByTagName('reference')[0].getAttribute('ref_url')

        criterions = d.getElementsByTagName('criterion')
        for c in criterions:
            criteria = c.getAttribute('comment').replace('\t', ' ')

            if re.search('el'+version, criteria, re.I) == None:
                continue # skipping lines that don't match version

            criteria = re.sub('\d+:', '', criteria)
            criteria = criteria.replace(' is earlier than ','<')

            app = criteria.split('<')[0]

            apps[app] = "%s\t%s\t%s" % (criteria, title, ref_url)

    for app in apps:
        print apps[app]


download_redhat_oval_bz2()
print_redhat_yvc(sys.argv[1])
sys.exit(0)
