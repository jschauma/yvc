# Copyright (c) 2008,2010,2011 Yahoo! Inc.
#
# This example Makefile can be used to maintain vulnerability list.
# See 'make help' for more information.

PREFIX=/usr/local

RHEL_URL=http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2
RHEL_XML=com.redhat.rhsa-all.xml.bz2
RH_VERSIONS=4 5 6
FBVLIST=fbvlist
RH4VLIST=rh4vlist
RH5VLIST=rh5vlist
RH6VLIST=rh6vlist
LISTS= ${RH6VLIST} ${RH5VLIST} ${RH4VLIST} ${FBVLIST}
MANPAGES=fetch-vlist.1 yvc.1 yvc.conf.5

GONERS= ${RH6VLIST}.in ${RH5VLIST}.in ${RH4VLIST}.in ${FBVLIST}.in \
	${RHEL_XML} MANIFEST

date!=date

all: fetch sign

help:
	@echo "The following targets are available:"
	@echo "clean	  remove any interim files"
	@echo "fetch      retrieve the different vulnerability lists"
	@echo "help	  print this help"
	@echo "install    install yvc and fetch-vlist"
	@echo "rpm        build an RPM"
	@echo "sign	  sign the vulnerability list"
	@echo "uninstall  uninstall yvc and fetch-vlist"

install: man-compress
	python setup.py install

uninstall:
	@echo "Sorry, setup.py apparently can't do that."
	@echo "Your best bet is to run 'python setup.py install --record /tmp/f'"
	@echo "followed by 'xargs rm -f </tmp/f'"

rpm: man-compress
	python setup.py bdist_rpm

man-compress:
	@for f in ${MANPAGES}; do				\
		gzip -9 doc/man/$${f} -c > doc/man/$${f}.gz;	\
	done;
	

fetch: ${RHEL_XML}

${RHEL_XML}:
	wget -q ${RHEL_URL}

lists: fetch ${LISTS}

${FBVLIST}:
	echo "# Generated on ${date}" > ${FBVLIST}
	perl ./misc/harvest_freebsd_yvc.pl >> ${FBVLIST}

rh4vlist:
	python ./misc/redhat_oval_to_yvc.py 4 | sort -u > rh4vlist

rh5vlist:
	python ./misc/redhat_oval_to_yvc.py 5 | sort -u > rh5vlist

rh6vlist:
	python ./misc/redhat_oval_to_yvc.py 6 | sort -u > rh6vlist

clean:
	rm -f ${LISTS} ${GONERS} doc/man/*gz
	rm -fr build dist 
