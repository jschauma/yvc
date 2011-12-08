# Copyright (c) 2008,2010,2011 Yahoo! Inc.
#
# This example Makefile can be used to maintain vulnerability list.
# See 'make help' for more information.

# Location to which to upload the vlists.
LOCATION="<hostname>:~/public_html/yvc/"

RHEL_URL=http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml.bz2
RHEL_XML=com.redhat.rhsa-all.xml.bz2
RH_VERSIONS=4 5 6
FBVLIST=fbvlist
RH4VLIST=rh4vlist
RH5VLIST=rh5vlist
RH6VLIST=rh6vlist
YVLIST=yvlist
LISTS= ${YVLIST} ${RH6VLIST} ${RH5VLIST} ${RH4VLIST} ${FBVLIST}

GONERS= ${RH6VLIST}.in ${RH5VLIST}.in ${RH4VLIST}.in ${FBVLIST}.in \
	${RHEL_XML}

date!=date

all: fetch sign upload

help:
	@echo "The following targets are available:"
	@echo "all	sign + upload"
	@echo "clean	remove any interim files"
	@echo "help	print this help"
	@echo "sign	sign the vulnerability list"
	@echo "upload	upload the vulnerability list"

fetch: ${RHEL_XML}

${RHEL_XML}:
	wget -q ${RHEL_URL}

sign: ${LISTS}

${YVLIST}: ${YVLIST}.in
	gpg -o ${YVLIST} --clearsign ${YVLIST}.in
	chmod a+r ${YVLIST}

${FBVLIST}: ${FBVLIST}.in
	gpg -o ${FBVLIST} --clearsign ${FBVLIST}.in
	chmod a+r ${FBVLIST}

${FBVLIST}.in:
	echo "# Generated on ${date}" > ${FBVLIST}.in
	perl ./misc/harvest_freebsd_yvc.pl >> ${FBVLIST}.in

.for n in ${RH_VERSIONS}

rh${n}vlist.in:
	python ./misc/redhat_oval_to_yvc.py ${n} | sort -u > rh${n}vlist.in

rh${n}vlist: rh${n}vlist.in
	gpg -o $@ --clearsign $>
	chmod a+r $>
.endfor

upload: sign
	scp ${LISTS} ${LOCATION}

clean:
	rm -f ${LISTS} ${GONERS}
