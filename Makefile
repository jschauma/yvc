# Copyright (c) 2008,2010  Yahoo! Inc.
#
# This example Makefile can be used to maintain vulnerability list.
# See 'make help' for more information.

# Location to which to upload the vlists.
LOCATION="<hostname>:~/public_html/yvc/"
FBVLIST=fbvlist
RH4VLIST=rh4vlist
RH5VLIST=rh5vlist
LISTS= ${RH5VLIST} ${RH4VLIST} ${FBVLIST}

GONERS= ${RH5VLIST}.in ${RH4VLIST}.in ${FBVLIST}.in \
	com.redhat.rhsa-all.xml.bz2

date!=date

all: sign upload

help:
	@echo "The following targets are available:"
	@echo "all	sign + upload"
	@echo "clean	remove any interim files"
	@echo "help	print this help"
	@echo "sign	sign the vulnerability list"
	@echo "upload	upload the vulnerability list"

sign: ${LISTS}

${FBVLIST}: ${FBVLIST}.in
	gpg -o ${FBVLIST} --clearsign ${FBVLIST}.in
	chmod a+r ${FBVLIST}

${FBVLIST}.in:
	@echo "# Generated on ${date}" > ${FBVLIST}.in
	perl ./misc/harvest_freebsd_yvc.pl >> ${FBVLIST}.in


${RH4VLIST}: ${RH4VLIST}.in
	gpg -o ${RH4VLIST} --clearsign ${RH4VLIST}.in
	chmod a+r ${RH4VLIST}

${RH4VLIST}.in:
	python ./misc/redhat_oval_to_yvc.py 4 > ${RH4VLIST}.in


${RH5VLIST}: ${RH5VLIST}.in
	gpg -o ${RH5VLIST} --clearsign ${RH5VLIST}.in
	chmod a+r ${RH5VLIST}

${RH5VLIST}.in:
	python ./misc/redhat_oval_to_yvc.py 5 > ${RH5VLIST}.in


upload: sign
	scp ${LISTS} ${LOCATION}

clean:
	rm -f ${LISTS} ${GONERS}
