# A Makefile to create html docs from the man pages.

MANPAGES=../man/fetch-vlist.1 ../man/yvc.1 ../man/yvc.conf.5

all: html

html: ${MANPAGES}
.for m in ${MANPAGES}
	nroff -man ${m} | rman -f html > ${m:S/..\/man\///}.html
.endfor

clean:
.for m in ${MANPAGES}
	@rm -f ${m:S/..\/man\///}.html
.endfor

upload:
	scp *.html <hostname>:~/public_html/yvc/
