#! /usr/bin/env python

from distutils.core import setup

setup(name = 'yvc',
	version = '3.4.1',
	description = 'a software package vulnerability check',
	author = 'Jan Schaumann',
	author_email = 'jschauma@netmeister.org',
	license = 'BSD',
	url = 'http://www.netmeister.org/apps/yvc/',
	long_description = 'yvc compares the given package name against the list of known vulnerabilities and reports any security issues. This output contains the name and version of the package, the type of vulnerability, and a URL for further information for each vulnerable package.',
	py_modules = [ 'yahoo.yvc' ],
	scripts = [ 'bin/yvc', 'bin/fetch-vlist' ],
	data_files = [ ('share/man/man1', [ 'doc/man/fetch-vlist.1.gz', 'doc/man/yvc.1.gz' ]),
			('share/man/man5', [ 'doc/man/yvc.conf.5.gz' ]),
			('/var/yvc', [ 'conf/fbvlist', 'conf/nbvlist', 'conf/rh4vlist',
					'conf/rh5vlist', 'conf/rh6vlist' ]),
			('/etc', [ 'conf/yvc.conf' ]), ]
	)
