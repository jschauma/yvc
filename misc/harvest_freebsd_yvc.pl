#! /usr/local/bin/perl -w
#
# Copyright (c) 2009,2010 Yahoo! Inc.
#
# Originally written by Joshua Moss <jmos@yahoo-inc.com> in March 2009.
#
# This program fetches the list of known vulnerabilities in the FreeBSD
# ports collection from http://www.freebsd.org/ports/portaudit/ and
# generates a yvc(1) compatible vlist.

use strict;
use IO::Socket;

use constant FBSD_PORTAUDIT => "http://www.freebsd.org/ports/portaudit/";

# each element stores a hash which contains unique vuln id, description,
# packages (vulns)
my @VULN_INFO;

###
### Subroutines
###

# function : get_freebsd_vulns
# purpose  : loop over the list of vulnerabilities and populate the global
#            array with hashes containing an id and a description
# inputs   : none
# returns  : void, global @VULN_INFO has been populated

sub get_freebsd_vulns {

	my $vuln_regex = qr/([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\.html\"\>\s*([^<]+)/;

	foreach my $line (get_page(FBSD_PORTAUDIT)) {
		next unless ($line =~ m/$vuln_regex/);
		# unique vuln id, description
		push(@VULN_INFO, { id => $1,  desc => $2 });
	}

	return;
}

# function : get_freebsd_vuln_detail
# purpose  : loop over all vulnerabilities and fetch their respective page,
#            then parse that page and populate the 'vulns' field of this
#            vulnerabilitie's hash
# inputs   : none
# returns  : void, populates @VULN_INFO further

sub get_freebsd_vuln_detail {
	my $affects;

	for (my $i=0; $i< scalar (@VULN_INFO); $i++) {

		my $vuln_page = FBSD_PORTAUDIT . $VULN_INFO[$i]->{'id'} . '.html';
		$affects = 0;

		foreach my $line (get_page($vuln_page)) {
			if ($line =~/Affects\:/) {
				$affects = 1;
				next;
			}

			if ($affects && $line =~ m/li>\s*([^<]+)</) {
				push(@{ $VULN_INFO[$i]->{'vulns'} }, $1);
			}

			if ($affects && $line =~ m/\/ul/) {
				$affects = 0;
				next;
			}
		}
	}

	return;
}

# function : print_freebsd_vuln_yvc
# purpose  : iterate over all vulnerabilities and print them in the desired
#            format
# inputs   : none
# returns  : void, output is printed to stdout

sub print_freebsd_vuln_yvc {

	my $desc_regex = qr/(multiple-vulnerabilities|denial-of-service|cross-site-request-forgery|remote-dos|xss|cross-site-scripting|arbitrary-code-execution|script-insertion|input-validation|directory-traversal|heap-overflow|buffer-overflow|stack-overflow|session-hijacking|command-execution|local-privilege-escalation|command-injection|information-disclosure|arbitrary-file-disclosure|arbitrary-script-execution)/;

	# reverse just to be consistent with pkgsrc vlist ordering
	for (my $i=scalar(@VULN_INFO); $i>=0; $i--) {

		next unless ($VULN_INFO[$i]->{'vulns'});

		foreach my $pkg (sort  @{ $VULN_INFO[$i]->{'vulns'} } ) {
			next unless ($pkg =~/[a-z]/);

			$pkg =~ s/\&lt\;/\</g;
			$pkg =~ s/\&gt\;/\>/g;
			#$pkg =~ s/=/-/g;
			$pkg =~ s/\s+//g;

			$VULN_INFO[$i]->{'desc'} = lc( $VULN_INFO[$i]->{'desc'} );
			$VULN_INFO[$i]->{'desc'} =~ s/^\s*[a-z0-9]+\s+\-{2,}\s*//;
			$VULN_INFO[$i]->{'desc'} =~ s/[^a-z0-9]/-/g;
			$VULN_INFO[$i]->{'desc'} =~ s/-{2,}/-/g;
			$VULN_INFO[$i]->{'desc'} =~ s/^-+//g;
			$VULN_INFO[$i]->{'desc'} =~ s/-+$//g;
			$VULN_INFO[$i]->{'desc'} =~ s/-vulnerability$//;

			# shorten some of these long descriptions to their core issue
			if ($VULN_INFO[$i]->{'desc'} =~/$desc_regex/) {
				$VULN_INFO[$i]->{'desc'} = $1;
				$VULN_INFO[$i]->{'desc'} =~s/^dos$/denial-of-service/;
				$VULN_INFO[$i]->{'desc'} =~s/^xss$/cross-site-scripting/;
			}

			printf("%s\t%s\t%s\n", $pkg, $VULN_INFO[$i]->{'desc'},
					FBSD_PORTAUDIT . $VULN_INFO[$i]->{'id'} . '.html');
		}
	}

	return;
}

# function : get_page
# purpose  : retrieve the given document and return the contents as an array
# inputs   : URI
# returns  : an array of lines

sub get_page {
	my ($url) = @_;

	my ($port, $host, $uri);

	if ($url =~s/^(https?):\/+([^\/]+)(\/.*)$//) {
		$port = ($1 eq 'https') ? 443 : 80;
		$host = $2;
		$uri  = $3;
	} else {
		return undef;
	}

	my $PAGE = IO::Socket::INET->new(PeerAddr=>$host,
		PeerPort=>$port,
		Proto=>"tcp",
		Timeout=>7) or return;

	my $timeout = 30;
	print $PAGE "GET $uri HTTP/1.0\r\n",
			"Host: $host\r\n\r\n";

	alarm($timeout);

	my @page = <$PAGE>;

	return @page;
}

###
### Main
###

# scrape the main listing
get_freebsd_vulns();

# dive into each page
get_freebsd_vuln_detail();

# clean up and print out
print_freebsd_vuln_yvc();

exit(0);
