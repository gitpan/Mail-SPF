use strict;
use warnings;
use blib;
use Data::Dumper;

use Test::More tests => 7;

use_ok('Mail::SPF::Server');
use_ok('Mail::SPF::Record');

my $domain = 'foo.org';
my %records = (
	'v=spf1 a/24 mx/24 -all' => {
		Errors	=> 0,
	},
	'v=spfx a/24 mx/24 -all' => {
		Errors	=> 1,
	},
);

my $s = new Mail::SPF::Server();
foreach my $record (keys %records) {
	my $data = $records{$record};
	my $e = new Mail::SPF::Response();
	my $p = new Net::DNS::Packet("$domain", 'TXT', 'IN');
	my $rr = new Net::DNS::RR("$domain. 300 IN TXT '$record'");
	$p->push('answer', $rr);
	my $r = new Mail::SPF::Record(
			Server		=> $s,
			Domain		=> 'foo.org',
			Packet		=> $p,
			Response	=> $e,
				);
	isa_ok($r, 'Mail::SPF::Record');
	if ($data->{Errors} > 0) {
		isnt($e->{Errors}, undef, 'Errors were detected.');
		is(scalar(@{ $e->{Errors} }), $data->{Errors},
				'Got the right number of errors.');
	}
	else {
		is($e->{Errors}, undef, 'No errors should be present.');
	}

	# print "Record: $record\n";
	# print Dumper($e->{Errors});
}

1;
