use strict;
use warnings;
use blib;

use Test::More tests => 13;

BEGIN { use_ok('Mail::SPF::Request'); }

my $r = new Mail::SPF::Request(
		Ip		=> '123.45.6.7',
		Sender	=> 'foo.com',
			);
ok(defined $r, 'Created an object');
isa_ok($r, 'Mail::SPF::Request');
is($r->{Sender}, 'foo.com', 'Sender set Ok');
isa_ok($r->{IPv4}, 'Net::IP');
is($r->{IPv4}->ip(), '123.45.6.7', 'IP is OK');
isa_ok($r->{IPv6}, 'Net::IP');
like($r->{IPv6}->ip(), qr/:ffff:7b2d:0607$/, 'IP is OK');

$r = new Mail::SPF::Request(
		Ip		=> '255.21.05.6',
		Sender	=> 'fred@nowhere.net',
			);
isa_ok($r->{IPv4}, 'Net::IP');
is($r->{Sender}, 'nowhere.net');
is($r->{IPv4}->ip(), '255.21.5.6', 'IP is OK');

$r = new Mail::SPF::Request(
		Ip		=> '::ffff:255.21.05.6',
		Sender	=> 'fred@nowhere.net',
			);
isa_ok($r->{IPv4}, 'Net::IP');
isa_ok($r->{IPv6}, 'Net::IP');

1;
