#!/usr/bin/perl

use blib;
use Data::Dumper;
use Mail::SPF::Server;
use Mail::SPF::Request;
use Mail::SPF::Response;
use Mail::SPF::Record;

$Data::Dumper::Indent = 1;

my $domain = shift || 'anarres.org';
my $ip = shift || '62.49.9.82';

my $server = new Mail::SPF::Server;
my $request = new Mail::SPF::Request(
		Scope	=> "mfrom",
		Sender	=> $domain,
		Ip		=> $ip,
			);
my $response = $server->query($request);

print "Response is $response\n";
print Dumper($response);
print "Result is " . $response->get_result . "\n";
