package Mail::SPF;

use strict;
use warnings;
use vars qw($VERSION);

use Mail::SPF::Server;
use Mail::SPF::Request;
use Mail::SPF::Response;

$VERSION = "2.00";

=head1 NAME

Mail::SPF - Mail Sender Authentication

=head1 SYNOPSIS

	use Mail::SPF;
	my $spf = new Mail::SPF::Server();
	my $request = new Mail::SPF::Request(
			Ip		=> '123.45.6.7',
			Sender	=> 'fred@nowhere.net',
				);
	my $response = $spf->query($request);
	print "Result is " . $response->get_result;

=head1 DESCRIPTION

This is an initial draft object oriented reimplementation of
Mail::SPF::Query. It is not yet fully tested, and does not yet
contain all of the additional features expected of a practical SPF
implementation.

=head1 EXPORTS

None.

=head1 BUGS

=head1 SEE ALSO

L<Mail::SRS::Server>, L<Mail::SRS::Request>, L<Mail::SRS::Response>

=head1 COPYRIGHT

Copyright (c) 2005 Shevek, Julian Mehnle. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
