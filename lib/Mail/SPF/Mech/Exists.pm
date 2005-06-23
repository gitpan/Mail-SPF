package Mail::SPF::Mech::Exists;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_domain_spec($response, 1);
	$self->parse_end($response);
	return $self;
}

sub interp {
	my ($self, $record, $request, $response) = @_;

	my $domain = $self->get_domain_spec($request, $response);
	return 1 unless $domain;
	my $packet = $record->{Server}->get_dns($domain, 'A');
	return undef unless $packet;
	foreach my $rr ($packet->answer) {
		if ($rr->type eq 'A') {
			$self->match($request, $response);
			return 1;
		}
	}

	return undef;
}

1;
