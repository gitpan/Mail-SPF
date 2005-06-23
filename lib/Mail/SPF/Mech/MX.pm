package Mail::SPF::Mech::MX;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_domain_spec($response, 0);
	$self->parse_ip4_cidr_length($response, 0);
	$self->parse_ip6_cidr_length($response, 0);
	$self->parse_end($response);
	return $self;
}

sub interp {
	my ($self, $record, $request, $response) = @_;

	my $domain = $self->get_domain_spec($request, $response);
	return 1 unless $domain;

	my $packet = $record->{Server}->get_dns($domain, 'MX');
	return undef unless $packet;

	foreach my $rr ($packet->answer) {
		if ($rr->type eq 'MX') {
			my $domain = $rr->exchange;
			if ($self->match_in_domain(
					$record, $request, $response, $domain
						)) {
				return 1;
			}
		}
		else {
			warn "MX: Unexpected RR type " . $rr->type;
		}
	}

	return undef;
}

1;
