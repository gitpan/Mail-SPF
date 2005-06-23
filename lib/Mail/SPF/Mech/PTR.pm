package Mail::SPF::Mech::PTR;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

use Net::IP;

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_domain_spec($response, 0);
	$self->parse_end($response);
	return $self;
}

sub interp {
	my ($self, $record, $request, $response) = @_;

	my $domain = $self->get_domain_spec($request, $response);
	return 1 unless $domain;

	my ($ip, $type);
	if (defined $request->{IPv4}) {
		$ip = $request->{IPv4};
		$type = 'A';
	}
	elsif (defined $request->{IPv6}) {
		$ip = $request->{IPv6};
		$type = 'AAAA';
	}
	else {
		die "No IP address available in request for PTR.";
	}
	my $ptrdomain = $ip->reverse_ip;
	my $packet = $record->{Server}->get_dns($ptrdomain, 'PTR');
	return undef unless $packet;

	foreach my $rr ($packet->answer) {
		if ($rr->type eq 'PTR') {
			my $name = $rr->ptrdname;
			my $subpacket = $record->{Server}->get_dns($name, $type);
			next unless $subpacket;
			foreach my $subrr ($subpacket->answer) {
				if ($rr->type eq $type) {
					my $subip = new Net::IP($rr->address);
					if ($subip->overlaps($ip) != $IP_NO_OVERLAP) {
						if (($name eq $domain) ||
							($name =~ /\.\Q$domain\E$/)) {
							$self->match($request, $response);
							return 1;
						}
					}
				}
				elsif ($rr->type =~ /^(CNAME|A|AAAA)$/) {
				}
				else {
					warn "PTR/$type: Unexpected RR type " . $rr->type;
				}
			}
		}
		else {
			warn "PTR: Unexpected RR type " . $rr->type;
		}
	}

	return undef;
}

1;
