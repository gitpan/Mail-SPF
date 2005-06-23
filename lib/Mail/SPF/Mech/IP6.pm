package Mail::SPF::Mech::IP6;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

use Net::IP;

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_ip6_network($response, 1);
	$self->parse_ip6_cidr_length($response, 0);
	$self->parse_end($response);
	return $self;
}

sub interp {
    my ($self, $record, $request, $response) = @_;

	my $needle = $request->{IPv6};
	return undef unless defined $needle;

	my $str = $self->{IP6_Network};
	$str .= "/" . $self->{IP6_CIDR_Mask}
			if defined $self->{IP6_CIDR_Mask};
    my $ip = new Net::IP($str);
	if ($ip->contains($needle) != $IP_NO_OVERLAP) {
		$self->match($request, $response);
		return 1;
	}
	return undef;
}

1;
