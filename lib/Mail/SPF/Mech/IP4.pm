package Mail::SPF::Mech::IP4;

use strict;
use warnings;

use base 'Mail::SPF::Mech';

use Net::IP;

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_ip4_network($response, 1);
	$self->parse_ip4_cidr_length($response, 0);
	$self->parse_end($response);
	return $self;
}

sub interp {
    my ($self, $record, $request, $response) = @_;

	my $needle = $request->{IPv4};
	return undef unless defined $needle;

	my $str = $self->{IP4_Network};
	$str .= "/" . $self->{IP4_CIDR_Mask}
			if defined $self->{IP4_CIDR_Mask};
    my $ip = new Net::IP($str);
	if ($ip->contains($needle) != $IP_NO_OVERLAP) {
		$self->match($request, $response);
		return 1;
	}
	return undef;
}

1;
