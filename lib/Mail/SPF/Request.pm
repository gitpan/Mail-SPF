package Mail::SPF::Request;

use strict;
use warnings;

use base qw(Mail::SPF::Base);

use Net::IP;

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	$self->{Scope} = 'mfrom' unless exists $self->{Scope};
	foreach (qw(Sender Ip)) {
		unless (defined $self->{$_}) {
			die "No $_ in Request";
		}
	}
	$self->{Sender} =~ s/^(.*)@// and $self->{SenderLocalPart} = $1;
	my $ip = new Net::IP($self->{Ip});
	if ($ip->version == 4) {
		$self->{IPv4} = $ip;
		# Translate into IPv4-mapped IPv6 address:
		$self->{IPv6} = new Net::IP("::ffff:$self->{Ip}");
	}
	elsif ($ip->version == 6) {
		$self->{IPv6} = $ip;
		if ($ip->ip =~ /^(?:0000:)*ffff:([\p{IsXDigit}:]{9})/) {
			my $str = $1;
			$str =~ s/://;
			my $ip4 = join(".", unpack("C4", pack("H*", $str)));
			$self->{IPv4} = new Net::IP($ip4);
		}
	}
	else {
		die "Could not get IP version from $self->{Ip}";
	}
	return $self;
}

=head1 FIELDS

=over 4

=item $req->{Ip}

	A Net::IP object containing an IPv6 representation of either the
	given IPv6 address or the given IPv4 address mapped into IPv6
	space.

=item $req->{Sender}

=item $req->{Domain}

	This field is set and maintained by the SPF interpreter.

=back

=cut

1;
