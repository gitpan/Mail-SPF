package Mail::SPF::Mech;

use strict;
use warnings;

use base 'Mail::SPF::Base';

use Net::IP;

#use overload
#    '""' => &stringify;

use Mail::SPF::Response qw(:result);

use constant QUALIFIER_RESULT_MAP => {
    ''  => SPF_RESULT_PASS,
    '+' => SPF_RESULT_PASS,
    '-' => SPF_RESULT_FAIL,
    '~' => SPF_RESULT_SOFTFAIL,
    '?' => SPF_RESULT_NEUTRAL
};

# Template

our @EXPORT_OK = qw(%SPF_MECH_CLASSES);

our %SPF_MECH_CLASSES = (
    all     => 'Mail::SPF::Mech::All',
    include => 'Mail::SPF::Mech::Include',
    a       => 'Mail::SPF::Mech::A',
    mx      => 'Mail::SPF::Mech::MX',
    ptr     => 'Mail::SPF::Mech::PTR',
    ip4     => 'Mail::SPF::Mech::IP4',
    ip6     => 'Mail::SPF::Mech::IP6',
    'exists'=> 'Mail::SPF::Mech::Exists'
);

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	$self->{ParseValue} = $self->{Value};
	return $self;
}

sub parse_domain_spec {
    my ($self, $response, $required) = @_;
    if ($self->{ParseValue} =~ s#^:([^\s/]+)##i) {
        $self->{Domain} = $1;
    }
    elsif ($required) {
		$response->error("Missing required domain-spec in " .
						$self->stringify);
    }
}

sub parse_ip4_network {
    my ($self, $response, $required) = @_;
    my $QNUM = qr/\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5]/;
    if ($self->{ParseValue} =~ s/^($QNUM(?:\.$QNUM){3})//) {
        $self->{IP4_Network} = $1;
    }
    elsif ($required) {
		$response->error("Missing required ip4-network in " .
						$self->stringify);
    }
}

sub parse_ip4_cidr_length {
    my ($self, $response, $required) = @_;
    if ($self->{ParseValue} =~ s#^(/\d+)##) {
        $self->{IP4_CIDR_Length} = $1;
    }
    elsif ($required) {
		$response->error("Missing required ip4-cidr-length in " .
						$self->stringify);
    }
}

sub parse_ip6_network {
    my ($self, $response, $required) = @_;
    if ($self->{ParseValue} =~ s/^([:\p{IsXDigit}]+)//) {
        $self->{IP6_Network} = $1;
    }
    elsif ($required) {
		$response->error("Missing required ip6-network in " .
						$self->stringify);
    }
}

sub parse_ip6_cidr_length {
    my ($self, $response, $required) = @_;
    if ($self->{ParseValue} =~ s#^(/\d+)##) {
        $self->{IP6_CIDR_Length} = $1;
    }
    elsif ($required) {
		$response->error("Missing required ip6-cidr-length in " .
						$self->stringify);
    }
}

sub parse_end {
    my ($self, $response) = @_;
	if ($self->{ParseValue} ne '') {
		$response->error("Junk after mechanism in " .
							$self->stringify . ": '" .
							$self->{ParseValue} . "'");
	}
}

sub get_domain_spec {
    my ($self, $request, $response) = @_;
	my $value = $self->{Domain};
	if (defined $value) {
		return $self->expand($request, $response, $value);
	}
	else {
		return $request->{Domain};
	}
}

sub match_in_domain {
	my ($self, $record, $request, $response, $domain) = @_;

	# print "MatchInDomain: Record: $record\n";
	# print "MatchInDomain: Request: $request\n";
	# print "MatchInDomain: Response: $response\n";

	my $ipv4 = $request->{IPv4};
	my $ipv6 = $request->{IPv6};
	my @types = qw(AAAA);
	unshift(@types, 'A') if defined $ipv4;

	my $cidr4 = $self->{IP4_CIDR_Length};;
	$cidr4 = 32 unless defined $cidr4;
	my $cidr6 = $self->{IP6_CIDR_Length};;
	$cidr6 = 128 unless defined $cidr6;

	foreach my $type (@types) {
		print "match_in_domain($domain, $type)\n";
		# print "IPv4 needle: " . $ipv4->ip . "/$cidr4\n";
		# print "IPv6 needle: " . $ipv6->ip . "/$cidr6\n";
		my $packet = $record->{Server}->get_dns($domain, $type);
		next unless $packet;
		foreach my $rr ($packet->answer) {
			$rr->print;
			# print "Address is " . $rr->address . ", CIDR $cidr4\n";
			if ($rr->type eq 'A') {
				my $haystack = new Net::IP($rr->address .  "/$cidr4");
				if ($haystack->overlaps($ipv4) != $IP_NO_OVERLAP) {
					$self->match($request, $response);
					return 1;
				}
			}
			elsif ($rr->type eq 'AAAA') {
				my $haystack = new Net::IP($rr->address .  "/$cidr6");
				if ($haystack->overlaps($ipv6) != $IP_NO_OVERLAP) {
					$self->match($request, $response);
					return 1;
				}
			}
			elsif ($rr->type eq 'CNAME') {
				# ignore - we should have gotten the A records anyway
			}
			else {
				warn "A: Unexpected RR type " . $rr->type;
			}
		}
	}
	return undef;
}

sub match {
    my ($self, $request, $response) = @_;
	print "Match: Request = $request\n";
	print "Match: Response = $response\n";
    my $qualifier = $self->{Qualifier};
    my $result = QUALIFIER_RESULT_MAP->{$qualifier};
    die "Unknown qualifier '$qualifier'" unless defined $result;
    $response->done($result, "Matched mechanism"); # XXX Be specific
    return 1;
}

sub error {
    my ($self, $request, $response, $result, $message) = @_;
	# XXX Be specific
    $response->done($result, "Error in mechanism: $message");
}

sub expand {
    my ($self, $request, $response, $string) = @_;

	my $out = '';
	pos($string) = 0;
	while ($string =~ m/\G(.*)%(.)/mscg) {
		$out .= $1;
		my $key = $2;
		if ($key eq '{') {
			if ($string =~ m/\G([slodiphcrt])([0-9]?)(r?)([-\.+,_=\/]?)}/mscg) {

				my ($char, $arg, $rev, $sep) = ($1, $2, $3, $4);
				my $value;
				if ($char eq 's') {
					$value = $request->{SenderLocalPart} . '@' .
							$request->{Sender};
				}
				elsif ($char eq 'l') {
					$value = $request->{SenderLocalPart} || '';
				}
				elsif ($char eq 'o') {
					$value = $request->{Sender};
				}
				elsif ($char eq 'd') {
					$value = $request->{Domain};
				}
				elsif ($char eq 'i') {
					if (defined $request->{IPv4}) {
						$value = $request->{IPv4}->ip;
					}
					else {
						$value = $request->{IPv6}->ip;
					}
				}
				elsif ($char eq 'p') {
					$value = "XXX.XXX";	# XXX FIXME.
				}
				elsif ($char eq 'v') {
					if (defined $request->{IPv4}) {
						$value = "in-addr";
					}
					else {
						$value = "ip6";
					}
				}
				elsif ($char eq 'h') {
					# XXX This should be Sender.
					$value = 'MACRO-H';
				}
				elsif ($char eq 'c') {
					# XXX
					$value = 'MACRO-C';
				}
				elsif ($char eq 'r') {
					# XXX
					$value = 'MACRO-R';
				}
				elsif ($char eq 't') {
					# XXX
					$value = 'MACRO-T';
				}
				else {
					die "Unknown macro '$char'!";
				}
				if ($arg || $rev) {
					$sep ||= '.';
					my @list = split(/$sep/, $value);
					@list = reverse @list if $rev;
					splice(@list, 0, $#list - $arg + 1) if $arg;
					$value = join('.', @list);
				}
				$out .= $value;
			}
			else {
				# XXX Generate PermError.
				$out .= '%{';
			}
		}
		elsif ($key eq '-') {
			$out .= '-';
		}
		elsif ($key eq '_') {
			$out .= ' ';
		}
		elsif ($key eq '%') {
			$out .= '%';
		}
	}
	$out .= substr($string, pos($string));

	print "Expand $string -> $out\n";
    return $out;
}

sub stringify {
    my ($self) = @_;
    my $class = ref($self);
	die("Must be called as an instance method")
					unless defined $class;
	$class =~ s/.*:://;
    my $string = lc $class . $self->{Value};
#    $string .= $self->{Domain};
#    $string .= $self->{IP4_Network} if defined($self->{IP4_Network});
#    $string .= $self->{IP6_Network} if defined($self->{IP6_Network});
#    $string .= $self->{IP4_CIDR_Length} if defined($self->{IP4_CIDR_Length});
#    $string .= $self->{IP6_CIDR_Length} if defined($self->{IP6_CIDR_Length});
	return $string;
}

1;
