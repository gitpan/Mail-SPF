package Mail::SPF::Mech::Include;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

use Mail::SPF::Response qw(:result);

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
	$self->parse_domain_spec($response, 1);
	$self->parse_end($response);
	return $self;
}

# | Pass        | match
# | Fail        | not match
# | SoftFail    | not match
# | Neutral     | not match
# | TempError   | throw TempError
# | PermError   | throw PermError
# | None        | throw PermError

sub interp {
	my ($self, $record, $request, $response) = @_;

	my $domain = $self->get_domain_spec($request, $response);
	return 1 unless $domain;
	my $subrecord = $record->{Server}->get_record($domain, $response);
	unless ($subrecord) {
		$self->error($request, $response, SPF_RESULT_TEMPERROR,
						'No SPF record found');
		return 1;
	}
	my $saved = $request->{Domain};
	$request->{Domain} = $domain;
	if ($subrecord->interp($request, $response)) {
		my $code = $response->{Code};
		if ($code eq SPF_RESULT_PASS) {
			return 1;
		}
		elsif (($code eq SPF_RESULT_FAIL)
			|| ($code eq SPF_RESULT_SOFTFAIL)
			|| ($code eq SPF_RESULT_NEUTRAL)) {
			$response->done(undef, undef);
		}
		elsif ($code eq SPF_RESULT_TEMPERROR) {
			# XXX Use message
			$self->error($request, $response, SPF_RESULT_TEMPERROR, '');
		}
		elsif (($code eq SPF_RESULT_PERMERROR)
			|| ($code eq SPF_RESULT_NONE)) {
			# XXX Use message
			$self->error($request, $response, SPF_RESULT_PERMERROR, '');
		}
	}

	return undef;
}

1;
