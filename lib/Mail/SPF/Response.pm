package Mail::SPF::Response;

use strict;
use warnings;
use vars qw(@EXPORT_OK %EXPORT_TAGS);
use constant {
	SPF_RESULT_PASS 		=> 0,
	SPF_RESULT_FAIL			=> 1,
	SPF_RESULT_SOFTFAIL		=> 2,
	SPF_RESULT_NEUTRAL		=> 3,
	SPF_RESULT_PERMERROR	=> 4,
	SPF_RESULT_TEMPERROR	=> 5,
	SPF_RESULT_NONE			=> 6,
		};

@EXPORT_OK = qw(
	SPF_RESULT_PASS 
	SPF_RESULT_FAIL
	SPF_RESULT_SOFTFAIL
	SPF_RESULT_NEUTRAL
	SPF_RESULT_PERMERROR
	SPF_RESULT_TEMPERROR
	SPF_RESULT_NONE
		);
%EXPORT_TAGS = (result => \@EXPORT_OK);

use base qw(Mail::SPF::Base);

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	return $self;
}

sub done {
	my ($self, $result, $message) = @_;
	$self->{Code} = $result;
	return $self;
}

sub error {
	my ($self, $message) = @_;
	push( @{ $self->{Errors} }, $message);
}

sub get_result {
	my ($self) = @_;
	my $code = $self->{Code};

	if ($code == SPF_RESULT_PASS) {
		return "Pass";
	}
	elsif ($code == SPF_RESULT_FAIL) {
		return "Fail";
	}
	elsif ($code == SPF_RESULT_SOFTFAIL) {
		return "SoftFail";
	}
	elsif ($code == SPF_RESULT_NEUTRAL) {
		return "Neutral";
	}
	elsif ($code == SPF_RESULT_PERMERROR) {
		return "PermError";
	}
	elsif ($code == SPF_RESULT_TEMPERROR) {
		return "TempError";
	}
	elsif ($code == SPF_RESULT_NONE) {
		return "None";
	}
	else {
		die "Unknown or invalid code $code";
	}
}

1;
