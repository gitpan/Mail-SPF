package Mail::SPF::Record;

use strict;
use warnings;
use base qw(Mail::SPF::Base);
use vars qw($TAG_SPF1 $TAG_SPF2_0);
use Mail::SPF::Mech qw(%SPF_MECH_CLASSES);
use Mail::SPF::Mech::A;
use Mail::SPF::Mech::All;
use Mail::SPF::Mech::Exists;
use Mail::SPF::Mech::IP4;
use Mail::SPF::Mech::IP6;
use Mail::SPF::Mech::Include;
use Mail::SPF::Mech::MX;
use Mail::SPF::Mech::PTR;
use Mail::SPF::Response qw(:result);

$TAG_SPF1 = qr/^v=spf1\b/;
$TAG_SPF2_0 = qr/^spf2\.0\b/;

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	$self->parse(delete $self->{Packet}, delete $self->{Response});
	return $self;
}

sub parse {
	my ($self, $packet, $response) = @_;
	my @answer = $packet->answer;
	foreach (@answer) {
		next unless $_->type eq 'TXT';
		my $txt = $_->txtdata;
		if ($txt =~ /$TAG_SPF1/o) {
			return $self->parse_spf1($txt, $response);
		}
		elsif ($txt =~ /$TAG_SPF2_0/o) {
		}
	}
	# XXX Don't actually die - return something sensible.
	$response->error("Failed to find a valid SPF record.");
	$response->done(SPF_RESULT_NONE,
					"Failed to find a valid SPF record.");
	return undef;
}

sub parse_spf1 {
	my ($self, $txt, $response) = @_;
	my @txt = split(/\s+/, $txt);
	shift @txt; # v=spf1

	foreach my $term (@txt) {
		if ($term =~ m/^([A-Z][A-Z0-9-_.]*)=(.*)/i) {
			# Modifier
			my ($name, $value) = ($1, $2);;
			my $mod = new Mail::SPF::Mod(
							Name	=> $name,
							Value	=> $value,
								);
			push(@{ $self->{Modifiers} }, $mod);
		}
		elsif ($term =~ m/^([~+?-]?)([a-z]+)((?:[\/:].*)?)$/) {
			# Mechanism
			my ($qual, $name, $value) = ($1, $2, $3);
			my $class = $SPF_MECH_CLASSES{$name};
			if ($class) {
				my $mech = $class->new(
								Qualifier	=> $qual,
								Value		=> $value,
								Response	=> $response,
									);
				delete $mech->{Response};
				use Data::Dumper;
				print Dumper($mech);
				push(@{ $self->{Mechanisms} }, $mech);
			}
			else {
				$response->error("No such mechanism '$name'")
								unless $class;
			}
		}
		else {
			$response->error(
				"'$term' is neither a mechanism nor a modifier."
					);
		}
	}
	return 1;
}

sub stringify {
	my ($self) = @_;
	my @mech = map { $_->stringify } @{ $self->{Mechanisms} };
	my @mod = map { $_->stringify } @{ $self->{Modifiers} };
	return "v=spf1 " . join(" ", @mech, @mod);
}

sub interp {
	my ($self, $request, $response) = @_;
	foreach my $mech (@{ $self->{Mechanisms} }) {
		return 1 if $mech->interp($self, $request, $response);
	}
	foreach my $mod (@{ $self->{Modifiers} }) {
		if ($mod->{Name} eq 'redirect') {
			my $server = $self->{Server};
			my $target = $mod->get_value($request);
			my $record = $server->get_record($target, $response);
			unless ($record) {
				$response->done(SPF_RESULT_PERMERROR,
								"No record for redirect '$target'");
			}
			$request->{Domain} = $target;
			return $record->interp($request, $response);
		}
	}
	$response->done(SPF_RESULT_NEUTRAL,
					'No mechanism or modifier matched.');
	return undef;
}

1;
