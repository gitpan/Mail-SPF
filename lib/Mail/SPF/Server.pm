package Mail::SPF::Server;

use strict;
use warnings;
use base qw(Mail::SPF::Base);
use Net::DNS::Resolver;
use Mail::SPF::Record;
use Mail::SPF::Response qw(:result);

sub new {
	my $class = shift;
	my $self = $class->SUPER::new(@_);
	$self->{Resolver} = new Net::DNS::Resolver();
	return $self;
}

sub get_dns {
	my ($self, $domain, $type) = @_;
	print "Query $domain $type\n";
	my $packet = $self->{Resolver}->query($domain, $type);
	return undef unless $packet;
	my $header = $packet->header;
	return undef if $header->rcode eq 'NXDOMAIN';
	return $packet;
}

sub get_record {
	my ($self, $domain, $response) = @_;
	my $packet = $self->get_dns($domain, 'TXT');
	unless ($packet) {
		$response->error("No DNS data available for $domain");
		return undef;
	}
	return new Mail::SPF::Record(
			Server		=> $self,
			Domain		=> $domain,
			Packet		=> $packet,
			Response	=> $response,
				);
}

sub query {
	my ($self, $request) = @_;
	my $response = new Mail::SPF::Response(
					Request	=> $request,
						);
	unless ($request->{Scope} eq 'mfrom') {
	}
	my $record = $self->get_record($request->{Sender}, $response);
	unless ($record) {
		$response->done(SPF_RESULT_NONE,
						"No record for '$request->{Sender}'");
		return $response;
	}
	$request->{Domain} = $request->{Sender};
	$record->interp($request, $response);
	return $response;
}

1;
