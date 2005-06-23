package Mail::SPF::Mech::All;

use strict;
use warnings;
use base 'Mail::SPF::Mech';

sub new {
    my $class = shift;
    my $self = $class->SUPER::new(@_);
	my $response = delete $self->{Response};
    $self->parse_end($response);
    return $self;
}

sub interp {
	my ($self, $record, $request, $response) = @_;
	return $self->match($request, $response);
}

1;
