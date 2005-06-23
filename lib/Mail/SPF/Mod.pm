package Mail::SPF::Mod;

use strict;
use warnings;
use base 'Mail::SPF::Base';

# XXX Really, we should have a common superclass.
sub expand {
	return Mail::SPF::Mech::expand(@_);
}

sub get_name {
	my ($self) = @_;
	return $self->{Name};
}

sub get_value {
	my ($self, $request) = @_;
	return $self->expand($self->{Value}, $request);
}

sub stringify {
	my ($self) = @_;
	return "$self->{Name}=$self->{Value}";
}

1;
