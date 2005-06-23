package Mail::SPF::Base;

use strict;
use warnings;
use vars qw(@ISA @EXPORT_OK %EXPORT_TAGS);
use Exporter;

@ISA = qw(Exporter);

sub new {
        my $class = shift;
        my $self = ($#_ == 0) ? { %{ (shift) } } : { @_ };
        return bless $self, $class;
}

1;
