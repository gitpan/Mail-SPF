package Mail::SPF::Mod;

use strict;
use warnings;
use base 'Mail::SPF::Base';

# Template

sub exec {
        return;
}

sub expand {
        my ($self, $request, $string) = @_;
        # XXX Perform expansion!
        return $string;
}

1;
