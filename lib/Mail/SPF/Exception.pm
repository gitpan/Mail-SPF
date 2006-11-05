#
# Mail::SPF::Exception
# Mail::SPF exception classes.
#
# (C) 2006 Julian Mehnle <julian@mehnle.net>
# $Id: Exception.pm 16 2006-11-04 23:39:16Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Exception;

use warnings;
use strict;

use base 'Error';

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

sub new {
    my ($self, $text) = @_;
    local $Error::Depth = $Error::Depth + 1;
    #XXX $text = $self if not defined($text);
    return $self->SUPER::new(
        defined($text) ? (-text => $text) : ()
    );
}

sub stringify {
    my ($self) = @_;
    my $text = $self->SUPER::stringify;
    $text .= sprintf(" (%s) at %s line %d.\n", ref($self), $self->file, $self->line)
        if $text !~ /\n$/s;
    return $text;
}


# Generic Exceptions
##############################################################################

# Tried to call a class method as an instance method:
package Mail::SPF::EClassMethod;
our @ISA = qw(Mail::SPF::Exception);

sub new {
    my ($self) = @_;
    local $Error::Depth = $Error::Depth + 2;
    return $self->SUPER::new(
        sprintf('Pure class method %s called as an instance method', (caller($Error::Depth - 1))[3])
    );
}

# Tried to call an instance method as a class method:
package Mail::SPF::EInstanceMethod;
our @ISA = qw(Mail::SPF::Exception);

sub new {
    my ($self) = @_;
    local $Error::Depth = $Error::Depth + 2;
    return $self->SUPER::new(
        sprintf('Pure instance method %s called as a class method', (caller($Error::Depth - 1))[3])
    );
}

# Abstract class cannot be instantiated:
package Mail::SPF::EAbstractClass;
our @ISA = qw(Mail::SPF::Exception);

sub new {
    my ($self) = @_;
    local $Error::Depth = $Error::Depth + 2;
    return $self->SUPER::new('Abstract class cannot be instantiated');
}

# Missing required method option:
package Mail::SPF::EOptionRequired;
our @ISA = qw(Mail::SPF::Exception);

# Invalid value for method option:
package Mail::SPF::EInvalidOptionValue;
our @ISA = qw(Mail::SPF::Exception);

# Read-only value:
package Mail::SPF::EReadOnlyValue;
our @ISA = qw(Mail::SPF::Exception);


# Miscellaneous Errors
##############################################################################

# Invalid scope:
package Mail::SPF::EInvalidScope;
our @ISA = qw(Mail::SPF::Exception);

# DNS error:
package Mail::SPF::EDNSError;
our @ISA = qw(Mail::SPF::Exception);

# DNS timeout:
package Mail::SPF::EDNSTimeout;
our @ISA = qw(Mail::SPF::EDNSError);

# No suitable record found:
package Mail::SPF::ENoSuitableRecord;
our @ISA = qw(Mail::SPF::Exception);

# No unparsed text available:
package Mail::SPF::ENoUnparsedText;
our @ISA = qw(Mail::SPF::Exception);

# Unexpected term object encountered:
package Mail::SPF::EUnexpectedTermObject;
our @ISA = qw(Mail::SPF::Exception);

# Missing required context for macro expansion:
package Mail::SPF::EMacroExpansionCtxRequired;
our @ISA = qw(Mail::SPF::EOptionRequired);


# Parser Errors
##############################################################################

# Nothing to parse:
package Mail::SPF::ENothingToParse;
our @ISA = qw(Mail::SPF::Exception);

# Generic syntax error:
package Mail::SPF::ESyntaxError;
our @ISA = qw(Mail::SPF::Exception);

# Invalid record version:
package Mail::SPF::EInvalidRecordVersion;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Junk encountered in record:
package Mail::SPF::EJunkInRecord;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Invalid term:
package Mail::SPF::EInvalidTerm;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Junk encountered in term:
package Mail::SPF::EJunkInTerm;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Invalid modifier:
package Mail::SPF::EInvalidMod;
our @ISA = qw(Mail::SPF::EInvalidTerm);

# Duplicate global modifier:
package Mail::SPF::EDuplicateGlobalMod;
our @ISA = qw(Mail::SPF::EInvalidMod);

# Invalid mechanism:
package Mail::SPF::EInvalidMech;
our @ISA = qw(Mail::SPF::EInvalidTerm);

# Invalid mechanism qualifier:
package Mail::SPF::EInvalidMechQualifier;
our @ISA = qw(Mail::SPF::EInvalidMech);

# Missing required <domain-spec> in term:
package Mail::SPF::ETermDomainSpecExpected;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Missing required <ip4-network> in term:
package Mail::SPF::ETermIPv4AddressExpected;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Missing required <ip4-cidr-length> in term:
package Mail::SPF::ETermIPv4PrefixLengthExpected;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Missing required <ip6-network> in term:
package Mail::SPF::ETermIPv6AddressExpected;
our @ISA = qw(Mail::SPF::ESyntaxError);

# Missing required <ip6-cidr-length> in term:
package Mail::SPF::ETermIPv6PrefixLengthExpected;
our @ISA = qw(Mail::SPF::ESyntaxError);


package Mail::SPF::Exception;

TRUE;
