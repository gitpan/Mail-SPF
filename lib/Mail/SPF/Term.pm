#
# Mail::SPF::Term
# SPF record term class.
#
# (C) 2005-2006 Julian Mehnle <julian@mehnle.net>
#     2005      Shevek <cpan@anarres.org>
# $Id: Term.pm 16 2006-11-04 23:39:16Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Term;

=head1 NAME

Mail::SPF::Term - SPF record term class

=cut

use warnings;
use strict;

use base 'Mail::SPF::Base';

use overload
    '""' => 'stringify';

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant name_pattern   => qr/ \p{IsAlpha} [\p{IsAlnum}\-_.]* /x;

=head1 DESCRIPTION

An object of class B<Mail::SPF::Term> represents a term within an SPF record.
Mail::SPF::Term cannot be instantiated directly.  Create an instance of a
concrete sub-class instead.

=head2 Constructor

The following constructor is provided:

=over

=item B<new(%options)>: returns I<Mail::SPF::Term>

I<Abstract>.  Creates a new SPF record term object.

%options is a list of key/value pairs, however Mail::SPF::Term itself specifies
no constructor options.

=item B<new_from_string($text)>: returns I<Mail::SPF::Term>; throws
I<Mail::SPF::ENothingToParse>, I<Mail::SPF::EInvalidTerm>

I<Abstract>.  Creates a new SPF record term object by parsing the given
string.

=cut

sub new_from_string {
    my ($self, $text, %options) = @_;
    $self = $self->new(%options, text => $text);
    $self->parse();
    return $self;
}

=back

=head2 Class methods

The following class methods are provided:

=over

=item B<name_pattern>: returns I<Regexp>

Returns a regular expression that matches any legal name for an SPF record
term.

=back

=head2 Instance methods

The following instance methods are provided:

=over

=item B<text>: returns I<string>; throws I<Mail::SPF::ENoUnparsedText>

Returns the unparsed text of the term.  Throws a I<Mail::SPF::ENoUnparsedText>
exception if the term was created synthetically instead of being parsed, and no
text was provided.

=cut

sub text {
    my ($self) = @_;
    defined($self->{text})
        or throw Mail::SPF::ENoUnparsedText;
    return $self->{text};
}

=item B<name>: returns I<string>

I<Abstract>.  Returns the name of the term.

=back

=head1 SEE ALSO

L<Mail::SPF>, L<Mail::SPF::Record>, L<Mail::SPF::Mech>, L<Mail::SPF::Mod>

L<http://www.ietf.org/rfc/rfc4408.txt|"RFC 4408">

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Julian Mehnle <julian@mehnle.net>, Shevek <cpan@anarres.org>

=cut

TRUE;
