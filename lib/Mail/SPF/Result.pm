#
# Mail::SPF::Result
# SPF result class.
#
# (C) 2005-2006 Julian Mehnle <julian@mehnle.net>
# $Id: Result.pm 25 2006-11-15 15:58:51Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Result;

=head1 NAME

Mail::SPF::Result - SPF result class

=cut

use warnings;
use strict;

use base 'Error', 'Mail::SPF::Base';
    # An SPF result is not really a code exception in ideology, but in form.
    # The Error base class fits our purpose, anyway.

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant result_classes_by_code => {
    pass        => 'Mail::SPF::Result::Pass',
    fail        => 'Mail::SPF::Result::Fail',
    softfail    => 'Mail::SPF::Result::SoftFail',
    neutral     => 'Mail::SPF::Result::Neutral',
    none        => 'Mail::SPF::Result::None',
    error       => 'Mail::SPF::Result::Error',
    permerror   => 'Mail::SPF::Result::PermError',
    temperror   => 'Mail::SPF::Result::TempError'
};

# Interface:
##############################################################################

=head1 SYNOPSIS

For the general usage of I<Mail::SPF::Result> objects in code that calls
Mail::SPF, see L<Mail::SPF>.  For the detailed interface of I<Mail::SPF::Result>
and its derivatives, see below.

=head2 Throwing results

    package Mail::SPF::Foo;
    use Error ':try';
    use Mail::SPF::Result;
    
    sub foo {
        if (...) {
            throw Mail::SPF::Result::Pass($request);
        }
        else {
            throw Mail::SPF;;Result::PermError($request, 'Invalid foo');
        }
    }

=head2 Catching results

    package Mail::SPF::Bar;
    use Error ':try';
    use Mail::SPF::Foo;
    
    try {
        Mail::SPF::Foo->foo();
    }
    catch Mail::SPF::Result with {
        my ($result) = @_;
        my $code     = $result->code;
        my $request  = $result->request;
        my $text     = $result->text;
    };

=cut

# Implementation:
##############################################################################

=head1 DESCRIPTION

An object of class B<Mail::SPF::Result> represents the result of an SPF
request.

There is usually no need to construct an SPF result object directly using the
C<new> constructor.  Instead, use the C<throw> class method to signal to the
calling code that a definite SPF result has been determined.  In other words,
use Mail::SPF::Result and its derivatives just like exceptions.  See L<Error>
or L<perlfunc/eval> for how to handle exceptions in Perl.

=head2 Constructor

The following constructor is provided:

=over

=item B<new($request)>: returns I<Mail::SPF::Result>

=item B<new($request, $text)>: returns I<Mail::SPF::Result>

Creates a new SPF result object and associates the given I<Mail::SPF::Request>
object with it.  An optional result text may be specified.

=cut

sub new {
    my ($self, @args) = @_;
    
    local $Error::Depth = $Error::Depth + 1;
    
    $self =
        ref($self) ?                        # Was new() involed on a class or an object?
            bless({ %$self }, ref($self))   # Object: clone source result object.
        :   $self->SUPER::new();            # Class:  create new result object.
    
    # Set/override fields:
    $self->{request} = shift(@args) if @args;
    defined($self->{request})
        or throw Mail::SPF::EOptionRequired('Request object required');
    $self->{'-text'} = shift(@args) if @args;
    
    return $self;
}

=back

=head2 Class methods

The following class methods are provided:

=over

=item B<throw($request)>: throws I<Mail::SPF::Result>

=item B<throw($request, $text)>: throws I<Mail::SPF::Result>

Throws a new SPF result object, associating the given I<Mail::SPF::Request>
with it.  An optional result text may be specified.

=cut

sub throw {
    my ($self, @args) = @_;
    local $Error::Depth = $Error::Depth + 1;
    $self = $self->new(@args);
    die($Error::THROWN = $self);
}

=item B<name>: returns I<string>

Returns the trailing part of the name of the I<Mail::SPF::Result::*> class on
which it is invoked.  For example, returns C<NeutralByDefault> if invoked on
I<Mail::SPF::Result::NeutralByDefault>.  This method may also be used as an
instance method.

=cut

sub name {
    my ($self) = @_;
    my $class = ref($self) || $self;
    return $class =~ /^Mail::SPF::Result::(\w+)$/ ? $1 : $class;
}

=item B<code>: returns I<string>

Returns the result code (C<"pass">, C<"fail">, C<"softfail">, C<"neutral">,
C<"none">, C<"error">, C<"permerror">, C<"permerror">) of the
I<Mail::SPF::Result::*> class on which it is invoked.  This method may also be
used as an instance method.

=item B<class_by_code($code)>: returns I<class>

Maps the given result code to the corresponding I<Mail::SPF::Result::*> class.
If an unknown result code was specified, returns B<undef>.

=cut

sub class_by_code {
    my ($self, $code) = @_;
    return $self->result_classes_by_code->{lc($code)};
}

=item B<is_code($code)>: returns I<boolean>

If the class (or object) on which this method is invoked represents the given
result code (or a derivative code), returns B<true>.  Returns B<false>
otherwise.  This method may also be used as an instance method.

For example, C<< Mail::SPF::Result::Pass->is_code('pass') >> returns B<true>.

=cut

sub is_code {
    my ($self, $code) = @_;
    my $suspect_class = $self->class_by_code($code);
    return FALSE if not defined($suspect_class);
    return $self->isa($suspect_class);
}

=back

=head2 Instance methods

The following instance methods are provided:

=over

=item B<throw>: throws I<Mail::SPF::Result>

=item B<throw($request)>: throws I<Mail::SPF::Result>

=item B<throw($request, $text)>: throws I<Mail::SPF::Result>

Re-throws an existing SPF result object.  If a I<Mail::SPF::Request> object is
specified, associates it with the result object, replacing the prior request
object.  If a result text is specified as well, overrides the prior result
text.

=item B<code>: returns I<string>

Returns the result code of the result object.

=item B<request>: returns I<Mail::SPF::Request>

Returns the SPF request that led to the result at hand.

=cut

# Read-only accessor:
__PACKAGE__->make_accessor('request', TRUE);

=item B<text>: returns I<string>

Returns the text message of the result object.

=item B<stringify>: returns I<string>

Returns the result's name and text message formatted as a string.  You can
simply use a Mail::SPF::Result object as a string for the same effect, see
L</OVERLOADING>.

=cut

sub stringify {
    my ($self) = @_;
    return sprintf("%s (%s)", $self->name, $self->SUPER::stringify);
}

=back

=head1 OVERLOADING

If a Mail::SPF::Result object is used as a I<string>, the L</stringify> method
is used to convert the object into a string.

=head1 RESULT CLASSES

The following result classes are provided:

=over

=item I<Mail::SPF::Result::Pass>

=item I<Mail::SPF::Result::Fail>

The following additional instance method is provided:

=over

=item B<explanation>: returns I<string>

Returns the explanation string for the C<fail> result.  Be aware that the
explanation is provided by a potentially malicious party and thus should not be
trusted.  See RFC 4408, 10.5, for a more detailed discussion of this issue.

=back

=item I<Mail::SPF::Result::SoftFail>

=item I<Mail::SPF::Result::Neutral>

=item I<Mail::SPF::Result::NeutralByDefault>

This is a special-case of the C<neutral> result that is thrown as a default
when "falling off" the end of the record during evaluation.  See RFC 4408,
4.7.

=item I<Mail::SPF::Result::None>

=item I<Mail::SPF::Result::Error>

The following sub-classes of I<Mail::SPF::Result::Error> are provided:

=over

=item I<Mail::SPF::Result::PermError>

=item I<Mail::SPF::Result::TempError>

=back

=cut

package Mail::SPF::Result::Pass;
our @ISA = 'Mail::SPF::Result';
use constant code => 'pass';

package Mail::SPF::Result::Fail;
our @ISA = 'Mail::SPF::Result';

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant code => 'fail';

sub new {
    my ($self, @args) = @_;
    local $Error::Depth = $Error::Depth + 1;
    $self = $self->SUPER::new(@args);
    $self->{explanation} = $self->{request}->state('explanation')->expand;
    return $self;
}

# Read-only accessor:
__PACKAGE__->make_accessor('explanation', TRUE);

package Mail::SPF::Result::SoftFail;
our @ISA = 'Mail::SPF::Result';
use constant code => 'softfail';

package Mail::SPF::Result::Neutral;
our @ISA = 'Mail::SPF::Result';
use constant code => 'neutral';

package Mail::SPF::Result::NeutralByDefault;
our @ISA = 'Mail::SPF::Result::Neutral';
    # This is a special-case of the Neutral result that is thrown as a default
    # when "falling off" the end of the record.  See Mail::SPF::Record::eval().

package Mail::SPF::Result::None;
our @ISA = 'Mail::SPF::Result';
use constant code => 'none';

package Mail::SPF::Result::Error;
our @ISA = 'Mail::SPF::Result';
use constant code => 'error';

package Mail::SPF::Result::PermError;
our @ISA = 'Mail::SPF::Result::Error';
use constant code => 'permerror';

package Mail::SPF::Result::TempError;
our @ISA = 'Mail::SPF::Result::Error';
use constant code => 'temperror';

=back

=head1 SEE ALSO

L<Mail::SPF>, L<Mail::SPF::Server>, L<Error>, L<perlfunc/eval>

L<RFC 4408|http://www.ietf.org/rfc/rfc4408.txt>

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Julian Mehnle <julian@mehnle.net>

=cut

package Mail::SPF::Result;

TRUE;
