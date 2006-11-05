#
# Mail::SPF::Mech
# SPF record mechanism class.
#
# (C) 2005-2006 Julian Mehnle <julian@mehnle.net>
#     2005      Shevek <cpan@anarres.org>
# $Id: Mech.pm 16 2006-11-04 23:39:16Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Mech;

=head1 NAME

Mail::SPF::Mech - SPF record mechanism base class

=cut

use warnings;
use strict;

use base 'Mail::SPF::Term';

use Error ':try';
use NetAddr::IP;

use Mail::SPF::Record;
use Mail::SPF::MacroString;
use Mail::SPF::Result;
use Mail::SPF::Util;

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant {
    default_qualifier           => Mail::SPF::Record->default_qualifier,
    default_ipv4_prefix_length  => 32,
    default_ipv6_prefix_length  => 128
};

use constant {
    qualifier_pattern   => qr/[+\-~?]/,
    name_pattern        => qr/ ${\__PACKAGE__->SUPER::name_pattern} (?= : | \x20 | $ ) /x,
    qnum_pattern        => qr/ \d | [1-9]\d | 1\d\d | 2[0-4]\d | 25[0-5] /x
};

=head1 DESCRIPTION

An object of class B<Mail::SPF::Mech> represents a mechanism within an SPF
record.  Mail::SPF::Mech cannot be instantiated directly.  Create an instance
of a concrete sub-class instead.

=head2 Constructors

The following constructors are provided:

=over

=item B<new(%options)>: returns I<Mail::SPF::Mech>

I<Abstract>.  Creates a new SPF record mechanism object.

%options is a list of key/value pairs representing any of the following
options:

=over

=item B<text>

A I<string> denoting the unparsed text of the mechanism.

=item B<qualifier>

A single-character I<string> denoting the qualifier of the mechanism.  Any of
the following may be specified: B<'+'> (C<Pass>), B<'-'> (C<Fail>),
B<'~'> (C<SoftFail>), B<'?'> (C<Neutral>).  See RFC 4408, 4.6.2 and 2.5, for
their meanings.  Defaults to B<'+'>.

=item B<name>

A I<string> denoting the name of the mechanism.  I<Required> if a generic
I<Mail::SPF::Mech> object (as opposed to a specific sub-class) is being
constructed.  

=item B<ip_network>

A I<NetAddr::IP> object denoting an optional IP address network parameter of
the mechanism.  Can be either an IPv4 or an IPv6 address, with an optional
network prefix length.  IPv4-mapped IPv6 addresses (e.g. '::ffff:192.168.0.1')
must I<not> be specified directly, but as plain IPv4 addresses.

=item B<domain_spec>

Either a plain I<string> or a I<Mail::SPF::MacroString> object denoting an
optional C<domain-spec> parameter of the mechanism.

=item B<ipv4_prefix_length>

=item B<ipv6_prefix_length>

A I<string> denoting an optional IPv4 or IPv6 network prefix length for the
C<domain_spec> of the mechanism.  Note that these options do not apply to the
C<ip_network> option, which already includes an optional network prefix
length.

=back

Other options may be specified by sub-classes of Mail::SPF::Mech.

=cut

sub new {
    my ($self, %options) = @_;
    $self->class ne __PACKAGE__
        or throw Mail::SPF::EAbstractClass;
    $self = $self->SUPER::new(%options);
    $self->{parse_text} = $self->{text} if not defined($self->{parse_text});
    #$self->{qualifier} ||= $self->default_qualifier;  # Defaulting already happens in qualifier().
    $self->{domain_spec} = Mail::SPF::MacroString->new(text => $self->{domain_spec})
        if  defined($self->{domain_spec})
        and not UNIVERSAL::isa($self->{domain_spec}, 'Mail::SPF::MacroString');
    return $self;
}

=item B<new_from_string($text)>: returns I<Mail::SPF::Mech>; throws
I<Mail::SPF::ENothingToParse>, I<Mail::SPF::EInvalidMech>

I<Abstract>.  Creates a new SPF record mechanism object by parsing the given
string.

=back

=head2 Class methods

The following class methods are provided:

=over

=item B<default_qualifier>: returns I<string>

Returns the default qualifier, i.e. B<'+'>.

=item B<default_ipv4_prefix_length>: returns I<integer>

Returns the default IPv4 network prefix length, i.e. B<32>.

=item B<default_ipv6_prefix_length>: returns I<integer>

Returns the default IPv6 network prefix length, i.e. B<128>.

=item B<qualifier_pattern>: returns I<Regexp>

Returns a regular expression that matches any legal mechanism qualifier, i.e. B<'+'>,
B<'-'>, B<'~'>, or B<'?'>.

=item B<name_pattern>: returns I<Regexp>

Returns a regular expression that matches any legal mechanism name.

=back

=head2 Instance methods

The following instance methods are provided:

=over

=cut

sub parse {
    my ($self) = @_;
    defined($self->{parse_text})
        or throw Mail::SPF::ENothingToParse('Nothing to parse for mechanism');
    $self->parse_qualifier();
    $self->parse_name();
    $self->parse_params();
    $self->parse_end();
    return;
}

sub parse_qualifier {
    my ($self) = @_;
    if ($self->{parse_text} =~ s/^(${\$self->qualifier_pattern})?//) {
        $self->{qualifier} = $1 || $self->default_qualifier;
    }
    else {
        throw Mail::SPF::EInvalidMechQualifier(
            "Invalid qualifier encountered in '" . $self->text . "'");
    }
    return;
}

sub parse_name {
    my ($self) = @_;
    if ($self->{parse_text} =~ s/^(${\$self->name_pattern})($|:(?=\S))//i) {
        $self->{name} = $1;
    }
    else {
        throw Mail::SPF::EInvalidMech(
            "Unexpected mechanism name encountered in '" . $self->text . "'");
    }
    return;
}

sub parse_params {
    my ($self) = @_;
    # Parse generic string of parameters text (should be overridden in sub-classes):
    if ($self->{parse_text} =~ s/^(.*)//) {
        $self->{params_text} = $1;
    }
    return;
}

sub parse_domain_spec {
    my ($self, $required) = @_;
    if ($self->{parse_text} =~ s#^([^\s/]+)\.?##) {
        $self->{domain_spec} = Mail::SPF::MacroString->new(text => $1);
    }
    elsif ($required) {
        throw Mail::SPF::ETermDomainSpecExpected(
            "Missing required domain-spec in '" . $self->text . "'");
    }
    return;
}

sub parse_ipv4_address {
    my ($self, $required) = @_;
    my $QNUM = $self->qnum_pattern;
    if ($self->{parse_text} =~ s/^($QNUM(?:\.$QNUM){3})//) {
        $self->{ip_address} = $1;
    }
    elsif ($required) {
        throw Mail::SPF::ETermIPv4AddressExpected(
            "Missing required IPv4 address in '" . $self->text . "'");
    }
    return;
}

sub parse_ipv4_prefix_length {
    my ($self, $required) = @_;
    if ($self->{parse_text} =~ s#^/(\d+)## and $1 >= 0 and $1 <= 32) {
        $self->{ipv4_prefix_length} = $1;
    }
    elsif (not $required) {
        $self->{ipv4_prefix_length} = $self->default_ipv4_prefix_length;
    }
    else {
        throw Mail::SPF::ETermIPv4PrefixLengthExpected(
            "Missing required IPv4 prefix length in '" . $self->text . "'");
    }
    return;
}

sub parse_ipv4_network {
    my ($self, $required) = @_;
    $self->parse_ipv4_address($required);
    $self->parse_ipv4_prefix_length();
    $self->{ip_network} = Mail::SPF::Util->ipv4_address_to_ipv6(
        NetAddr::IP->new($self->{ip_address}, $self->{ipv4_prefix_length}));
    return;
}

sub parse_ipv6_address {
    my ($self, $required) = @_;
    if ($self->{parse_text} =~ s/^([:\p{IsXDigit}]+)//) {
        $self->{ip_address} = $1;
    }
    elsif ($required) {
        throw Mail::SPF::ETermIPv6AddressExpected(
            "Missing required IPv6 address in '" . $self->text . "'");
    }
    return;
}

sub parse_ipv6_prefix_length {
    my ($self, $required) = @_;
    if ($self->{parse_text} =~ s#^//(\d+)## and $1 >= 0 and $1 <= 128) {
        $self->{ipv6_prefix_length} = $1;
    }
    elsif (not $required) {
        $self->{ipv6_prefix_length} = $self->default_ipv6_prefix_length;
    }
    else {
        throw Mail::SPF::ETermIPv6PrefixLengthExpected(
            "Missing required IPv6 prefix length in '" . $self->text . "'");
    }
    return;
}

sub parse_ipv6_network {
    my ($self, $required) = @_;
    $self->parse_ipv6_address($required);
    $self->parse_ipv6_prefix_length();
    $self->{ip_network} = NetAddr::IP->new(
        $self->{ip_address}, $self->{ipv6_prefix_length});
    return;
}

sub parse_ipv4_ipv6_prefix_lengths {
    my ($self) = @_;
    $self->parse_ipv4_prefix_length();
    if (
        defined($self->{ipv4_prefix_length}) and  # an IPv4 prefix length has been parsed, and
        $self->{parse_text} =~ s#^/##             # another slash is following
    ) {
        # Parse an IPv6 prefix length:
        $self->parse_ipv6_prefix_length(TRUE);
    }
    return;
}

sub parse_end {
    my ($self) = @_;
    $self->{parse_text} eq ''
        or throw Mail::SPF::EJunkInTerm("Junk encountered in mechanism '" . $self->text . "'");
    delete($self->{parse_text});
    return;
}

=item B<text>: returns I<string>; throws I<Mail::SPF::ENoUnparsedText>

Returns the unparsed text of the mechanism.  Throws a
I<Mail::SPF::ENoUnparsedText> exception if the mechanism was created
synthetically instead of being parsed, and no text was provided.

=item B<qualifier>: returns I<string>

Returns the qualifier of the mechanism.  See the description of the C<new>
constructor's C<qualifier> option.

=cut

sub qualifier {
    my ($self) = @_;
    # Read-only!
    return $self->{qualifier} || $self->default_qualifier;
}

=item B<name>: returns I<string>

Returns the name of the mechanism.

=cut

# Make read-only accessor:
__PACKAGE__->make_accessor('name', TRUE);

=item B<params>: returns I<string>

I<Abstract>.  Returns the mechanism's parameters formatted as a string.

A sub-class of Mail::SPF::Mech does not have to implement this method if it
supports no parameters.

=item B<stringify>: returns I<string>

Formats the mechanism's qualifier, name, and parameters as a string and returns
it.  (A qualifier that matches the default of B<'+'> is omitted.)  You can
simply use a Mail::SPF::Mech object as a string for the same effect, see
L<"OVERLOADING">.

=cut

sub stringify {
    my ($self) = @_;
    my $params = $self->can('params') ? $self->params : undef;
    return sprintf(
        '%s%s%s',
        $self->qualifier eq $self->default_qualifier ? '' : $self->qualifier,
        $self->name,
        defined($params) ? ':' . $params : ''
    );
}

=item B<domain($server, $request)>: returns I<string>

Returns the target domain of the mechanism.  Depending on whether the mechanism
does have an explicit C<domain_spec> parameter, this is either the
macro-expanded C<domain_spec> parameter, or the request's authority domain
(see L<Mail::SPF::Request/authority_domain>) otherwise.  Both a
I<Mail::SPF::Server> and a I<Mail::SPF::Request> object are required for
resolving the target domain.

=cut

sub domain {
    my ($self, $server, $request) = @_;
    defined($server)
        or throw Mail::SPF::EOptionRequired('Server object required for target domain resolution');
    defined($request)
        or throw Mail::SPF::EOptionRequired('Request object required for target domain resolution');
    return
        defined($self->{domain_spec}) ?
            lc($self->{domain_spec}->expand($server, $request))
        :   $request->domain;
}

=item B<match($server, $request)>: returns I<boolean>; throws I<Mail::SPF::Result::Error>

I<Abstract>.  Checks whether the mechanism matches the parameters of the given
request (see L<Mail::SPF::Request>) and returns B<true> if it does, or B<false>
otherwise.  In any case, takes both a I<Mail::SPF::Server> and a
I<Mail::SPF::Request> object.

This method is abstract and must be implemented by sub-classes of
Mail::SPF::Mech.

=item B<match_in_domain($server, $request)>: returns I<boolean>;
throws I<Mail::SPF::Result::Error>

=item B<match_in_domain($server, $request, $domain)>: returns I<boolean>;
throws I<Mail::SPF::Result::Error>

Checks whether the mechanism's target domain name (that is, any of its DNS C<A>
or C<AAAA> records) matches the given request's IP address (see
L<Mail::SPF::Request/ip_address>), and returns B<true> if it does, or B<false>
otherwise.  If an explicit domain is specified, it is used instead of the
mechanism's target domain.  The mechanism's IP network prefix lengths are
respected when matching DNS address records against the request's IP address.
See RFC 4408, 5, for the exact algorithm used.

This method exists mainly for the convenience of sub-classes of
Mail::SPF::Mech.

=cut

sub match_in_domain {
    my ($self, $server, $request, $domain) = @_;
    
    $domain ||= $self->domain($server, $request);
    
    my $ipv4_prefix_length  = $self->ipv4_prefix_length;
    my $ipv6_prefix_length  = $self->ipv6_prefix_length;
    my $addr_rr_type        = $request->ip_address->version == 4 ? 'A' : 'AAAA';
    
    my $packet = $server->dns_lookup($domain, $addr_rr_type);
    defined($packet) or next;
    foreach my $rr ($packet->answer) {
        if ($rr->type eq 'A') {
            my $network = NetAddr::IP->new($rr->address, $ipv4_prefix_length);
            return TRUE
                if $network->contains($request->ip_address);
        }
        elsif ($rr->type eq 'AAAA') {
            my $network = NetAddr::IP->new($rr->address, $ipv6_prefix_length);
            return TRUE
                if $network->contains($request->ip_address_v6);
        }
        elsif ($rr->type eq 'CNAME') {
            # TODO Does this case occur in the first place?
            warn('XXX: got a CNAME $rr (Mech.pm:379)');
            # Ignore -- we should have gotten the A/AAAA records anyway.
        }
        else {
            # TODO Generate debug info or ignore silently!
            warn(uc($self->name) . ': Unexpected RR type ' . $rr->type);
        }
    }
    return FALSE;
}

=back

=head1 OVERLOADING

If a Mail::SPF::Mech object is used as a I<string>, the C<stringify> method is
used to convert the object into a string.

=head1 SEE ALSO

L<Mail::SPF::Mech::All>,
L<Mail::SPF::Mech::IP4>,
L<Mail::SPF::Mech::IP6>,
L<Mail::SPF::Mech::A>,
L<Mail::SPF::Mech::MX>,
L<Mail::SPF::Mech::PTR>,
L<Mail::SPF::Mech::Exists>,
L<Mail::SPF::Mech::Include>

L<Mail::SPF>, L<Mail::SPF::Record>, L<Mail::SPF::Term>

L<http://www.ietf.org/rfc/rfc4408.txt|"RFC 4408">

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Julian Mehnle <julian@mehnle.net>, Shevek <cpan@anarres.org>

=cut

TRUE;
