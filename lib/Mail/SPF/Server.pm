#
# Mail::SPF::Server
# Server class for processing SPF requests.
#
# (C) 2005-2006 Julian Mehnle <julian@mehnle.net>
#     2005      Shevek <cpan@anarres.org>
# $Id: Server.pm 25 2006-11-15 15:58:51Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Server;

=head1 NAME

Mail::SPF::Server - Server class for processing SPF requests

=cut

use warnings;
use strict;

use base 'Mail::SPF::Base';

use Error ':try';
use Net::DNS::Resolver;

use Mail::SPF::MacroString;
use Mail::SPF::Record;
use Mail::SPF::Result;

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant record_classes_by_version => {
    1   => 'Mail::SPF::v1::Record',
    2   => 'Mail::SPF::v2::Record'
};

use constant default_max_dns_interactive_terms  => 10;  # RFC 4408, 10.1/6
use constant default_max_name_lookups_per_term  => 10;  # RFC 4408, 10.1/7
sub default_max_name_lookups_per_mx_mech  { shift->max_name_lookups_per_term };
sub default_max_name_lookups_per_ptr_mech { shift->max_name_lookups_per_term };

use constant default_default_explanation        =>
    'Please see http://www.openspf.org/why.html?sender=%{S}&ip=%{I}&receiver=%{R}';

# Interface:
##############################################################################

=head1 SYNOPSIS

    use Mail::SPF;
    
    my $spf_server  = Mail::SPF::Server->new(
        # Optional default explanation:
        default_explanation => 'See http://www.%{d}/why/s=%{S};i=%{I};r=%{R}'
    );
    
    my $result      = $spf_server->process($request);

=cut

# Implementation:
##############################################################################

=head1 DESCRIPTION

B<Mail::SPF::Server> is a server class for processing SPF requests.  Each
server instance can be configured with specific processing parameters and has
its own DNS cache (TODO).  Also, the default I<Net::DNS::Resolver> DNS resolver
used for making DNS look-ups can be overridden with a custom resolver object.

=head2 Constructor

The following constructor is provided:

=over

=item B<new(%options)>: returns I<Mail::SPF::Server>

Creates a new server object for processing SPF requests.

%options is a list of key/value pairs representing any of the following
options:

=over

=item B<dns_resolver>

An optional DNS resolver object.  If none is specified, a new I<Net::DNS::Resolver>
object is used.  The resolver object may be of a different class, but it must
provide an interface similar to I<Net::DNS::Resolver> -- at least the C<send>
and C<errorstring> methods must be supported, and the C<send> method must
return either an object of class I<Net::DNS::Packet>, or, in the case of an
error, B<undef>.

=item B<max_dns_interactive_terms>

An I<integer> denoting the maximum number of terms (mechanisms and modifiers)
per SPF record that perform DNS look-ups, as defined in RFC 4408, 10.1,
paragraph 6.  If B<undef> is specified, there is no limit on the number of such
terms.  Defaults to B<10>, which is the value defined in RFC 4408.

A value above the default is I<strongly discouraged> for security reasons.  A
value below the default has implications with regard to the predictability of
SPF results.  Only deviate from the default if you know what you are doing!

=item B<max_name_lookups_per_term>

An I<integer> denoting the maximum number of DNS name look-ups per term
(mechanism or modifier), as defined in RFC 4408, 10.1, paragraph 7.  If
B<undef> is specified, there is no limit on the number of look-ups performed.
Defaults to B<10>, which is the value defined in RFC 4408.

A value above the default is I<strongly discouraged> for security reasons.  A
value below the default has implications with regard to the predictability of
SPF results.  Only deviate from the default if you know what you are doing!

=item B<max_name_lookups_per_mx_mech>

=item B<max_name_lookups_per_ptr_mech>

An I<integer> denoting the maximum number of DNS name look-ups per B<mx> or B<ptr>
mechanism, respectively.  Defaults to the value of the C<max_name_lookups_per_term>
option.  See there for additional information and security notes.

=item B<default_explanation>

A I<string> denoting the default (not macro-expanded) explanation string.
Defaults to:

    'Please see http://www.openspf.org/why.html?sender=%{S}&ip=%{I}&receiver=%{R}'

=back

=cut

sub new {
    my ($self, %options) = @_;
    $self = $self->SUPER::new(%options);
    
    $self->{dns_resolver} ||= Net::DNS::Resolver->new();
    
    $self->{max_dns_interactive_terms}      = $self->default_max_dns_interactive_terms
                                       if not exists($self->{max_dns_interactive_terms});
    $self->{max_name_lookups_per_term}      = $self->default_max_name_lookups_per_term
                                       if not exists($self->{max_name_lookups_per_term});
    $self->{max_name_lookups_per_mx_mech}   = $self->default_max_name_lookups_per_mx_mech
                                       if not exists($self->{max_name_lookups_per_mx_mech});
    $self->{max_name_lookups_per_ptr_mech}  = $self->default_max_name_lookups_per_ptr_mech
                                       if not exists($self->{max_name_lookups_per_ptr_mech});
    
    $self->{default_explanation} = $self->default_default_explanation
        if not defined($self->{default_explanation});
    $self->{default_explanation} = Mail::SPF::MacroString->new(
        text            => $self->{default_explanation},
        server          => $self,
        is_explanation  => TRUE
    )
        if not UNIVERSAL::isa($self->{default_explanation}, 'Mail::SPF::MacroString');
    
    return $self;
}

=back

=head2 Instance methods

The following instance methods are provided:

=over

=item B<process($request)>: returns I<Mail::SPF::Result>; throws Perl exceptions

Processes the given I<Mail::SPF::Request> object, queries the authoritative
domain for an SPF sender policy, evaluates the policy, and returns a
I<Mail::SPF::Result> object denoting the result of the policy evaluation.

More precisely, the following algorithm is performed:

=over

=item 1.

Determine the authority domain, the set of acceptable SPF record versions, and
the identity scope from the given request object.

=item 2.

Query the authority domain for SPF records of the C<SPF> DNS RR type,
discarding any records that are of an inacceptable version or do not cover the
desired scope.

If this yields no SPF records, query the authority domain for SPF records of
the C<TXT> DNS RR type, discarding any records that are of an inacceptable
version or do not cover the desired scope.

If still no acceptable SPF records could be found, processing ends with a
C<none> result.

=item 3.

Discard all records but those of the highest acceptable version found.

If more than one record remains, processing ends with a C<permerror> result.

=item 4.

Parse the selected record, constructing a I<Mail::SPF::Record> object, and
evaluate it with regard to the given identity and other request parameters.
Return an appropriate result.

=back

=cut

sub process {
    my ($self, $request) = @_;
    
    my $explanation = $self->{default_explanation}->new(request => $request);
    $request->state('explanation', $explanation);
    $request->state('dns_interactive_terms_count', 0);
    
    my $result;
    try {
        my $domain   = $request->authority_domain;
        my @versions = sort { $b <=> $a } $request->versions;
            # Try higher record versions first.
            # (This may be too simplistic for future revisions of SPF.)
        my $scope    = $request->scope;
        
        # Employ identical behavior for 'v=spf1' and 'spf2.0' records, both of
        # which support SPF (code 99) and TXT type records (this may be different
        # in future revisions of SPF):
        # Query for SPF type records first, then fall back to TXT type records.
        
        my @records;
        
        # Query for SPF type RRs first:
        try {
            my $packet = $self->dns_lookup($domain, 'SPF');
            push(
                @records,
                $self->get_acceptable_records_from_packet(
                    $packet, 'SPF', \@versions, $scope, $domain)
            );
        }
        catch Mail::SPF::EDNSTimeout with {
            # FIXME Ignore DNS time-outs on SPF type lookups?
            #warn('XXX: DNS time-out on SPF RR-type lookup (Server.pm:258)');
            # Apparrently some brain-dead DNS servers time out on SPF-type queries.
        };
        
        if (not @records) {
            # No usable SPF-type RRs, try TXT-type RRs.
            
            # NOTE:
            #   This deliberately violates RFC 4406 (Sender ID), 4.4/3 (4.4.1):
            #   TXT-type RRs are still tried if there _are_ SPF-type RRs but all of
            #   them are inapplicable (i.e. "Hi!", or even "spf2.0/pra" for an
            #   'mfrom' scope request).  This conforms to the spirit of the more
            #   sensible algorithm in RFC 4408 (SPF), 4.5.
            #   Implication:  Sender ID processing may make use of existing TXT-
            #   type records where a result of "None" would normally be returned
            #   under a strict interpretation of RFC 4406.
            
            my $packet = $self->dns_lookup($domain, 'TXT');
            push(
                @records,
                $self->get_acceptable_records_from_packet(
                    $packet, 'TXT', \@versions, $scope, $domain)
            );
        }
        
        @records
            or throw Mail::SPF::Result::None($request,
                "No acceptable TXT/SPF records available for domain '$domain'");  # RFC 4408, 4.5/7
        
        #STDERR->print("DEBUG: Acceptable records:\n");
        #foreach my $record (@records) {
        #    STDERR->print("  $record\n");
        #}
        
        # TODO Discard all records but the highest acceptable version!
        #...

        @records == 1
            or throw Mail::SPF::Result::PermError($request,
                "Redundant applicable records found for domain '$domain'");  # RFC 4408, 4.5/6
        
        $records[0]->eval($self, $request);
    }
    catch Mail::SPF::Result with {
        $result = shift;
    }
    catch Mail::SPF::ESyntaxError with {
        $result = Mail::SPF::Result::PermError->new($request, shift->text);
    }
    catch Mail::SPF::EProcessingLimitExceeded with {
        $result = Mail::SPF::Result::PermError->new($request, shift->text);
    }
    catch Mail::SPF::EDNSError with {
        $result = Mail::SPF::Result::TempError->new($request, shift->text);
    };
    # Propagate other, unknown errors.
    # This should not happen, but if it does, it helps exposing the bug!
    
    return $result;
}

=item B<dns_lookup($domain, $rr_type)>: returns I<Net::DNS::Packet>;
throws I<Mail::SPF::EDNSTimeout>, I<Mail::SPF::EDNSError>

Queries the DNS using the configured resolver for resource records of the
desired type at the specified domain and returns a I<Net::DNS::Packet> object
if an answer packet was received.  Throws a I<Mail::SPF::EDNSTimeout> exception
if a DNS time-out occurred.  Throws a I<Mail::SPF::EDNSError> exception if an
error (other than RCODE 3 AKA C<NXDOMAIN>) occurred.

=cut

sub dns_lookup {
    my ($self, $domain, $rr_type) = @_;
    #STDERR->print("DEBUG: DNS lookup: $domain $rr_type\n");
    
    if (UNIVERSAL::isa($domain, 'Mail::SPF::MacroString')) {
        # Expand macro string, and truncate domain name if longer than 253 bytes (RFC 4408, 8.1/25):
        $domain = $domain->expand;
        $domain =~ s/^[^.]+\.(.*)$/$1/
            while length($domain) > 253;
    }
    $domain =~ s/^(.*?)\.?$/\L$1/;  # Normalize domain.
    
    my $packet = $self->dns_resolver->send($domain, $rr_type);
    
    # Throw DNS exception unless an answer packet with RCODE 0 or 3 (NXDOMAIN)
    # was received (thereby treating NXDOMAIN as an acceptable but empty answer packet):
    $self->dns_resolver->errorstring !~ /^(timeout|query timed out)$/
        or throw Mail::SPF::EDNSTimeout(
            "Time-out on '$rr_type' DNS lookup of '$domain'");
    defined($packet)
        or throw Mail::SPF::EDNSError(
            "Unknown error on '$rr_type' DNS lookup of '$domain'");
    $packet->header->rcode =~ /^(NOERROR|NXDOMAIN)$/
        or throw Mail::SPF::EDNSError(
            "'" . $packet->header->rcode . "' error on '$rr_type' DNS lookup of '$domain'");
    
    return $packet;
}

=item B<get_acceptable_records_from_packet($packet, $rr_type, \@versions, $scope, $domain)>:
returns I<list> of I<Mail::SPF::Record>

Filters from the given I<Net::DNS::Packet> object all resource records of the
given RR type and for the given domain name, discarding any records that are
not SPF records at all, that are of an inacceptable SPF record version, or that
do not cover the given scope.  Returns a list of acceptable records.

=cut

sub get_acceptable_records_from_packet {
    my ($self, $packet, $rr_type, $versions, $scope, $domain) = @_;
    my @records;
    foreach my $rr ($packet->answer) {
        next if $rr->type ne $rr_type;  # Ignore RRs of unexpected type.
        
        my $text = join('', $rr->char_str_list);
        my $record;
        
        # Try to parse RR as each of the requested record versions,
        # starting from the highest version:
        VERSION:
        foreach my $version (@$versions) {
            my $class = $self->record_classes_by_version->{$version};
            eval("require $class");
            try {
                $record = $class->new_from_string($text);
            }
            catch Mail::SPF::EInvalidRecordVersion with {};
                # Ignore non-SPF and unknown-version records.
                # Propagate other errors (including syntax errors), though.
            last VERSION if defined($record);
        }
        
        push(@records, $record)
            if  defined($record)
            and grep($scope eq $_, $record->scopes);  # record covers requested scope?
    }
    return @records;
}

=item B<count_dns_interactive_term($request)>: throws I<Mail::SPF::EProcessingLimitExceeded>

Increments by one the count of DNS-interactive mechanisms and modifiers that
have been processed so far during the evaluation of the given
I<Mail::SPF::Request> object.  If this exceeds the configured limit (see the
L</new> constructor's C<max_dns_interactive_terms> option), throws a
I<Mail::SPF::EProcessingLimitExceeded> exception.

This method is supposed to be called by the C<match> and C<process> methods of
I<Mail::SPF::Mech> and I<Mail::SPF::Mod> sub-classes before (and only if) they
do any DNS look-ups.

=cut

sub count_dns_interactive_term {
    my ($self, $request) = @_;
    my $dns_interactive_terms_count = ++$request->root_request->state('dns_interactive_terms_count');
    my $max_dns_interactive_terms = $self->max_dns_interactive_terms;
    if (
        defined($max_dns_interactive_terms) and
        $dns_interactive_terms_count > $max_dns_interactive_terms
    ) {
        throw Mail::SPF::EProcessingLimitExceeded(
            "Maximum DNS-interactive terms limit ($max_dns_interactive_terms) exceeded");
    }
    return;
}

=item B<dns_resolver>: returns I<Net::DNS::Resolver> or compatible object

Returns the DNS resolver object of the server object.  See the description of
the L</new> constructor's C<dns_resolver> option.

=item B<max_dns_interactive_terms>: returns I<integer>

=item B<max_name_lookups_per_term>: returns I<integer>

=item B<max_name_lookups_per_mx_mech>: returns I<integer>

=item B<max_name_lookups_per_ptr_mech>: returns I<integer>

Return the limit values of the server object.  See the description of the
L</new> constructor's corresponding options.

=item B<default_explanation>: returns I<Mail::SPF::MacroString>

Returns the default explanation as a I<MacroString> object.  See the
description of the L</new> constructor's C<default_explanation> option.

=cut

# Make read-only accessors:
__PACKAGE__->make_accessor($_, TRUE)
    foreach qw(
        dns_resolver
        
        max_dns_interactive_terms
        max_name_lookups_per_term
        max_name_lookups_per_mx_mech
        max_name_lookups_per_ptr_mech
        
        default_explanation
    );

=back

=head1 SEE ALSO

L<Mail::SPF>, L<Mail::SPF::Request>, L<Mail::SPF::Result>

L<RFC 4408|http://www.ietf.org/rfc/rfc4408.txt>

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Julian Mehnle <julian@mehnle.net>, Shevek <cpan@anarres.org>

=cut

TRUE;
