use strict;
use warnings;
use blib;

use Error ':try';

use Test::More tests => 16;

use Mail::SPF::Request;


#### Class Compilation ####

BEGIN { use_ok('Mail::SPF::Result') }


#### Basic Instantiation ####

{
    my $result = eval { Mail::SPF::Result->new('dummy server', 'dummy request', 'result text') };

    $@ eq '' and isa_ok($result, 'Mail::SPF::Result',   'Basic result object')
        or BAIL_OUT("Basic result instantiation failed: $@");

    # Have options been interpreted correctly?
    is($result->server,             'dummy server',     'Basic result server()');
    is($result->request,            'dummy request',    'Basic result request()');
    is($result->text,               'result text',      'Basic result text()');
}


#### Parameterized Result Rethrowing ####

{
    eval {
        eval { throw Mail::SPF::Result('server', 'request', 'result text') };
        $@->throw('other server', 'other request', 'other text');
    };

    isa_ok($@,                     'Mail::SPF::Result', 'Param-rethrown result object');
    is($@->server,                  'other server',     'Param-rethrown result server()');
    is($@->request,                 'other request',    'Param-rethrown result request()');
    is($@->text,                    'other text',       'Param-rethrown result text()');
}


#### class_by_code() ####

{
    my $class;

    $class = Mail::SPF::Result->class_by_code('PaSs');
    is($class,               'Mail::SPF::Result::Pass', 'Result class_by_code($valid_code)');

    $class = Mail::SPF::Result->class_by_code('foo');
    is($class,                      undef,              'Result class_by_code($invalid_code)');
}


#### is_code() ####

{
    my $result = Mail::SPF::Result::Pass->new('dummy server', 'dummy request');
    ok($result->is_code('PaSs'),                        'Result is_code($valid_code)');
    ok((not $result->is_code('foo')),                   'Result is_code($invalid_code)');
}


#### NeutralByDefault, code() ####

{
    my $result = Mail::SPF::Result::NeutralByDefault->new('dummy server', 'dummy request');
    isa_ok($result,       'Mail::SPF::Result::Neutral', 'NeutralByDefault result object');
    is($result->code,               'neutral',          'NeutralByDefault result code()');
    ok($result->is_code('neutral'),                     'NeutralByDefault is_code("neutral")');
}
