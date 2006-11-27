use strict;
use warnings;
use blib;

use lib '/home/julian/source/spf/software/mail-spf-test-perl/trunk/lib';

use Test::More;

eval("use Mail::SPF::Test");
plan(skip_all => "Mail::SPF::Test required for testing Mail::SPF's RFC compliance") if $@;

use constant test_case_overrides => {
    'cidr6-0-ip4'   => 'SKIP: Test case is disputed',
    'cidr6-ip4'     => 'SKIP: If cidr6-0-ip4 prevails, test case is disputed; otherwise, test case should be modified to use "ip6:::ffff:1.2.3.4" and an IPv4 address of 1.2.3.4'
};

require('t/Mail-SPF-Test-lib.pm');

run_spf_test_suite_file('t/rfc4408-tests.yml', test_case_overrides);
