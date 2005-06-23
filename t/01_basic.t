use strict;
use warnings;
use blib;

use Test::More tests => 7;

use_ok('Mail::SPF');
use_ok('Mail::SPF::Server');
use_ok('Mail::SPF::Request');
use_ok('Mail::SPF::Response');
use_ok('Mail::SPF::Record');
use_ok('Mail::SPF::Mod');
use_ok('Mail::SPF::Mech');
