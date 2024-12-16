#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use lib '../lib';
use SecurityGate::Utils::Helper;

subtest 'Helper output' => sub {
    my $helper_output = SecurityGate::Utils::Helper->new();

    like($helper_output, qr/Security\ Gate\ v0\.0\.3/x, 'Helper output contains version');
    like($helper_output, qr/-t,\ --token/x, 'Helper output contains token option');
    like($helper_output, qr/-r,\ --repo/x, 'Helper output contains repo option');
    like($helper_output, qr/--dependency-alerts/x, 'Helper output contains dependency alerts option');
    like($helper_output, qr/--secret-alerts/x, 'Helper output contains secret scanning alerts option');
    like($helper_output, qr/--code-alerts/x, 'Helper output contains code scanning alerts option');
};

done_testing();
