#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::Output;
use Mojo::JSON qw(encode_json);

my $mock_ua = Test::MockObject -> new();
$mock_ua -> fake_module('Mojo::UserAgent');
$mock_ua -> fake_new('Mojo::UserAgent');

require_ok('../security-gate.pl');

subtest 'Command-line argument parsing' => sub {
    local @ARGV = ();
    stdout_like(
        sub { main() },
        qr/Security Gate v0\.0\.3/,
        'Help message displayed when no arguments provided'
    );
};

subtest 'Severity counting' => sub {
    my $mock_response = Test::MockObject -> new();
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'high' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'medium' } },
        { state => 'closed', security_vulnerability => { severity => 'low' } },
    ]);

    my $mock_tx = Test::MockObject -> new();
    $mock_tx -> set_always('result', $mock_response);

    $mock_ua -> set_always('get', $mock_tx);

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo');
    stdout_like(
        sub { main() },
        qr/critical: 1.*high: 1.*medium: 1.*low: 0/s,
        'Severity counts are correct'
    );
};

subtest 'Threshold checking' => sub {
    my $mock_response = Test::MockObject -> new();
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
    ]);

    my $mock_tx = Test::MockObject -> new();
    $mock_tx -> set_always('result', $mock_response);

    $mock_ua -> set_always('get', $mock_tx);

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo', '-c', '1');
    is(
        scalar(main()),
        1,
        'Script exits with non-zero code when threshold is exceeded'
    );

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo', '-c', '2');
    is(
        scalar(main()),
        0,
        'Script exits with zero code when threshold is not exceeded'
    );
};

subtest 'Output formatting' => sub {
    my $mock_response = Test::MockObject -> new();
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'high' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
    ]);

    my $mock_tx = Test::MockObject -> new();
    $mock_tx -> set_always('result', $mock_response);

    $mock_ua -> set_always('get', $mock_tx);

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo');
    stdout_like(
        sub { main() },
        qr/\[!\] Total of security alerts:.*\[-\] critical: 1.*\[-\] high: 1/s,
        'Output is correctly formatted'
    );
};

done_testing();
