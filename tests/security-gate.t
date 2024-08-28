#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::Output;
use Carp qw(croak);
use Capture::Tiny qw(capture);
use Mojo::JSON qw(encode_json);

local $ENV{TEST_MODE} = 1;

my $mock_ua = Test::MockObject -> new();
$mock_ua -> fake_module('Mojo::UserAgent');
$mock_ua -> fake_new('Mojo::UserAgent');

require_ok('../security-gate.pl');

subtest 'Command-line argument parsing' => sub {
    local @ARGV = ();
    stdout_like(
        sub { main() },
        qr/Security\ Gate\ v0\.0\.3/x,
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
        qr/critical:\ 1.*high:\ 1.*medium:\ 1.*low:\ 0/xs,
        'Severity counts are correct'
    );
};

subtest 'Threshold checking' => sub {
    my $mock_response = Test::MockObject  ->  new();
    $mock_response  ->  set_always('code', 200);
    $mock_response  ->  set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
    ]);

    my $mock_tx = Test::MockObject  ->  new();
    $mock_tx  ->  set_always('result', $mock_response);

    $mock_ua  ->  set_always('get', $mock_tx);

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

    my $total_alerts_re = qr/\[!\]\ Total\ of\ security\ alerts:/x;
    my $critical_alerts_re = qr/\[-\]\ critical:\ 1/x;
    my $high_alerts_re = qr/\[-\]\ high:\ 1/x;

    stdout_like(
        sub { main() },
        qr/$total_alerts_re.*$critical_alerts_re.*$high_alerts_re/xs,
        'Output is correctly formatted'
    );
};

subtest 'Invalid token or repository' => sub {
    my $mock_response = Test::MockObject  ->  new();
    $mock_response  ->  set_always('code', 401);

    my $mock_tx = Test::MockObject  ->  new();
    $mock_tx  ->  set_always('result', $mock_response);

    $mock_ua  ->  set_always('get', $mock_tx);

    local @ARGV = ('-t', 'invalid_token', '-r', 'invalid_repo');
    is(
        scalar(main()),
        1,
        'Script exits with non-zero code when token or repository is invalid'
    );
};

subtest 'Empty response from GitHub API' => sub {
    my $mock_response = Test::MockObject  ->  new();
    $mock_response  ->  set_always('code', 200);
    $mock_response  ->  set_always('json', []);

    my $mock_tx = Test::MockObject  ->  new();
    $mock_tx  ->  set_always('result', $mock_response);

    $mock_ua  ->  set_always('get', $mock_tx);

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo');
    is(
        scalar(main()),
        0,
        'Script exits with zero code when no alerts are found'
    );
};

subtest 'Multiple severity thresholds' => sub {
    my $mock_response = Test::MockObject -> new();
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'high' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'medium' } },
    ]);

    my $mock_tx = Test::MockObject -> new();
    $mock_tx -> set_always('result', $mock_response);

    $mock_ua -> set_always('get', $mock_tx);

    local @ARGV = ('-t', 'test_token', '-r', 'test_repo', '-c', '0', '-h', '0', '-m', '0', '-l', '0');

     my ($stdout, $stderr, $result) = capture {
        main();
    };

    diag("STDOUT: $stdout");
    diag("STDERR: $stderr");
    diag("Result: $result");

    is(
        $result,
        1,
        'Script exits with non-zero code when multiple thresholds are exceeded'
    );

    like(
        $stdout,
        qr/Total\ of\ security\ alerts:/x,
        'Output contains expected content'
    );
};

done_testing();
