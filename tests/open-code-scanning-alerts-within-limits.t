#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::Output;
use Capture::Tiny qw(capture_stdout);

{
    package Mojo::UserAgent;
    use Test::MockObject;

    my $mock_response;

    sub new {
        my $class = shift;
        return Test::MockObject -> new -> mock('get', sub {
            my ($self, $url, $headers) = @_;
            return Test::MockObject -> new -> mock('result', sub {
                return $mock_response;
            });
        });
    }

    sub set_mock_response {
        my ($class, $response) = @_;
        $mock_response = $response;
        return $mock_response;
    }
}

use lib '../lib';
use SecurityGate::Engine::Code;

subtest 'Open code scanning alerts within limits' => sub {
    plan tests => 2;

    my $mock_response = Mojo::UserAgent -> set_mock_response(Test::MockObject -> new);
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', rule => { severity => 'high' } },
        { state => 'open', rule => { severity => 'medium' } },
    ]);

    my %severity_limits = (
        critical => 0,
        high     => 1,
        medium   => 1,
        low      => 0
    );

    my $result;
    my $total_pattern = qr/\[!\] \s Total \s of \s open \s code \s scanning \s alerts: \s 2/x;
    my $severity_pattern = qr/(?:\[-\] \s (?:low|medium|high|critical): \s \d+\s*)+/x;
    my $full_pattern = qr/$total_pattern.*$severity_pattern/sx;

    stdout_like(
        sub { $result = SecurityGate::Engine::Code -> new('test_token', 'test_repo', \%severity_limits) },
        $full_pattern,
        'Correct output for open alerts within limits'
    );

    is($result, 0, 'Returns 0 when open alerts are within limits');
};

done_testing();
