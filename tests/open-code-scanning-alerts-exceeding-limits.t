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

subtest 'Open code scanning alerts exceeding limits' => sub {
    plan tests => 3;

    my $mock_response = Mojo::UserAgent -> set_mock_response(Test::MockObject -> new);
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', rule => { severity => 'high' } },
        { state => 'open', rule => { severity => 'high' } },
        { state => 'open', rule => { severity => 'medium' } },
    ]);

    my %severity_limits = (
        critical => 0,
        high     => 1,
        medium   => 1,
        low      => 0
    );

    my ($output, $result);
    $output = capture_stdout {
        $result = SecurityGate::Engine::Code -> new('test_token', 'test_repo', \%severity_limits);
    };

    like($output, qr/\[!\] \s Total \s of \s open \s code \s scanning \s alerts: \s 3/x,
         'Output contains correct total alerts');

    like($output, qr/\[\+\] \s More \s than \s \d+ \s \w+ \s code \s scanning \s alerts \s found/x,
         'Output contains correct severity alert count');

    is($result, 1, 'Returns 1 when open alerts exceed limits');
};

done_testing();
