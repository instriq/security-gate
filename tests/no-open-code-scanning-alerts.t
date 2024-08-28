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

subtest 'No open code scanning alerts' => sub {
    plan tests => 2;

    my $mock_response = Mojo::UserAgent -> set_mock_response(Test::MockObject -> new);
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', []);

    my %severity_limits = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    my $result;
    stdout_like(
        sub { $result = SecurityGate::Engine::Code -> new('test_token', 'test_repo', \%severity_limits) },
        qr/\[!\] \s Total \s of \s open \s code \s scanning \s alerts: \s 0/x,
        'Correct output for no open alerts'
    );

    is($result, 0, 'Returns 0 when no open alerts are found');
};

done_testing();
