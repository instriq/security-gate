#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::Output;

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
        return;
    }
}

use lib '../lib';
use SecurityGate::Engine::Dependencies;

subtest 'Threshold checking' => sub {
    plan tests => 2;

    my $mock_response = Test::MockObject -> new;
    Mojo::UserAgent -> set_mock_response($mock_response);
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
    ]);

    my %severity_limits_exceeded = (
        critical => 1,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    my %severity_limits_not_exceeded = (
        critical => 2,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    is(
        SecurityGate::Engine::Dependencies -> new('test_token', 'test_repo', \%severity_limits_exceeded),
        1,
        'Returns 1 when threshold is exceeded'
    );

    is(
        SecurityGate::Engine::Dependencies -> new('test_token', 'test_repo', \%severity_limits_not_exceeded),
        0,
        'Returns 0 when threshold is not exceeded'
    );
};

done_testing();
