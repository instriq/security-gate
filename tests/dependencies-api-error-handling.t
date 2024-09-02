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

subtest 'API error handling' => sub {
    plan tests => 1;

    my $mock_response = Test::MockObject -> new;
    Mojo::UserAgent -> set_mock_response($mock_response);
    $mock_response -> set_always('code', 401);

    my %severity_limits = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    is(
        SecurityGate::Engine::Dependencies -> new('invalid_token', 'test_repo', \%severity_limits),
        1,
        'Returns 1 when API request fails'
    );
};

done_testing();
