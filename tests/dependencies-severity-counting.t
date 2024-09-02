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

subtest 'Severity counting' => sub {
    plan tests => 1;

    my $mock_response = Test::MockObject -> new;
    Mojo::UserAgent -> set_mock_response($mock_response);
    $mock_response -> set_always('code', 200);
    $mock_response -> set_always('json', [
        { state => 'open', security_vulnerability => { severity => 'high' } },
        { state => 'open', security_vulnerability => { severity => 'critical' } },
        { state => 'open', security_vulnerability => { severity => 'medium' } },
        { state => 'closed', security_vulnerability => { severity => 'low' } },
    ]);

    my %severity_limits = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    stdout_like(
        sub { SecurityGate::Engine::Dependencies -> new('test_token', 'test_repo', \%severity_limits) },
        qr/critical:\ 1.*high:\ 1.*medium:\ 1.*low:\ 0/xs,
        'Severity counts are correct'
    );
};

done_testing();
