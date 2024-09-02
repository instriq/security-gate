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

subtest 'API request error' => sub {
    plan tests => 2;

    my $mock_response = Mojo::UserAgent -> set_mock_response(Test::MockObject -> new);
    $mock_response -> set_always('code', 401);

    my %severity_limits = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    my $result;
    my $error_message = qr/Error: \s Unable \s to \s fetch \s code \s scanning \s alerts\./x;
    my $status_code = qr/\s HTTP \s status \s code: \s 401/x;
    my $full_error_pattern = qr/$error_message$status_code/x;

    stdout_like(
        sub { $result = SecurityGate::Engine::Code -> new('test_token', 'test_repo', \%severity_limits) },
        $full_error_pattern,
        'Correct error message for API request failure'
    );

    is($result, 1, 'Returns 1 when API request fails');
};

done_testing();
