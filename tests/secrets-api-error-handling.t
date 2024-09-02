#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;
use Test::Exception;
use Test::MockObject;
use Test::Output;
use Capture::Tiny qw(capture_stdout);

BEGIN {
    use lib '../lib';
    use_ok('SecurityGate::Engine::Secrets') || print "Bail out!\n";
}

{
    package MockMojoUserAgent;
    use Test::MockObject;

    my $mock_response;
    my $locations_response;

    sub new {
        my $class = shift;
        return Test::MockObject -> new -> mock('get', sub {
            my ($self, $url, $headers) = @_;
            return Test::MockObject -> new -> mock('result', sub {
                if ($url =~ m{locations$}xsm) {
                    return $locations_response;
                }
                return $mock_response;
            });
        });
    }

    sub setup_mock_response {
        my ($code, $json) = @_;
        $mock_response = Test::MockObject -> new;
        $mock_response -> set_always('code', $code);
        $mock_response -> set_always('json', $json);
        return;
    }

    sub setup_locations_response {
        my ($code, $json) = @_;
        $locations_response = Test::MockObject -> new;
        $locations_response -> set_always('code', $code);
        $locations_response -> set_always('json', $json);
        return;
    }
}

*Mojo::UserAgent::new = \&MockMojoUserAgent::new;

subtest 'API error handling' => sub {
    plan tests => 2;

    MockMojoUserAgent::setup_mock_response(401, undef);

    my %severity_limits = (
        critical => 0,
        high     => 1,
        medium   => 0,
        low      => 0
    );

    my $result;
    my $expected_error_output_part1 = qr/Error:\ Unable\ to\ fetch\ secret\ scanning\ alerts\./xsm;
    my $expected_error_output_part2 = qr/\ HTTP\ status\ code:\ 401/xsm;
    my $expected_error_output = qr/$expected_error_output_part1.*$expected_error_output_part2/xsm;

    stdout_like(
        sub { $result = SecurityGate::Engine::Secrets -> new('invalid_token', 'test_repo', \%severity_limits) },
        $expected_error_output,
        'Correct error message for API failure'
    );

    is($result, 1, 'Returns 1 when API request fails');
};

done_testing();

1;
