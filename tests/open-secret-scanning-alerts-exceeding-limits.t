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

subtest 'Open secret scanning alerts exceeding limits' => sub {
    plan tests => 5;

    MockMojoUserAgent::setup_mock_response(200, [
        { state => 'open', number => 1 },
        { state => 'open', number => 2 },
    ]);

    MockMojoUserAgent::setup_locations_response(200, [
        { path => 'file1.txt', start_line => 10 },
        { path => 'file2.txt', start_line => 20 },
    ]);

    my %severity_limits = (
        critical => 0,
        high     => 1,
        medium   => 0,
        low      => 0
    );

    my $result;
    my $output = capture_stdout {
        $result = SecurityGate::Engine::Secrets -> new('test_token', 'test_repo', \%severity_limits);
    };

    like($output, qr{\[!\]\ Total\ of\ open\ secret\ scanning\ alerts:\ 2}xsm, 'Correct total number of alerts');
    like($output, qr{\[-\]\ Alert\ 1\ found\ in\ the\ following\ locations:}xsm, 'Alert 1 details present');
    like($output, qr{\[-\]\ Alert\ 2\ found\ in\ the\ following\ locations:}xsm, 'Alert 2 details present');

    my $match_plus_sign    = qr/\[\+\]/xsm;
    my $match_more_than    = qr/\ More\ than\ \d+/xsm;
    my $match_alerts_found = qr/\ secret\ scanning\ alerts?\ found\./xsm;
    my $match_blocking     = qr/\ Blocking\ pipeline\./xsm;
    like($output, qr{$match_plus_sign$match_more_than$match_alerts_found$match_blocking}xsm, 'Blocking message present');
    is($result, 1, 'Returns 1 when open alerts exceed limit');
};

done_testing();

1;
