#!/usr/bin/env perl

use 5.030;
use strict;
use warnings;
use lib "./lib/";
use SecurityGate::Engine::Dependencies qw(@SEVERITIES);
use SecurityGate::Engine::Secrets;
use SecurityGate::Engine::Code;
use SecurityGate::Utils::Helper;
use Getopt::Long;

sub main {
    my ($token, $repository, $dependency_alerts, $secret_alerts, $code_alerts);
    my %severity_limits = map {$_ => 0} @SEVERITIES;

    Getopt::Long::GetOptions(
        "t|token=s"         => \$token,
        "r|repo=s"          => \$repository,
        "c|critical=i"      => \$severity_limits{critical},
        "h|high=i"          => \$severity_limits{high},
        "m|medium=i"        => \$severity_limits{medium},
        "l|low=i"           => \$severity_limits{low},
        "dependency-alerts" => \$dependency_alerts,
        "secret-alerts"     => \$secret_alerts,
        "code-alerts"       => \$code_alerts
    );

    if ($token && $repository) {
        my $result = 0;

        my %alert_checks = (
            'dependency-alerts' => $dependency_alerts ? sub { SecurityGate::Engine::Dependencies->new($token, $repository, \%severity_limits) } : undef,
            'secret-alerts'     => $secret_alerts ? sub { SecurityGate::Engine::Secrets->new($token, $repository, \%severity_limits) } : undef,
            'code-alerts'       => $code_alerts ? sub { SecurityGate::Engine::Code->new($token, $repository, \%severity_limits) } : undef
        );

        for my $check (grep { defined } values %alert_checks) {
            $result += $check->();
        }

        return $result;
    }

    else {
        print SecurityGate::Utils::Helper->new();
        return 1;
    }

    return 0;
}

if ($ENV{TEST_MODE}) {
    main();
}

else {
    exit main();
}
