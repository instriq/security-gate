#!/usr/bin/env perl

use 5.030;
use strict;
use warnings;
use lib "./lib/";
use SecurityGate::Engine::Dependencies qw(@SEVERITIES);
use SecurityGate::Utils::Helper;
use Getopt::Long;

sub main {
    my ($token, $repository, $dependency_alerts);

    my %severity_limits = map { $_ => 0 } @SEVERITIES;

    Getopt::Long::GetOptions(
        "t|token=s"    => \$token,
        "r|repo=s"     => \$repository,
        "c|critical=i" => \$severity_limits{critical},
        "h|high=i"     => \$severity_limits{high},
        "m|medium=i"   => \$severity_limits{medium},
        "l|low=i"      => \$severity_limits{low},
        "dependency-alerts" => \$dependency_alerts
    );

    if ($token && $repository) {
        my $result = 0;

        if ($dependency_alerts) {
            $result = SecurityGate::Engine::Dependencies -> new($token, $repository, \%severity_limits);
        }

        else {
            print "No alerts type specified. Use --dependency-alerts to check for dependency alerts.\n";
        }

        return $result;
    } 
        
    else {
        print SecurityGate::Utils::Helper -> new();

        return 1;
    }
}

if ($ENV{TEST_MODE}) {
    main();
}
 
else {
    exit main();
}
