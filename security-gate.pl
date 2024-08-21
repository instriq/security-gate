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
  my ($token, $repository, $dependency_alerts, $secret_scanning_alerts, $code_scanning_alerts);

  my %severity_limits = map {$_ => 0} @SEVERITIES;

  Getopt::Long::GetOptions(
    "t|token=s" => \$token,
    "r|repo=s" => \$repository,
    "c|critical=i" => \$severity_limits{critical},
    "h|high=i" => \$severity_limits{high},
    "m|medium=i" => \$severity_limits{medium},
    "l|low=i" => \$severity_limits{low},
    "dependency-alerts" => \$dependency_alerts,
    "secret-scanning-alerts" => \$secret_scanning_alerts,
    "code-scanning-alerts" => \$code_scanning_alerts
  );

  if ($token && $repository) {
    my $result = 0;

    my %alert_checks = (
        'dependency-alerts'      => sub { SecurityGate::Engine::Dependencies->new($token, $repository, \%severity_limits) },
        'secret-scanning-alerts' => sub { SecurityGate::Engine::Secrets->new($token, $repository) },
        'code-scanning-alerts'   => sub { SecurityGate::Engine::CodeScanning->new($token, $repository, \%severity_limits) },
    );

    for my $alert_type (keys %alert_checks) {
      if ($$alert_type) {
        $result += $alert_checks{$alert_type}->();
      }
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
