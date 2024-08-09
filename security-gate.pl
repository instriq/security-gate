#!/usr/bin/env perl

use 5.030;
use strict;
use warnings;
use Getopt::Long;
use Mojo::JSON;
use Mojo::UserAgent;

sub main {
    my ($token, $repository, @severity);
    my @severities = ("critical", "high", "medium", "low");

    my %severity_counts = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    my %severity_limits = (
        critical => 0,
        high     => 0,
        medium   => 0,
        low      => 0
    );

    Getopt::Long::GetOptions(
        "t|token=s"    => \$token,
        "r|repo=s"     => \$repository,
        "c|critical=i" => \$severity_limits{critical},
        "h|high=i"     => \$severity_limits{high},
        "m|medium=i"   => \$severity_limits{medium},
        "l|low=i"      => \$severity_limits{low}
    );

    if ($token && $repository) {
        my $endpoint  = "https://api.github.com/repos/$repository/dependabot/alerts";
        my $userAgent = Mojo::UserAgent -> new();
        my $request   = $userAgent -> get($endpoint, {Authorization => "Bearer $token"}) -> result();

        if ($request -> code() == 200) {
            my $data = $request -> json();

            foreach my $alert (@$data) {
                if ($alert -> {state} eq "open") {
                    my $severity = $alert -> {security_vulnerability} -> {severity};
                    $severity_counts{$severity}++;
                }
            }

            print "[!] Total of security alerts:\n\n";

            foreach my $severity (@severities) {
                print "[-] $severity: $severity_counts{$severity}\n";
            }

            print "\n";

            foreach my $severity (@severities) {
                if ($severity_counts{$severity} > $severity_limits{$severity}) {
                    print "[+] More than $severity_limits{$severity} $severity security alerts found. Finalizing the process with error.\n";
                    return 1;
                }
            }
        }

        return 0;
    } 
        
    else {
        print "
            \rSecurity Gate v0.0.3
            \rCore Commands
            \r==============
            \r\tCommand          Description
            \r\t-------          -----------
            \r\t-t, --token      GitHub token
            \r\t-r, --repo       GitHub repository
            \r\t-c, --critical   Critical severity limit
            \r\t-h, --high       High severity limit
            \r\t-m, --medium     Medium severity limit
            \r\t-l, --low        Low severity limit
        \n";

        return 1;
    }
}

if ($ENV{TEST_MODE}) {
    main();
} 
else {
    exit main();
}
