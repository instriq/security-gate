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

    my $critical = 0;
    my $high     = 0;
    my $medium   = 0;
    my $low      = 0;

    Getopt::Long::GetOptions (
        "t|token=s"    => \$token,
        "r|repo=s"     => \$repository,
        "c|critical=i" => \$critical,
        "h|high=i"     => \$high,
        "m|medium=i"   => \$medium,
        "l|low=i"      => \$low
    );

    if ($token && $repository) {
        my $endpoint  = "https://api.github.com/repos/$repository/dependabot/alerts";
        my $userAgent = Mojo::UserAgent -> new();
        my $request = $userAgent -> get($endpoint, {Authorization => "Bearer $token"}) -> result();

        if ($request -> code() == 200) {
            my $data = $request -> json();

            foreach my $alert (@$data) {
                if ($alert -> {"state"} eq "open") {
                    my $severity = $alert -> {security_vulnerability} -> {severity};
                    push @severity, $severity;
                }
            }
            
            print "[!] Total of security alerts:\n\n";

            for (my $i = 0; $i < scalar @severities; $i++) {
                my $severity = $severities[$i];
                my $count = grep { $_ eq $severity } @severity;

                print "[-] $severity: $count\n";

                my %severity_limits = (
                    "critical" => $critical,
                    "high"     => $high,
                    "medium"   => $medium,
                    "low"      => $low
                );
                
                if (exists $severity_limits{$severity} && $count > $severity_limits{$severity}) {
                    print "\n[+] More than $severity_limits{$severity} $severity security alerts found. Finalizing the process with error.\n";
                    exit 1;
                }
            }
        }
        
        return 0;
    }

    else {
        print "
			\rSecurity Gate v0.0.2
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
    }
}

exit main();