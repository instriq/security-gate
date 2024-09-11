package SecurityGate::Engine::Dependencies {
    use strict;
    use warnings;
    use Mojo::UserAgent;
    use Mojo::JSON;
    use Exporter 'import';

    our @EXPORT_OK = qw(@SEVERITIES);
    our @SEVERITIES = ("critical", "high", "medium", "low");

    sub new {
        my ($class, $token, $repository, $severity_limits) = @_;

        my %severity_counts = map { $_ => 0 } @SEVERITIES;

        my $endpoint = "https://api.github.com/repos/$repository/dependabot/alerts";
        my $userAgent = Mojo::UserAgent->new();
        my $request = $userAgent->get($endpoint, {Authorization => "Bearer $token"})->result();

        if ($request->code() == 200) {
            my $data = $request->json();

            foreach my $alert (@$data) {
                if ($alert->{state} eq "open") {
                    my $severity = $alert->{security_vulnerability}->{severity};
                    $severity_counts{$severity}++;
                }
            }

            print "\n[!] Total of dependency alerts:\n\n";

            foreach my $severity (@SEVERITIES) {
                print "[-] $severity: $severity_counts{$severity}\n";
            }

            print "\n";

            my $threshold_exceeded = 0;

            foreach my $severity (@SEVERITIES) {
                if ($severity_counts{$severity} > $severity_limits->{$severity}) {
                    print "[+] More than $severity_limits->{$severity} $severity security alerts found.\n";
                    $threshold_exceeded = 1;
                }
            }

            return $threshold_exceeded;
        }

        else {
            print "Error: Unable to fetch alerts. HTTP status code: " . $request->code() . "\n";
            return 1;
        }
    }
}

1;
