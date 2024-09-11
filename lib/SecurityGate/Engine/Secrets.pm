package SecurityGate::Engine::Secrets {
    use strict;
    use warnings;
    use Mojo::UserAgent;
    use Mojo::JSON;

    sub new {
        my ($class, $token, $repository, $severity_limits) = @_;

        my $endpoint = "https://api.github.com/repos/$repository/secret-scanning/alerts";
        my $userAgent = Mojo::UserAgent->new();
        my $request = $userAgent->get($endpoint, {Authorization => "Bearer $token"})->result();

        if ($request->code() == 200) {
            my $data = $request->json();
            my $open_alerts = 0;
            my @alert_details;

            foreach my $alert (@$data) {
                if ($alert->{state} eq "open") {
                    $open_alerts++;

                    my $locations_endpoint = "https://api.github.com/repos/$repository/secret-scanning/alerts/" . $alert->{number} . "/locations";
                    my $locations_request = $userAgent->get($locations_endpoint, {Authorization => "Bearer $token"})->result();

                    if ($locations_request->code() == 200) {
                        my $locations = $locations_request->json();

                        push @alert_details, {
                            alert_number => $alert->{number},
                            locations    => $locations,
                        };
                    }
                }
            }

            print "\n[!] Total of open secret scanning alerts: $open_alerts\n\n";

            foreach my $detail (@alert_details) {
                print "[-] Alert " . $detail->{alert_number} . " found in the following locations:\n";

                foreach my $location (@{$detail->{locations}}) {
                    my $file_path  = $location->{details}->{path} // 'Unknown file';
                    my $start_line = $location->{details}->{start_line} // 'Unknown line';

                    print "    File: $file_path, Start line: $start_line\n";
                }
            }

            print "\n";

            my $threshold = $severity_limits->{high};
            if ($open_alerts > $threshold) {
                print "[+] More than $threshold secret scanning alerts found. Blocking pipeline.\n";
                return 1;
            }

            else {
                print "[-] Number of secret scanning alerts ($open_alerts) is within the acceptable limit ($threshold).\n";
                return 0;
            }
        }

        else {
            print "Error: Unable to fetch secret scanning alerts. HTTP status code: " . $request->code() . "\n";
            return 1;
        }
    }
}

1;
