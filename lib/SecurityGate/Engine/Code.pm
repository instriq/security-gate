package SecurityGate::Engine::Code {
    use strict;
    use warnings;
    use Mojo::UserAgent;
    use Mojo::JSON;
    use Data::Dumper;

    sub new {
      my ($class, $token, $repository, $severity_limits) = @_;
      my $alerts_endpoint   = "https://api.github.com/repos/$repository/code-scanning/alerts";      
      my $userAgent = Mojo::UserAgent -> new();
      my $alerts_request = $userAgent -> get($alerts_endpoint, {Authorization => "Bearer $token"}) -> result();

      if ($alerts_request -> code() == 200) {
        my $alerts_data = $alerts_request -> json();
        my $open_alerts = 0;
        my %severity_counts = map {$_ => 0} keys %$severity_limits;

        foreach my $alert (@$alerts_data) {
          print Dumper($alert);

          if ($alert -> {state} eq "open") {
            $open_alerts++;
            
            my $severity = $alert -> {rule} -> {severity};
            $severity_counts{$severity}++ if exists $severity_counts{$severity};
          }
        }

        print "[!] Total of open code scanning alerts: $open_alerts\n";
        
        foreach my $severity (keys %severity_counts) {
          print "[-] $severity: $severity_counts{$severity}\n";
        }

        my $threshold_exceeded = 0;
        
        foreach my $severity (keys %severity_counts) {
          if ($severity_counts{$severity} > $severity_limits -> {$severity}) {
            print "[+] More than $severity_limits->{$severity} $severity code scanning alerts found.\n";
            
            $threshold_exceeded = 1;
          }
        }

        if ($threshold_exceeded) {
          return 1;
        }
      }

      else {
        print "Error: Unable to fetch code scanning alerts. HTTP status code: " . $alerts_request -> code() . "\n";
        
        return 1;
      }
      
      return 0;
    }
}

1;