package SecurityGate::Utils::Helper {
    use strict;
	use warnings;

	sub new {
	      return "
                \rSecurity Gate v0.1.0
                \rCore Commands
                \r====================
                \r\tCommand                Description
                \r\t-------                -----------
                \r\t-t, --token            GitHub token
                \r\t-r, --repo             GitHub repository, organization/repository-name
                \r\t-c, --critical         Critical severity limit
                \r\t-h, --high             High severity limit
                \r\t-m, --medium           Medium severity limit
                \r\t-l, --low              Low severity limit
                \r\t--dependency-alerts    Check dependency alerts
                \r\t--secret-alerts        Check secret scanning alerts
                \r\t--code-alerts          Check code scanning alerts\n\n";
	}
}

1;