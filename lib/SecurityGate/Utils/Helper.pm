package SecurityGate::Utils::Helper {
    use strict;
    use warnings;

    sub new {
        return <<"EOT";

Security Gate v0.0.3
Core Commands
==============
Command                         Description
-------                         -----------
-t, --token                     GitHub token
-r, --repo                      GitHub repository
-c, --critical                  Critical severity limit
-h, --high                      High severity limit
-m, --medium                    Medium severity limit
-l, --low                       Low severity limit
--dependency-alerts             Check for dependency alerts
--secret-scanning-alerts        Check for secret scanning alerts
--code-scanning-alerts          Check for code scanning alerts

EOT
    }
}

1;
