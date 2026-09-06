# Security policy

Web Guard changes Windows DNS settings and includes a privileged local protection
service, so security reports should not be posted as public issues before a fix
is available.

The service also offers an optional, reversible machine-policy control for
supported browsers. Recovery data is saved before DNS or browser-policy writes.
Reports involving incomplete restoration, policy conflicts, local named-pipe
authorization, DNS response validation, or encrypted-upstream certificate
validation are security-sensitive.

## Reporting a vulnerability

Once the official repository is published, use its **Security → Report a
vulnerability** option to open a private security advisory. Include the affected
Web Guard version, Windows version, DNS configuration, steps to reproduce, and
the impact. Do not include passwords, account tokens, browsing history, private
domain names, or other personal data.

Ordinary bugs, incorrect block-list entries, false positives, and interface
problems that do not create a security risk can be reported through the public
issue tracker.

## Supported version

Only the newest source version on the default branch is supported. Users should
reproduce an issue with that version before filing a report.
