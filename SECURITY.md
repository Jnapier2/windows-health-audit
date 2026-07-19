# Security policy

## Supported scope

Security fixes target the current default branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting feature when it is available for this repository. Otherwise, contact the maintainer through the GitHub profile before sharing technical details. Do not disclose credentials, private system reports, personal identifiers, exploit payloads, or real machine telemetry in a public issue.

Include the affected file and line, expected safety boundary, observed behavior, and a minimal synthetic reproduction. Reports that identify a path to system mutation, elevation, network access, identifier leakage, or secret exposure are especially valuable.

## Security boundary

This project is designed for read-only local inspection. It does not provide remediation, remote management, persistence, or telemetry upload. A proposed change that introduces one of those capabilities is out of scope and should not be merged into this repository.

The output remains sensitive operational data even after built-in minimization. Review it before sharing and store it according to your organization's retention and access policies.
