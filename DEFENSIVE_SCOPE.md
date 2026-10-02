# Defensive contract

One finite set of explicitly supplied local audit snapshots is parsed as bytes. Selected transaction/argument/path/network/authentication observations are preserved with positions and fingerprints. There is no daemon configuration, live agent, audit-rule installation, subprocess, target import, command execution, remote lookup, replay, network activity or file extraction.

Coverage is a bounded raw-record grammar and selected evidence fields. Interpreted/enriched logs, syslog wrappers, additional record types, argument chunk reconstruction, arbitrary field semantics, complete host/process ancestry, live retention guarantees and actual filesystem/network/authentication outcomes remain unsupported or OPEN. All reported grouping is provisional. No log timestamp is called a process birth, and no PID-only match closes process lifetime identity.

PASS means documented parsing/inventory checks, with permanent record authenticity/boot/retention/lifetime uncertainty. OPEN accounts for malformed, missing, unsupported or limited observations. No security verdict, exploitation finding, maliciousness claim, applicant identity or CVP approval is produced.

The original parser's complete runtime was inspected to choose and replace mechanisms. The final new runtime, CLI, tests, dependency declarations, packaging, CI and provenance must be reviewed and bound to measured source/artifact identities before publishing.
