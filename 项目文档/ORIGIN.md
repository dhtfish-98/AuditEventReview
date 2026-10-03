# Origin and changes

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.2**. Upstream authors and reused components retain their original attribution.


Reference: [exeronn/auditd-python-parser at 07c9322f54e87d5dd58992a55595a1f78813b415](https://github.com/exeronn/auditd-python-parser/tree/07c9322f54e87d5dd58992a55595a1f78813b415). Both complete runtime files, package metadata, README files and GPL-3 license were read. SOURCE_AUDIT.json records hashes and fixed Git blob identities. Upstream image examples and unrelated repository files are not claimed semantically audited. No upstream code or tests were executed; pandas is not a new runtime dependency.

The upstream author/project is exeron / auditd-python-parser. The current implementation independently elects GPL-3.0-only; LICENSE is its own current license, not a redundant third-party reference copy. This finite design is independently implemented, with new source, tests, CLI and documentation. New implementation author: dhtfish98. Attribution does not transfer upstream authorship to an applicant or prove independent human contribution.

The new implementation replaces PROCTITLE splitting, flattened field overwriting, float timestamps, presumed start times and generated GUID ancestry with explicit transaction keys, retained record positions, exact integer time fields, raw/decoded fingerprints and candidate-only PID links. It supports raw Linux record forms within documented bounds, not pandas return tables or full behavioral equivalence to the original enriched-input parser. Missing/unsupported evidence stays OPEN.

The Linux audit-userspace primary README and auparse interface were checked for the compound-event timestamp/serial/node model and out-of-order records: [primary source](https://github.com/linux-audit/audit-userspace). Native sockaddr shapes follow the declared Linux family layout; caller byteorder is an assertion, never inferred from the reviewing host or verified deployment.

This is an authorized local evidence tool. CVP eligibility is based on truthful actual defensive work and the provider's process, not repository count or a guaranteed safety-classifier outcome.
