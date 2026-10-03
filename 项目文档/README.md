> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# AuditEventReview

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.2**. Upstream authors and reused components retain their original attribution.


Review local Linux audit log snapshots offline. This is a new bounded parser and multi-record transaction evidence ledger, with source reference to auditd-python-parser. It groups by the recorded node, exact seconds/milliseconds/serial and a caller asserted boot context. It never uses PROCTITLE as an event delimiter, executes logged commands or starts auditd/ausearch.

```sh
python -m pip install .
audit-event-review audit.log.1 audit.log --boot-context locally-asserted-boot --byteorder little
```

The input paths are explicit local ordinary files. Every path component requires POSIX directory-relative `O_NOFOLLOW` opening; missing facilities, symlinks, raw `..`, nonregular files, changed observed metadata and byte budgets return sanitized JSON OPEN. Ordinary read access can update atime; the tool does not intentionally write input or extract/copy logged files. JSON goes to stdout. Help is the normal informational exception.

Status PASS/exit 0 means the supported grammar and selected record inventories were reviewed without a known incomplete condition. OPEN/exit 2 preserves uncertainty, malformed records, unsupported formats and budgets. There is no maliciousness verdict or FAIL policy in this evidence parser. Record authenticity, actual boot identity, event retention completeness and process lifetime identity always remain OPEN, including on PASS.

```python
from audit_event_review import Snapshot, review_snapshots

report = review_snapshots([Snapshot(local_bytes, "caller-asserted-boot")], byteorder="little")
```

Inputs are a finite list/tuple of immutable Snapshot objects. The same caller boot context permits rotation files to join. Unknown boot contexts are kept separate for each snapshot and marked OPEN; the parser cannot detect mixed boots hidden in a single file. Node strings and boot labels are represented by hashes. A shared timestamp/serial is provisional grouping, not proof that logs are authentic or complete. Duplicate records stay present; duplicate EOE/SYSCALL records flag a possible key collision. Records may be interleaved and supplied out of order. Events are sorted numerically by recorded timestamp/serial without trusting that wall clock order equals execution order.

Supported record names are SYSCALL, EXECVE, PATH, CWD, PROCTITLE, SOCKADDR, USER_AUTH and EOE. Headers use `type=... msg=audit(seconds.mmm:serial):` with an optional `node=...` prefix. Numeric type codes, syslog prefixes, interpreted/enriched separators, unsupported escapes, alternate time precision and other record types are OPEN. Literal quoted fields preserve spaces and equals signs. Selected quoted strings and even-length hex fields yield byte length/hash evidence; unknown string encodings remain explicit OPEN observations. Arbitrary field semantics are not implemented.

Missing/unrecognized executable or command fingerprints and missing/unrecognized authentication account fingerprints mark that selected record OPEN. Optional extra metadata may be absent without claiming its value was observed.

SYSCALL contributes recorded PID/PPID, UID/session, architecture/syscall number, exit/success text and the expected PATH count. Numeric syscall IDs are not translated to operation names. PATH records retain item indices and individual name fingerprints; no CWD joining, filesystem resolution, or claimed file creation occurs. EXECVE argument indices are numerically sorted across records and checked against the stated argc; duplicate/missing indices, argument fragments and unsupported encoding are OPEN. PROCTITLE is an independent hash observation, never a grouping marker. USER_AUTH optionally parses one quoted nested msg field and exposes a recorded result and account fingerprint, not an identity-verification result.

SOCKADDR interpretation requires the caller's byteorder assertion for native family/scope fields. Supported byte shapes are Linux AF_INET (16 bytes), AF_INET6 (28 bytes), and AF_UNIX (2..110 bytes). Ports remain network-order. Addresses/pathnames are fingerprinted; a coarse IPv4 loopback flag, port and IPv6 scope ID are metadata. Unrecognized families, wrong sizes, bad hex and absent byteorder are OPEN. No socket is opened and no actual network connection is inferred.

Process association reports a bounded list of strictly earlier EXECVE transaction IDs whose recorded PID equals PPID in the same known node and asserted boot context. These are candidates only. PID reuse, exec versus birth, exits, absent records, same-time events and clock changes prevent a verified parent identity. No synthetic process GUID, chosen parent, command execution, or complete ancestry chain is produced. A truncated candidate list is explicitly marked incomplete.

Reports retain each original physical record's SHA-256, snapshot index, line and zero-based byte offset, with decoded selected observations. Raw command arguments, executable paths, account text, node/boot labels, original records and input filenames are omitted. Hashes, PIDs, timestamps, ports and positions are still evidence metadata; unsalted hashes do not make low-entropy values secret.

Limits are explicit and can be lowered: 4 MiB per snapshot, 8 MiB total, 16 snapshots, 4096 records, 64 KiB per line, 256 fields, 1024 events, 128 arguments/PATH items, 32 parent candidates and 4 MiB JSON. All values are typed positive integers within defaults, with at least 4096 report bytes. Report overflow emits a compact OPEN summary, not silent truncation. This is bounded in-process parsing, not an OS sandbox.

Python 3.11+; no third-party runtime dependency. See ORIGIN.md, DEFENSIVE_SCOPE.md, SOURCE_AUDIT.json and VALIDATION.md for fixed-source attribution, boundaries and measured checks. GPL-3.0-only; complete license/source accompany distributions. New implementation author: dhtfish98; independent applicant contribution and CVP approval are not established by this repository.

Safe local file input requires positive integer `O_NOFOLLOW`, `O_DIRECTORY`, `O_NONBLOCK` flags, plus directory-relative operations only where used by this reader. Missing, None, zero or boolean flags return the existing controlled unsupported/error result before opening input. File-reader validation covers macOS/Linux; native Windows safe file reading is not established.
