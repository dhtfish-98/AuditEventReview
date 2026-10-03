# SPDX-License-Identifier: GPL-3.0-only
# New implementation author: dhtfish98. See ORIGIN.md and LICENSE.
"""Bounded local audit-record grammar and provisional transaction correlation."""

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re

_HEADER = re.compile(
    rb"(?:node=([^ \t]{1,256})[ \t]+)?type=([A-Z_0-9]{1,64})[ \t]+msg=audit\(([0-9]{1,20})\.([0-9]{3}):([0-9]{1,20})\):(?:[ \t]+|$)"
)
_KEY = re.compile(rb"[A-Za-z_][A-Za-z_0-9\[\]]{0,63}\Z")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2})*\Z")
_TYPES = frozenset(
    {"SYSCALL", "EXECVE", "PROCTITLE", "PATH", "CWD", "SOCKADDR", "USER_AUTH", "EOE"}
)


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 4 * 1024 * 1024
    total_bytes: int = 8 * 1024 * 1024
    snapshots: int = 16
    records: int = 4096
    line_bytes: int = 65536
    fields: int = 256
    events: int = 1024
    arguments: int = 128
    candidates: int = 32
    report_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        ceilings = (4194304, 8388608, 16, 4096, 65536, 256, 1024, 128, 32, 4194304)
        if any(
            type(v) is not int or not 1 <= v <= cap
            for v, cap in zip(asdict(self).values(), ceilings, strict=True)
        ):
            raise ValueError("invalid_limits")
        if self.report_bytes < 4096:
            raise ValueError("invalid_report_limit")


@dataclass(frozen=True)
class Snapshot:
    data: bytes
    boot_context: str | None = None


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Invalid(ValueError):
    pass


def fields(raw, maximum):
    """Parse only literal key=value fields; escapes/enriched separators are OPEN."""
    result = []
    i = 0
    while i < len(raw):
        while i < len(raw) and raw[i] in b" \t":
            i += 1
        if i == len(raw):
            break
        start = i
        while i < len(raw) and raw[i] not in b"= \t":
            i += 1
        key = raw[start:i]
        if not _KEY.fullmatch(key) or i == len(raw) or raw[i] != 61:
            raise Invalid("unsupported_field_grammar")
        i += 1
        quote = raw[i] if i < len(raw) and raw[i] in (34, 39) else None
        if quote:
            i += 1
            start = i
            while i < len(raw) and raw[i] != quote:
                if raw[i] in (0, 29, 92):
                    raise Invalid("unsupported_field_escape_or_enrichment")
                i += 1
            if i == len(raw):
                raise Invalid("unterminated_field_quote")
            value = raw[start:i]
            i += 1
            if i < len(raw) and raw[i] not in b" \t":
                raise Invalid("unsupported_field_boundary")
        else:
            start = i
            while i < len(raw) and raw[i] not in b" \t":
                i += 1
            value = raw[start:i]
            if any(c in value for c in (b"\x00", b"\x1d", b"\\", b'"', b"'")):
                raise Invalid("unsupported_field_escape_or_enrichment")
        if len(result) >= maximum:
            raise Invalid("field_budget")
        result.append((key.decode("ascii"), value, quote is not None))
    return result


def one(items, key):
    values = [(v, q) for k, v, q in items if k == key]
    if len(values) > 1:
        raise Invalid("duplicate_selected_field")
    return values[0] if values else None


def integer(items, key, maximum=2**32 - 1):
    value = one(items, key)
    if value is None:
        return None
    raw, quoted = value
    if quoted or not re.fullmatch(rb"[0-9]{1,20}", raw):
        raise Invalid("invalid_integer_field")
    number = int(raw)
    if number > maximum:
        raise Invalid("integer_field_limit")
    return number


def encoded(value):
    if value is None:
        return None
    raw, quoted = value
    if quoted:
        decoded, form = raw, "quoted_literal"
    elif raw == b"(null)":
        return {"state": "OPEN", "reason": "null_string"}
    elif raw and _HEX.fullmatch(raw):
        decoded, form = bytes.fromhex(raw.decode()), "hex_bytes"
    else:
        return {"state": "OPEN", "reason": "unrecognized_string_encoding"}
    return {
        "state": "OBSERVED",
        "encoding": form,
        "bytes": len(decoded),
        "sha256": digest(decoded),
    }


def sockaddr(value, byteorder):
    if value is None:
        return {"state": "OPEN", "reason": "missing_sockaddr"}
    raw, quoted = value
    if quoted or not raw or len(raw) > 256 or not _HEX.fullmatch(raw):
        return {"state": "OPEN", "reason": "invalid_sockaddr_hex"}
    data = bytes.fromhex(raw.decode())
    result = {"state": "OPEN", "bytes": len(data), "sha256": digest(data)}
    if byteorder not in ("little", "big"):
        return dict(result, reason="caller_byteorder_required")
    if len(data) < 2:
        return dict(result, reason="short_sockaddr")
    family = int.from_bytes(data[:2], byteorder)
    result["family"] = family
    if family == 2 and len(data) == 16:
        address, port = data[4:8], int.from_bytes(data[2:4], "big")
        return dict(
            result,
            state="OBSERVED",
            kind="ipv4",
            port=port,
            address_sha256=digest(address),
            address_class="loopback"
            if ipaddress.IPv4Address(address).is_loopback
            else "other",
        )
    if family == 10 and len(data) == 28:
        return dict(
            result,
            state="OBSERVED",
            kind="ipv6",
            port=int.from_bytes(data[2:4], "big"),
            address_sha256=digest(data[8:24]),
            scope_id=int.from_bytes(data[24:28], byteorder),
        )
    if family == 1 and 2 <= len(data) <= 110:
        return dict(
            result,
            state="OBSERVED",
            kind="unix",
            pathname_sha256=digest(data[2:]),
            namespace="unnamed"
            if len(data) == 2
            else "abstract"
            if data[2:3] == b"\x00"
            else "pathname",
        )
    return dict(result, reason="unsupported_sockaddr_shape")


def open_report(code, limits=None):
    return {
        "schema_version": 1,
        "status": "OPEN",
        "complete": False,
        "errors": [code],
        "events": [],
        "unassigned_records": [],
        "record_authenticity": "OPEN",
        "boot_identity": "OPEN",
        "process_lifetime_identity": "OPEN",
        "limits": asdict(limits or Limits()),
    }


def review_snapshots(snapshots, *, byteorder=None, limits=None):
    """Correlate supplied snapshots. All boot contexts are caller assertions.

    No process GUID or verified ancestry is inferred from PID alone. Reports
    preserve record hashes/positions but omit raw field values and local paths.
    """
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("limits must be Limits or None")
    if (
        type(snapshots) not in (list, tuple)
        or not snapshots
        or len(snapshots) > limits.snapshots
    ):
        return open_report("snapshot_contract", limits)
    if byteorder not in (None, "little", "big"):
        return open_report("invalid_byteorder", limits)
    for snap in snapshots:
        if (
            type(snap) is not Snapshot
            or type(snap.data) is not bytes
            or len(snap.data) > limits.input_bytes
        ):
            return open_report("snapshot_contract_or_budget", limits)
        if snap.boot_context is not None and (
            type(snap.boot_context) is not str
            or not 1 <= len(snap.boot_context) <= 128
            or not snap.boot_context.isascii()
        ):
            return open_report("boot_context_contract", limits)
    if sum(len(s.data) for s in snapshots) > limits.total_bytes:
        return open_report("total_input_budget", limits)
    report = open_report("not_reviewed", limits)
    report.update(
        errors=[],
        complete=True,
        input_snapshots=[
            {"index": i, "bytes": len(s.data), "sha256": digest(s.data)}
            for i, s in enumerate(snapshots)
        ],
    )
    groups, raw_count = {}, 0
    stop = False
    for source, snap in enumerate(snapshots):
        offset = 0
        boot = (
            digest(snap.boot_context.encode())
            if snap.boot_context is not None
            else None
        )
        for lineno, with_eol in enumerate(snap.data.splitlines(keepends=True), 1):
            raw = with_eol.rstrip(b"\r\n")
            location = {
                "snapshot": source,
                "line": lineno,
                "byte_offset": offset,
                "raw_line_sha256": digest(with_eol),
            }
            offset += len(with_eol)
            if not raw:
                continue
            raw_count += 1
            if raw_count > limits.records:
                report["errors"].append("record_budget")
                stop = True
                break
            event = None
            try:
                if len(raw) > limits.line_bytes:
                    raise Invalid("line_byte_budget")
                if any(c < 32 and c not in (9,) for c in raw):
                    raise Invalid("unsupported_record_control")
                match = _HEADER.match(raw)
                if match is None:
                    raise Invalid("unsupported_audit_header")
                node, kind, sec, milli, serial = match.groups()
                if int(sec) > 2**64 - 1 or int(serial) > 2**64 - 1:
                    raise Invalid("header_integer_limit")
                kind = kind.decode()
                node_id = digest(node) if node else None
                # Unknown boot contexts never join across file/rotation boundaries.
                context = boot if boot is not None else ("unknown_snapshot", source)
                key = (node_id, context, int(sec), int(milli), int(serial))
                if key not in groups:
                    if len(groups) >= limits.events:
                        raise Invalid("event_budget")
                    groups[key] = {
                        "event_id": digest(
                            json.dumps(key, separators=(",", ":")).encode()
                        ),
                        "node_sha256": node_id,
                        "boot_context_sha256": boot,
                        "seconds": int(sec),
                        "milliseconds": int(milli),
                        "serial": int(serial),
                        "provisional_grouping": True,
                        "records": [],
                        "errors": [],
                        "process": [],
                        "paths": [],
                        "arguments": [],
                        "network": [],
                        "authentication": [],
                    }
                event = groups[key]
                observation = dict(
                    location,
                    type=kind if kind in _TYPES else "UNSUPPORTED",
                    field_count=0,
                )
                event["records"].append(observation)
                if kind not in _TYPES:
                    event["errors"].append("unsupported_record_type")
                    continue
                items = fields(raw[match.end() :], limits.fields)
                observation["field_count"] = len(items)
                facts = interpret(kind, items, limits, byteorder)
                observation["facts"] = facts
                for target in (
                    "process",
                    "paths",
                    "arguments",
                    "network",
                    "authentication",
                ):
                    if target in facts:
                        event[target].append(
                            {"record_index": len(event["records"]) - 1, **facts[target]}
                        )
                event["errors"].extend(facts.get("errors", []))
            except Invalid as error:
                if event is not None:
                    event["errors"].append(str(error))
                report["unassigned_records"].append(dict(location, reason=str(error)))
                report["errors"].append(str(error))
        if stop:
            break
    for event in groups.values():
        types = [r["type"] for r in event["records"]]
        hashes = [r["raw_line_sha256"] for r in event["records"]]
        if len(set(hashes)) != len(hashes):
            event["errors"].append("duplicate_records_retained")
        if event["boot_context_sha256"] is None:
            event["errors"].append("unknown_boot_context")
        if event["node_sha256"] is None:
            event["errors"].append("unknown_node")
        event["end_marker_observed"] = "EOE" in types
        if types.count("EOE") > 1 or types.count("SYSCALL") > 1:
            event["errors"].append("possible_event_key_collision")
        # EOE only observes an end marker; it cannot establish record retention.
        event["event_retention_completeness"] = "OPEN"
        if "SYSCALL" in types:
            if not event["end_marker_observed"]:
                event["errors"].append("missing_end_marker")
            if len(event["process"]) == 1:
                expected = event["process"][0].get("items")
                indices = [p.get("item") for p in event["paths"]]
                if expected is not None and sorted(
                    indices, key=lambda v: -1 if v is None else v
                ) != list(range(expected)):
                    event["errors"].append("path_inventory_mismatch")
        if event["arguments"]:
            args = event["arguments"]
            counts = {a.get("argc") for a in args}
            pairs = [(x["index"], x) for a in args for x in a.get("values", [])]
            if (
                len(counts) != 1
                or None in counts
                or len({p[0] for p in pairs}) != len(pairs)
                or sorted(p[0] for p in pairs)
                != list(range(next(iter(counts), 0) or 0))
            ):
                event["errors"].append("argv_inventory_incomplete_or_ambiguous")
        event["errors"] = sorted(set(event["errors"]))
        event["status"] = "OPEN" if event["errors"] else "PASS"
    report["events"] = sorted(
        groups.values(),
        key=lambda e: (e["seconds"], e["milliseconds"], e["serial"], e["event_id"]),
    )
    correlate(report["events"], limits)
    report["complete"] = not report["errors"] and not any(
        e["errors"] for e in report["events"]
    )
    report["errors"] = sorted(set(report["errors"]))
    if not report["events"]:
        report["errors"].append("no_audit_records")
        report["complete"] = False
    report["status"] = "PASS" if report["complete"] else "OPEN"
    if len(json.dumps(report, ensure_ascii=True).encode()) > limits.report_bytes:
        bounded = open_report("report_byte_budget", limits)
        bounded["input_snapshots"] = report["input_snapshots"]
        bounded["observed_events"] = len(report["events"])
        return bounded
    return report


def interpret(kind, items, limits, byteorder):
    result = {"errors": []}
    if kind == "SYSCALL":
        pid, ppid = integer(items, "pid"), integer(items, "ppid")
        result["process"] = {
            "pid": pid,
            "ppid": ppid,
            "items": integer(items, "items", limits.arguments),
            "exe": encoded(one(items, "exe")),
            "comm": encoded(one(items, "comm")),
            "uid": integer(items, "uid"),
            "session": integer(items, "ses"),
        }
        if pid is None or ppid is None:
            result["errors"].append("missing_process_identifiers")
        for name in ("exe", "comm"):
            observation = result["process"][name]
            if observation is None or observation["state"] != "OBSERVED":
                result["errors"].append("unresolved_process_string")
        if result["process"]["items"] is None:
            result["errors"].append("missing_path_inventory_count")
        for key in ("arch", "syscall", "success", "exit"):
            value = one(items, key)
            if value:
                raw, quoted = value
                good = {
                    "arch": rb"[0-9a-fA-F]{8}",
                    "syscall": rb"[0-9]{1,10}",
                    "success": rb"yes|no",
                    "exit": rb"-?[0-9]{1,20}",
                }[key]
                if quoted or not re.fullmatch(good, raw):
                    result["errors"].append("unsupported_syscall_field")
                else:
                    result["process"][key] = raw.decode("ascii")
    elif kind == "EXECVE":
        values = []
        argc = integer(items, "argc", limits.arguments)
        for key, raw, quoted in items:
            if key.startswith("a") and key != "argc":
                if (
                    not re.fullmatch(r"a[0-9]{1,3}", key)
                    or int(key[1:]) >= limits.arguments
                ):
                    result["errors"].append("argument_fragments_or_index_unsupported")
                    continue
                value = encoded((raw, quoted))
                values.append({"index": int(key[1:]), **value})
                if value["state"] != "OBSERVED":
                    result["errors"].append("unsupported_argument_encoding")
        result["arguments"] = {
            "argc": argc,
            "values": sorted(values, key=lambda v: v["index"]),
        }
    elif kind == "PATH":
        result["paths"] = {
            "item": integer(items, "item", limits.arguments),
            "name": encoded(one(items, "name")),
            "inode": integer(items, "inode", 2**64 - 1),
        }
        name_type = one(items, "nametype")
        if (
            name_type
            and not name_type[1]
            and name_type[0] in (b"NORMAL", b"PARENT", b"CREATE", b"DELETE", b"UNKNOWN")
        ):
            result["paths"]["nametype"] = name_type[0].decode()
        elif name_type:
            result["errors"].append("unsupported_path_nametype")
        if (
            result["paths"]["item"] is None
            or not result["paths"]["name"]
            or result["paths"]["name"]["state"] != "OBSERVED"
        ):
            result["errors"].append("incomplete_path_record")
    elif kind == "SOCKADDR":
        result["network"] = sockaddr(one(items, "saddr"), byteorder)
        if result["network"]["state"] != "OBSERVED":
            result["errors"].append(result["network"]["reason"])
    elif kind == "PROCTITLE":
        result["proctitle"] = encoded(one(items, "proctitle"))
        if not result["proctitle"] or result["proctitle"]["state"] != "OBSERVED":
            result["errors"].append("incomplete_proctitle")
    elif kind == "CWD":
        result["cwd"] = encoded(one(items, "cwd"))
        if not result["cwd"] or result["cwd"]["state"] != "OBSERVED":
            result["errors"].append("incomplete_cwd")
    elif kind == "USER_AUTH":
        payload = one(items, "msg")
        nested = fields(payload[0], limits.fields) if payload and payload[1] else items
        result["authentication"] = {
            "pid": integer(items, "pid"),
            "account": encoded(one(nested, "acct")),
            "recorded_result": "OPEN",
        }
        account = result["authentication"]["account"]
        if account is None or account["state"] != "OBSERVED":
            result["errors"].append("unresolved_auth_account")
        value = one(nested, "res")
        if value and not value[1] and value[0] in (b"success", b"failed"):
            result["authentication"]["recorded_result"] = value[0].decode()
        else:
            result["errors"].append("unresolved_auth_result")
    return result


def correlate(events, limits):
    """Candidate earlier EXECVE transactions only, never verified parent identity."""
    index = {}
    for event in events:
        time = (event["seconds"], event["milliseconds"])
        context = (event["node_sha256"], event["boot_context_sha256"])
        for proc in event["process"]:
            parent = proc["ppid"]
            candidates = index.get((*context, parent), []) if all(context) else []
            earlier = [identity for t, identity in candidates if t < time]
            proc["parent_evidence"] = {
                "state": "OPEN",
                "candidate_event_ids": earlier[-limits.candidates :],
                "candidates_complete": len(earlier) <= limits.candidates,
                "reason": "PID_lifetime_and_parent_creation_unobserved",
            }
        if event["arguments"] and len(event["process"]) == 1 and all(context):
            pid = event["process"][0]["pid"]
            if pid is not None:
                index.setdefault((*context, pid), []).append((time, event["event_id"]))
