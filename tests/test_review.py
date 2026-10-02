import contextlib
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit_event_review import Limits, Snapshot, review_snapshots
from audit_event_review.cli import main
from audit_event_review.input import read_regular_file
from audit_event_review.parser import sockaddr


def line(kind, body=b"", serial=1, timestamp="1700000000.001", node="node-a"):
    return (
        (
            (f"node={node} " if node else "")
            + f"type={kind} msg=audit({timestamp}:{serial}): "
        ).encode()
        + body
        + b"\n"
    )


def event(pid=7, ppid=1, serial=1, timestamp="1700000000.001", node="node-a"):
    return b"".join(
        [
            line(
                "SYSCALL",
                f'arch=c000003e syscall=59 success=yes exit=0 items=2 ppid={ppid} pid={pid} uid=1000 ses=3 exe="/inert/file" comm="inert"'.encode(),
                serial,
                timestamp,
                node,
            ),
            line(
                "PATH",
                b'item=1 name="name = file" inode=9 nametype=NORMAL',
                serial,
                timestamp,
                node,
            ),
            line("EXECVE", b'argc=2 a1=61203D2062 a0="inert"', serial, timestamp, node),
            line(
                "PATH",
                b'item=0 name="/inert/file" inode=8 nametype=NORMAL',
                serial,
                timestamp,
                node,
            ),
            line("EOE", serial=serial, timestamp=timestamp, node=node),
        ]
    )


def review(data, **kwargs):
    return review_snapshots([Snapshot(data, "synthetic-boot")], **kwargs)


class Records(unittest.TestCase):
    def test_transaction_order_and_proctitle_optional(self):
        expected = review(event())
        self.assertEqual(expected["status"], "PASS")
        rows = event().splitlines(keepends=True)
        for data in (
            b"".join(reversed(rows)),
            b"".join(rows[2:] + rows[:2]),
            line("PROCTITLE", b"proctitle=696E6572740061203D2062") + event(),
            event() + line("PROCTITLE", b"proctitle=696E6572740061203D2062"),
        ):
            report = review(data)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(len(report["events"]), 1)
            self.assertEqual(
                [x["index"] for x in report["events"][0]["arguments"][0]["values"]],
                [0, 1],
            )
        self.assertEqual(len(expected["events"][0]["paths"]), 2)

    def test_precise_record_provenance(self):
        data = event()
        report = review(data)
        offset = 0
        for row, record in zip(
            data.splitlines(keepends=True), report["events"][0]["records"], strict=True
        ):
            self.assertEqual(record["raw_line_sha256"], hashlib.sha256(row).hexdigest())
            self.assertEqual(record["byte_offset"], offset)
            offset += len(row)
        self.assertEqual(
            report["input_snapshots"][0]["sha256"], hashlib.sha256(data).hexdigest()
        )

    def test_rotation_with_asserted_boot_joins(self):
        rows = event().splitlines(keepends=True)
        report = review_snapshots(
            [Snapshot(b"".join(rows[:2]), "b"), Snapshot(b"".join(rows[2:]), "b")]
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["events"]), 1)
        self.assertEqual(
            {r["snapshot"] for r in report["events"][0]["records"]}, {0, 1}
        )

    def test_unknown_boot_never_joins_rotations(self):
        rows = event().splitlines(keepends=True)
        report = review_snapshots(
            [Snapshot(b"".join(rows[:2])), Snapshot(b"".join(rows[2:]))]
        )
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(len(report["events"]), 2)
        self.assertTrue(
            all("unknown_boot_context" in e["errors"] for e in report["events"])
        )

    def test_node_and_boot_separate(self):
        report = review_snapshots(
            [
                Snapshot(event(), "b"),
                Snapshot(event(node="node-b"), "b"),
                Snapshot(event(), "c"),
            ]
        )
        self.assertEqual(len(report["events"]), 3)
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(all(e["provisional_grouping"] for e in report["events"]))

    def test_serial_does_not_replace_timestamp(self):
        report = review(event() + event(timestamp="1700000001.001"))
        self.assertEqual(len(report["events"]), 2)

    def test_duplicate_records_retained(self):
        data = event() + line(
            "PATH", b'item=0 name="/inert/file" inode=8 nametype=NORMAL'
        )
        report = review(data)
        self.assertEqual(report["status"], "OPEN")
        self.assertEqual(len(report["events"][0]["paths"]), 3)
        self.assertIn("duplicate_records_retained", report["events"][0]["errors"])

    def test_key_collision_is_open(self):
        report = review(event() + event(pid=9))
        self.assertIn("possible_event_key_collision", report["events"][0]["errors"])

    def test_missing_structural_records(self):
        for removed in (b"EOE", b"PATH"):
            rows = [
                r
                for r in event().splitlines(keepends=True)
                if b"type=" + removed not in r
            ]
            self.assertEqual(review(b"".join(rows))["status"], "OPEN")
        self.assertEqual(review(event(node=""))["status"], "OPEN")

    def test_no_process_start_or_ancestry_claim(self):
        data = (
            event(pid=7, ppid=1)
            + event(pid=7, ppid=1, serial=2, timestamp="1700000001.001")
            + event(pid=20, ppid=7, serial=3, timestamp="1700000002.001")
        )
        report = review(data)
        child = report["events"][-1]["process"][0]["parent_evidence"]
        self.assertEqual(child["state"], "OPEN")
        self.assertEqual(len(child["candidate_event_ids"]), 2)
        self.assertNotIn("guid", json.dumps(report))
        self.assertEqual(report["process_lifetime_identity"], "OPEN")
        self.assertEqual(report["boot_identity"], "OPEN")
        self.assertEqual(report["record_authenticity"], "OPEN")

    def test_equal_later_times_and_missing_parent_not_linked(self):
        for parenttime in ("1700000000.001", "1700000001.001"):
            data = event(pid=20, ppid=7) + event(pid=7, serial=2, timestamp=parenttime)
            report = review(data)
            child = next(e for e in report["events"] if e["process"][0]["pid"] == 20)
            self.assertEqual(
                child["process"][0]["parent_evidence"]["candidate_event_ids"], []
            )

    def test_candidate_limit_is_explicit(self):
        data = (
            event(pid=7)
            + event(pid=7, serial=2, timestamp="1700000001.001")
            + event(pid=20, ppid=7, serial=3, timestamp="1700000002.001")
        )
        child = review(data, limits=replace(Limits(), candidates=1))["events"][-1][
            "process"
        ][0]["parent_evidence"]
        self.assertFalse(child["candidates_complete"])
        self.assertEqual(len(child["candidate_event_ids"]), 1)

    def test_quoted_spaces_equals_hex_and_private_values(self):
        report = review(event())
        value = report["events"][0]["arguments"][0]["values"][1]
        self.assertEqual(value["sha256"], hashlib.sha256(b"a = b").hexdigest())
        encoded_report = json.dumps(report)
        for text in ("name = file", "/inert/file", "node-a", "synthetic-boot", "a = b"):
            self.assertNotIn(text, encoded_report)

    def test_execve_multi_record_args_and_fragments(self):
        rows = [r for r in event().splitlines(keepends=True) if b"type=EXECVE" not in r]
        good = (
            b"".join(rows)
            + line("EXECVE", b"argc=2 a1=61203D2062")
            + line("EXECVE", b'argc=2 a0="inert"')
        )
        self.assertEqual(review(good)["status"], "PASS")
        for body in (
            b'argc=2 a0="inert"',
            b'argc=2 a0="inert" a0="duplicate"',
            b'argc=2 a0_len=9 a0[0]="chunk"',
            b'argc=2 a0="inert" a1=123',
            b'argc=999 a0="inert"',
        ):
            self.assertEqual(
                review(b"".join(rows) + line("EXECVE", body))["status"], "OPEN"
            )

    def test_optional_cwd_and_authentication(self):
        data = line("CWD", b'cwd="/inert/cwd"') + line(
            "USER_AUTH",
            b"pid=7 uid=0 msg='op=PAM:authentication acct=\"private account\" res=failed'",
        )
        report = review(data)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(
            report["events"][0]["authentication"][0]["recorded_result"], "failed"
        )
        self.assertNotIn("private account", json.dumps(report))
        self.assertEqual(
            review(line("USER_AUTH", b"pid=7 res=unknown"))["status"], "OPEN"
        )

    def test_unknown_type_and_bad_line_not_dropped(self):
        for data in (
            event() + b"private invalid log\n",
            event() + line("AVC", b"denied {}"),
            event() + b"type=SYSCALL msg=audit(1.00:1): pid=7\n",
            event() + line("PATH", b"item=0 name=odd"),
            event() + line("PATH", b"item=0 item=1"),
        ):
            report = review(data)
            self.assertEqual(report["status"], "OPEN")
            self.assertFalse(report["complete"])
            self.assertNotIn("private invalid log", json.dumps(report))

    def test_unknown_selected_process_and_auth_values_are_open(self):
        for body in (
            b'pid=7 ppid=1 items=0 exe=(null) comm="inert"',
            b'pid=7 ppid=1 items=0 exe="inert" comm=odd',
            b"pid=7 ppid=1 items=0",
        ):
            report = review(line("SYSCALL", body) + line("EOE"))
            self.assertEqual(report["status"], "OPEN")
            self.assertFalse(report["complete"])
            self.assertIn("unresolved_process_string", report["events"][0]["errors"])
        for body in (b"pid=7 acct=alice res=success", b"pid=7 res=success"):
            report = review(line("USER_AUTH", body))
            self.assertEqual(report["status"], "OPEN")
            self.assertFalse(report["complete"])
            self.assertIn("unresolved_auth_account", report["events"][0]["errors"])

    def test_missing_inventory_and_unknown_path_type_are_open(self):
        data = line("SYSCALL", b'pid=7 ppid=1 exe="inert" comm="inert"') + line("EOE")
        report = review(data)
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("missing_path_inventory_count", report["events"][0]["errors"])
        data = event().replace(b"nametype=NORMAL", b"nametype=UNRECOGNIZED")
        report = review(data)
        self.assertEqual(report["status"], "OPEN")
        self.assertIn("unsupported_path_nametype", report["events"][0]["errors"])

    def test_invalid_controls_quotes_and_enrichment(self):
        for body in (
            b'item=0 name="a\\b"',
            b'item=0 name="unfinished',
            b'item=0 name="a"tail',
            b'item=0\x1dname="b"',
            b"item=0 \0",
            b"item=0 keywithoutvalue",
            b'item=0 name="a" item=1',
        ):
            report = review(line("PATH", body))
            self.assertEqual(report["status"], "OPEN")
            self.assertTrue(report["unassigned_records"])
            if report["events"]:
                self.assertEqual(report["events"][0]["status"], "OPEN")

    def test_empty_and_contract_errors(self):
        for snapshots in (
            [],
            [b"not snapshot"],
            [Snapshot(b"")],
            [Snapshot(b"\n")],
            [Snapshot(b"x", 1)],
            [Snapshot(b"x", "漢字")],
        ):
            self.assertEqual(review_snapshots(snapshots)["status"], "OPEN")
        self.assertEqual(review(event(), byteorder="native")["status"], "OPEN")
        with self.assertRaises(TypeError):
            review(event(), limits=False)

    def test_integer_header_and_fields_limits(self):
        for data in (
            event().replace(b"1700000000", b"99999999999999999999"),
            line("SYSCALL", b"pid=-1 ppid=0"),
            line("SYSCALL", b"pid=4294967296 ppid=0"),
            line("SYSCALL", b'pid="7" ppid=0'),
        ):
            self.assertEqual(review(data)["status"], "OPEN")

    def test_budget_boundaries(self):
        data = event()
        exact = replace(
            Limits(), input_bytes=len(data), total_bytes=len(data), records=5, events=1
        )
        self.assertEqual(review(data, limits=exact)["status"], "PASS")
        for limits in (
            replace(exact, input_bytes=len(data) - 1),
            replace(exact, total_bytes=len(data) - 1),
            replace(exact, records=4),
            replace(exact, line_bytes=16),
            replace(exact, fields=1),
            replace(exact, arguments=1),
        ):
            self.assertEqual(review(data, limits=limits)["status"], "OPEN")
        self.assertEqual(
            review(data + event(serial=2), limits=replace(Limits(), events=1))[
                "status"
            ],
            "OPEN",
        )
        report = review(data, limits=replace(Limits(), report_bytes=4096))
        self.assertIn("report_byte_budget", report["errors"])
        self.assertLessEqual(len(json.dumps(report).encode()), 4096)
        for bad in (0, -1, True, 9999999, "1"):
            with self.assertRaises(ValueError):
                replace(Limits(), records=bad)


class Address(unittest.TestCase):
    def check(self, data, order="little"):
        return sockaddr((data.hex().encode(), False), order)

    def test_ipv4_little_big_and_network_port(self):
        for order in ("little", "big"):
            data = (2).to_bytes(2, order) + b"\x01\xbb\x7f\0\0\1" + b"\0" * 8
            result = self.check(data, order)
            self.assertEqual(result["kind"], "ipv4")
            self.assertEqual(result["port"], 443)
            self.assertEqual(result["address_class"], "loopback")
            self.assertEqual(
                result["address_sha256"], hashlib.sha256(b"\x7f\0\0\1").hexdigest()
            )

    def test_ipv6_scope_and_unix(self):
        self.assertEqual(self.check(b"\1\0")["namespace"], "unnamed")
        data = (
            b"\x0a\0\0\x50" + b"\0" * 4 + b"\0" * 15 + b"\1" + (7).to_bytes(4, "little")
        )
        result = self.check(data)
        self.assertEqual(
            (result["kind"], result["scope_id"], result["port"]), ("ipv6", 7, 80)
        )
        for pathname, expected in ((b"\0inert", "abstract"), (b"/inert\0", "pathname")):
            self.assertEqual(self.check(b"\1\0" + pathname)["namespace"], expected)

    def test_short_invalid_unknown_and_unsupported(self):
        for data in (b"", b"\2", b"\2\0", b"\2\0" + b"\0" * 20, b"\x63\0" + b"\0" * 14):
            self.assertEqual(self.check(data)["state"], "OPEN")
        for value in (None, (b"xyz", False), (b"ABC", False), (b"0200", True)):
            self.assertEqual(sockaddr(value, "little")["state"], "OPEN")
        self.assertEqual(
            self.check(b"\2\0" + b"\0" * 14, None)["reason"],
            "caller_byteorder_required",
        )
        data = line("SOCKADDR", b"saddr=020001BB7F0000010000000000000000")
        self.assertEqual(review(data)["status"], "OPEN")
        self.assertEqual(review(data, byteorder="little")["status"], "PASS")


class LocalInput(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.file = self.root / "private.log"
        self.file.write_bytes(event())

    def tearDown(self):
        self.temp.cleanup()

    def test_regular_read_and_unchanged(self):
        before = self.file.read_bytes()
        self.assertEqual(read_regular_file(self.file, len(before)), before)
        self.assertEqual(self.file.read_bytes(), before)
        with self.assertRaises(ValueError):
            read_regular_file(self.file, len(before) - 1)

    def test_symlink_components_parent_and_nonregular(self):
        link = self.root / "link"
        link.symlink_to(self.file)
        parent = self.root / "linked-parent"
        parent.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (
            link,
            parent / self.file.name,
            fifo,
            self.root,
            str(self.root) + "/../private.log",
        ):
            with self.assertRaises((ValueError, OSError)):
                read_regular_file(path, 4096)

    def test_metadata_changes_short_read_and_platform_open(self):
        original = os.fstat
        from types import SimpleNamespace

        for field in ("st_size", "st_ino", "st_mtime_ns", "st_ctime_ns"):
            count = 0

            def changed(fd):
                nonlocal count
                info = original(fd)
                count += 1
                values = {
                    k: getattr(info, k)
                    for k in (
                        "st_dev",
                        "st_ino",
                        "st_mode",
                        "st_size",
                        "st_mtime_ns",
                        "st_ctime_ns",
                    )
                }
                if count > 1:
                    values[field] += 1
                return SimpleNamespace(**values)

            with patch("audit_event_review.input.os.fstat", side_effect=changed):
                with self.assertRaises(ValueError):
                    read_regular_file(self.file, 4096)
        with patch("audit_event_review.input.os.read", return_value=b""):
            with self.assertRaises(ValueError):
                read_regular_file(self.file, 4096)
        with patch("audit_event_review.input.os.supports_dir_fd", set()):
            with self.assertRaises(ValueError):
                read_regular_file(self.file, 4096)

    def test_cli_json_privacy_exit_and_preservation(self):
        for args, exit_code in (
            ([str(self.file), "--boot-context", "private-boot"], 0),
            ([str(self.file)], 2),
            ([], 2),
            (["private-file", "--unknown"], 2),
        ):
            before = self.file.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(args)
            self.assertEqual(code, exit_code)
            report = json.loads(output.getvalue())
            self.assertEqual(report["record_authenticity"], "OPEN")
            self.assertNotIn("private", output.getvalue())
            self.assertTrue(output.getvalue().isascii())
            self.assertEqual(self.file.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
