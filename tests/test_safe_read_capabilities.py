"""Safe-read capability refusal is controlled and precedes any input open."""

from contextlib import redirect_stdout, redirect_stderr
import importlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit_event_review import cli

reader = importlib.import_module("audit_event_review.input")


def read(path):
    return reader.read_regular_file(path, 1024)


class SafeReadCapabilities(unittest.TestCase):
    def test_missing_none_zero_bool_flags_refuse_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            original = reader.os.open
            for flag in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'):
                for value in ("MISSING", None, 0, True, False):
                    with self.subTest(flag=flag, value=value):
                        with patch.object(reader.os, flag, value, create=True):
                            if value == "MISSING":
                                delattr(reader.os, flag)
                            with patch.object(reader.os, "open", wraps=original) as opened:
                                with patch.object(reader.os, "supports_dir_fd", set(reader.os.supports_dir_fd) | {opened}):
                                    with self.assertRaises(ValueError) as failure:
                                        read(str(sample))
                                    self.assertEqual(str(failure.exception), 'safe_read_unavailable')
                                    output, errors = io.StringIO(), io.StringIO()
                                    with redirect_stdout(output), redirect_stderr(errors):
                                        exitcode = cli.main([str(sample)])
                                    self.assertEqual(exitcode, 2)
                                    if output.getvalue():
                                        self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
                                    self.assertNotIn(str(sample), output.getvalue()+errors.getvalue())
                                    opened.assert_not_called()
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_normal_file_and_symbolic_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            self.assertEqual(read(str(sample)), b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with self.assertRaises((ValueError, OSError)):
                read(str(link))
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_zero_nofollow_refuses_symbolic_target_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            link = sample.with_name("link.bin")
            link.symlink_to(sample)
            with patch.object(reader.os, "O_NOFOLLOW", 0):
                with self.assertRaises(ValueError):
                    read(str(link))
                output, errors = io.StringIO(), io.StringIO()
                with redirect_stdout(output), redirect_stderr(errors):
                    exitcode = cli.main([str(link)])
                self.assertEqual(exitcode, 2)
                if output.getvalue():
                    self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_support_collections_refuse_api_cli_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            original_open = reader.os.open
            dir_fd_support = set(reader.os.supports_dir_fd)
            for attribute in ('supports_dir_fd',):
                for value in ("MISSING", None, set(), frozenset(), [], (), {}, True):
                    with self.subTest(attribute=attribute, value=value):
                        with patch.object(reader.os, "open", wraps=original_open) as opened:
                            with patch.object(reader.os, "supports_dir_fd", dir_fd_support | {opened}):
                                with patch.object(reader.os, attribute, value, create=True):
                                    if value == "MISSING":
                                        delattr(reader.os, attribute)
                                    with self.assertRaises(ValueError) as failure:
                                        read(str(sample))
                                    self.assertEqual(str(failure.exception), 'safe_read_unavailable')
                                    output = io.StringIO()
                                    with redirect_stdout(output):
                                        exitcode = cli.main([str(sample)])
                                    self.assertEqual(exitcode, 2)
                                    if output.getvalue():
                                        self.assertEqual(json.loads(output.getvalue())["status"], "OPEN")
                                    opened.assert_not_called()
            self.assertEqual(sample.read_bytes(), b"synthetic")

    def test_normal_set_and_frozenset_support_collections(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary).resolve() / "synthetic.bin"
            sample.write_bytes(b"synthetic")
            for collection in (set, frozenset):
                with patch.object(reader.os, "supports_dir_fd", collection(reader.os.supports_dir_fd)):
                    self.assertEqual(read(str(sample)), b"synthetic")
