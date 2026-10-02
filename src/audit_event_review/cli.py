# SPDX-License-Identifier: GPL-3.0-only
import argparse
import json
from .input import read_regular_file
from .parser import Limits, Snapshot, open_report, review_snapshots


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_arguments")


def main(argv=None):
    parser = Parser(
        description="Offline Linux audit transaction evidence; PID lifetime and record authenticity remain OPEN"
    )
    parser.add_argument("logs", nargs="+")
    parser.add_argument(
        "--boot-context",
        help="Caller asserted common boot context for these snapshots; never validated by this tool",
    )
    parser.add_argument(
        "--byteorder",
        choices=("little", "big"),
        help="Caller asserted sockaddr family/host integer byte order",
    )
    try:
        args = parser.parse_args(argv)
        limits = Limits()
        if len(args.logs) > limits.snapshots:
            raise ValueError("snapshot_budget")
        snapshots, remaining = [], limits.total_bytes
        for path in args.logs:
            data = read_regular_file(path, min(limits.input_bytes, remaining))
            snapshots.append(Snapshot(data, args.boot_context))
            remaining -= len(data)
        result = review_snapshots(snapshots, byteorder=args.byteorder, limits=limits)
    except (ValueError, OSError, TypeError):
        result = open_report("input_or_arguments_rejected")
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2
