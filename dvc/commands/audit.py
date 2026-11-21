import logging

from dvc.cli import completion, formatter
from dvc.cli.command import CmdBase
from dvc.cli.utils import append_doc_link
from dvc.ui import ui

logger = logging.getLogger(__name__)


def _human_report(result) -> None:
    from collections import Counter

    summary = result.summary()
    for location in summary["locations"]:
        counts: Counter = Counter()
        for rec in result.records:
            if rec.location == location:
                counts["repaired" if rec.repaired else rec.status] += 1
        parts = ", ".join(
            f"{count} {status}" for status, count in sorted(counts.items())
        )
        ui.write(f"{location}: {parts or '0 objects'}")
    ui.write(
        f"checked {summary['checked']} objects "
        f"across {len(summary['locations'])} location(s)"
    )

    failed = result.failed
    if not failed:
        ui.write("No corruption found.")
        return
    for rec in failed:
        line = (
            f"[{rec.status}] {rec.location}: {rec.path} "
            f"(rev: {rec.rev}, kind: {rec.kind}, oid: {rec.oid})"
        )
        details = []
        if rec.actual_hash and rec.actual_hash != rec.expected_hash:
            details.append(f"expected hash {rec.expected_hash}, got {rec.actual_hash}")
        if (
            rec.expected_size is not None
            and rec.actual_size is not None
            and rec.expected_size != rec.actual_size
        ):
            details.append(f"expected size {rec.expected_size}, got {rec.actual_size}")
        if rec.error:
            details.append(rec.error)
        if details:
            line += " -- " + "; ".join(details)
        ui.write(line)


class CmdAudit(CmdBase):
    def run(self):
        result = self.repo.audit(
            targets=self.args.targets,
            remote=self.args.remote,
            repair=self.args.repair,
            recursive=self.args.recursive,
            revs=self.args.rev,
            all_branches=self.args.all_branches,
            all_tags=self.args.all_tags,
            all_commits=self.args.all_commits,
            all_experiments=self.args.all_experiments,
            jobs=self.args.jobs,
        )
        if self.args.json:
            ui.write_json(result.to_dict())
        else:
            _human_report(result)
        return result.exit_code


def add_parser(subparsers, parent_parser):
    AUDIT_HELP = (
        "Audit content integrity of DVC-tracked data by re-hashing objects "
        "in the local cache and, optionally, on remotes."
    )
    audit_parser = subparsers.add_parser(
        "audit",
        parents=[parent_parser],
        description=append_doc_link(AUDIT_HELP, "audit"),
        help=AUDIT_HELP,
        formatter_class=formatter.RawDescriptionHelpFormatter,
    )
    audit_parser.add_argument(
        "targets",
        nargs="*",
        help="Limit the audit to these stages or data paths.",
    ).complete = completion.FILE
    audit_parser.add_argument(
        "-r",
        "--remote",
        action="append",
        default=None,
        help="Also audit objects on this remote (may be specified multiple "
        "times). Each remote is audited independently.",
    )
    audit_parser.add_argument(
        "--repair",
        action="store_true",
        default=False,
        help="Repair missing or corrupted objects from healthy copies found "
        "at other audited locations, then re-verify them.",
    )
    audit_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Print the audit report in JSON format.",
    )
    audit_parser.add_argument(
        "-R",
        "--recursive",
        action="store_true",
        default=False,
        help="Recursively search for DVC files in subdirectories.",
    )
    audit_parser.add_argument(
        "--rev",
        action="append",
        default=None,
        help="Git revision(s) to audit (in addition to the workspace).",
    )
    audit_parser.add_argument(
        "--all-branches",
        action="store_true",
        default=False,
        help="Audit objects referenced by all Git branches.",
    )
    audit_parser.add_argument(
        "--all-tags",
        action="store_true",
        default=False,
        help="Audit objects referenced by all Git tags.",
    )
    audit_parser.add_argument(
        "--all-commits",
        action="store_true",
        default=False,
        help="Audit objects referenced by all Git commits.",
    )
    audit_parser.add_argument(
        "--all-experiments",
        action="store_true",
        default=False,
        help="Audit objects referenced by all DVC experiments.",
    )
    audit_parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        help="Number of parallel hashing workers.",
    )
    audit_parser.set_defaults(func=CmdAudit)
