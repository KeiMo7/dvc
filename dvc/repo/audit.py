"""Content-integrity audit and repair for DVC-tracked data.

`dvc status` only checks whether cache/remote objects *exist*. This module
re-hashes object contents and compares them against the hashes recorded in
DVC files, for the local cache and for each requested remote independently,
and can optionally repair corrupted or missing objects from healthy copies.

Only content fingerprints are authoritative here: an object is considered
intact iff its re-computed hash matches the recorded one. File names, sizes
and mtimes are never trusted as proof of integrity (a recorded size, when
available, is only used to classify a mismatch as truncation/size drift).

The audit is strictly read-only unless ``repair=True``. Repair writes to a
temporary file, verifies its hash, and only then atomically moves it into
place, so a failed repair never leaves half-written objects behind and never
removes the only healthy copy.
"""

import logging
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from dvc.exceptions import DvcException

if TYPE_CHECKING:
    from dvc.repo import Repo
    from dvc_data.hashfile.db import HashFileDB

logger = logging.getLogger(__name__)

LOCAL_LOCATION = "local"

# verdict statuses
OK = "ok"
MISSING = "missing"
SIZE_MISMATCH = "size-mismatch"
HASH_MISMATCH = "hash-mismatch"
UNREADABLE = "unreadable"  # local object exists but cannot be read
UNSTABLE = "unstable"  # object changed/disappeared while being audited
UNKNOWN = "unknown"  # location unreachable/no permission: cannot determine

# repair outcome flags (recorded separately from the verdict)
REPAIRED = "repaired"
REPAIR_FAILED = "repair-failed"

#: statuses that mean the object is definitely not intact
DEFECT_STATUSES = {MISSING, SIZE_MISMATCH, HASH_MISMATCH, UNREADABLE}
#: statuses that mean we could not determine integrity
INDETERMINATE_STATUSES = {UNKNOWN, UNSTABLE}

EXIT_OK = 0
EXIT_DEFECT = 1
EXIT_INDETERMINATE = 2

_CHUNK_SIZE = 1024 * 1024
_DEFAULT_JOBS = 8


@dataclass
class ObjectRef:
    """A content-addressed object and the places that reference it."""

    oid: str
    expected_size: Optional[int] = None
    refs: list = field(default_factory=list)  # (rev, path, kind)


@dataclass
class Verdict:
    status: str
    actual_hash: Optional[str] = None
    actual_size: Optional[int] = None
    error: Optional[str] = None
    repair: Optional[str] = None  # None / REPAIRED / REPAIR_FAILED


@dataclass
class AuditRecord:
    rev: str
    path: str
    kind: str  # "file" | "dir" | "dir-entry"
    oid: str
    location: str
    status: str
    expected_hash: str
    actual_hash: Optional[str] = None
    expected_size: Optional[int] = None
    actual_size: Optional[int] = None
    error: Optional[str] = None
    repaired: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditResult:
    records: list = field(default_factory=list)
    locations: list = field(default_factory=list)
    checked: int = 0  # number of (location, object) checks performed

    @property
    def failed(self) -> list:
        """Records that are still not OK after any repair attempt."""
        return [r for r in self.records if r.status != OK]

    @property
    def indeterminate(self) -> list:
        return [r for r in self.failed if r.status in INDETERMINATE_STATUSES]

    @property
    def broken(self) -> list:
        return [r for r in self.failed if r.status in DEFECT_STATUSES]

    @property
    def exit_code(self) -> int:
        if self.broken:
            return EXIT_DEFECT
        if self.indeterminate:
            return EXIT_INDETERMINATE
        return EXIT_OK

    def summary(self) -> dict[str, Any]:
        by_location: dict[str, dict[str, int]] = {}
        for rec in self.records:
            counts = by_location.setdefault(rec.location, {})
            key = "repaired" if rec.repaired else rec.status
            counts[key] = counts.get(key, 0) + 1
        return {
            "checked": self.checked,
            "locations": self.locations,
            "status": {EXIT_OK: "ok", EXIT_DEFECT: "corrupted"}.get(
                self.exit_code, "indeterminate"
            ),
            "by_location": by_location,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "failures": [r.to_dict() for r in self.failed],
        }


def _is_local_fs(fs) -> bool:
    protocol = getattr(fs, "protocol", None)
    if isinstance(protocol, (tuple, list)):
        protocol = protocol[0] if protocol else None
    return protocol in ("local", "file")


def _classify_exc(fs, exc: BaseException) -> str:
    """Classify an unexpected fs error during a read.

    Local read errors mean the object cannot be read (a defect). Any error
    talking to a remote (network, auth, permissions) means we cannot tell
    anything about the object, so the location is indeterminate.
    """
    logger.debug("fs error during audit: %s", exc)
    if _is_local_fs(fs):
        return UNREADABLE
    return UNKNOWN


def _stat(fs, path: str):
    info = fs.info(path)
    mtime = info.get("mtime")
    if mtime is None:
        mtime = info.get("modified")
    return info.get("size"), mtime


def _hash_of(oid: str) -> str:
    """Hash part of an oid (strips the '.dir' suffix of dir manifests)."""
    return oid.split(".", maxsplit=1)[0]


def _verify(odb: "HashFileDB", oid: str, expected_size: Optional[int]) -> Verdict:  # noqa: PLR0911
    """Re-hash one object and compare it against its recorded oid.

    Never modifies anything. An object that changes underneath us while we
    read it is reported as UNSTABLE rather than OK or corrupted.
    """
    from dvc_data.hashfile.hash import hash_file

    fs = odb.fs
    path = odb.oid_to_path(oid)
    try:
        pre = _stat(fs, path)
    except FileNotFoundError:
        return Verdict(MISSING)
    except Exception as exc:  # noqa: BLE001
        return Verdict(_classify_exc(fs, exc), error=str(exc))

    size, _mtime = pre
    if expected_size is not None and size != expected_size:
        return Verdict(SIZE_MISMATCH, actual_size=size)

    try:
        _meta, actual = hash_file(path, fs, odb.hash_name, None)
    except FileNotFoundError:
        return Verdict(UNSTABLE, error="object disappeared while auditing")
    except Exception as exc:  # noqa: BLE001
        return Verdict(_classify_exc(fs, exc), error=str(exc))

    try:
        post = _stat(fs, path)
    except FileNotFoundError:
        return Verdict(
            UNSTABLE,
            actual_hash=actual.value,
            error="object disappeared while auditing",
        )
    except Exception as exc:  # noqa: BLE001
        return Verdict(_classify_exc(fs, exc), actual_hash=actual.value, error=str(exc))

    if post != pre:
        return Verdict(
            UNSTABLE,
            actual_hash=actual.value,
            actual_size=size,
            error="object changed while auditing",
        )
    if _hash_of(actual.value or "") != _hash_of(oid):
        return Verdict(HASH_MISMATCH, actual_hash=actual.value, actual_size=size)
    return Verdict(OK, actual_hash=actual.value, actual_size=size)


def _probe_remote(fs, path: str) -> Optional[str]:
    """Return an error message if the location cannot be talked to at all."""
    try:
        if fs.exists(path):
            return None
        # The storage root does not exist. For a local remote, distinguish
        # "never pushed to" (parent exists -> objects are genuinely missing)
        # from "storage not mounted" (parent missing too -> cannot tell).
        if _is_local_fs(fs):
            import os

            parent = os.path.dirname(path.rstrip(os.sep))
            if parent and not os.path.exists(parent):
                return f"storage root '{path}' not found (not mounted?)"
        return None
    except Exception as exc:  # noqa: BLE001
        return str(exc)


def _iter_outs(repo: "Repo", targets, recursive: bool):
    index = repo.index
    for stage_info in index.collect_targets(targets, recursive=recursive):
        for out in stage_info.stage.outs:
            if not out.use_cache or out.is_metric or out.is_plot:
                continue
            hash_info = out.hash_info
            if not hash_info or not hash_info.value:
                continue
            yield out, stage_info.filter_info


def _filter_prefix(out, filter_info) -> Optional[tuple]:
    """Key prefix inside a dir out for a granular target, if any."""
    if not filter_info or not out.hash_info or not out.hash_info.isdir:
        return None
    from dvc.utils import relpath

    try:
        rel = relpath(filter_info, out.fs_path)
    except Exception:  # noqa: BLE001
        return None
    if rel in (".", "") or rel.startswith(".."):
        return None
    return tuple(rel.split("/"))


def _collect_objects(  # noqa: C901
    repo: "Repo",
    targets=None,
    recursive: bool = False,
    revs=None,
    all_branches: bool = False,
    all_tags: bool = False,
    all_commits: bool = False,
    all_experiments: bool = False,
) -> dict:
    """Collect every object referenced by the selected scope.

    Returns a dict mapping oid -> ObjectRef. Objects are deduplicated across
    revisions/paths; every referencing (rev, path, kind) is remembered so
    findings can be located precisely.
    """
    from dvc_data.hashfile.tree import Tree

    objects: dict[str, ObjectRef] = {}

    def add(oid, expected_size, rev, path, kind):
        ref = objects.get(oid)
        if ref is None:
            ref = objects[oid] = ObjectRef(oid, expected_size)
        elif ref.expected_size is None:
            ref.expected_size = expected_size
        entry = (rev, path, kind)
        if entry not in ref.refs:
            ref.refs.append(entry)

    for rev in repo.brancher(
        revs=revs,
        all_branches=all_branches,
        all_tags=all_tags,
        all_commits=all_commits,
        all_experiments=all_experiments,
    ):
        from dvc.utils import relpath

        rev_name = rev or "workspace"
        for out, filter_info in _iter_outs(repo, targets, recursive):
            hash_info = out.hash_info
            oid = hash_info.value
            meta = getattr(out, "meta", None)
            size = getattr(meta, "size", None)
            try:
                out_path = relpath(out.fs_path, repo.root_dir)
            except Exception:  # noqa: BLE001
                out_path = out.def_path
            if not hash_info.isdir:
                add(oid, size, rev_name, out_path, "file")
                continue
            # dir out: audit the manifest object itself, then each entry
            add(oid, None, rev_name, out_path, "dir")
            try:
                tree = Tree.load(repo.cache.local, hash_info)
            except (DvcException, ValueError, OSError) as exc:
                logger.debug("cannot load dir manifest for '%s': %s", out_path, exc)
                continue
            prefix = _filter_prefix(out, filter_info)
            for key, (entry_meta, entry_hi) in tree.iteritems():
                if prefix and key[: len(prefix)] != prefix:
                    continue
                if not entry_hi or not entry_hi.value:
                    continue
                entry_size = getattr(entry_meta, "size", None)
                entry_path = "/".join([out_path, *key])
                add(entry_hi.value, entry_size, rev_name, entry_path, "dir-entry")
    return objects


def _verify_location(
    name: str, odb: "HashFileDB", objects: dict, jobs: Optional[int]
) -> dict:
    """Verify every object at one location. Returns oid -> Verdict."""
    from dvc.progress import Tqdm

    verdicts: dict[str, Verdict] = {}
    if not objects:
        return verdicts
    if name != LOCAL_LOCATION:
        error = _probe_remote(odb.fs, odb.path)
        if error is not None:
            logger.warning("cannot audit '%s': %s", name, error)
            for oid in objects:
                verdicts[oid] = Verdict(UNKNOWN, error=error)
            return verdicts

    items = sorted(objects.items())

    def check(item):
        oid, ref = item
        return oid, _verify(odb, oid, ref.expected_size)

    with Tqdm(
        desc=f"Auditing '{name}'",
        total=len(items),
        unit="obj",
        disable=None,
        leave=False,
    ) as pbar:
        if jobs == 1 or len(items) < 2:
            for item in items:
                oid, verdict = check(item)
                verdicts[oid] = verdict
                pbar.update()
        else:
            with ThreadPoolExecutor(max_workers=jobs or _DEFAULT_JOBS) as executor:
                for oid, verdict in executor.map(check, items):
                    verdicts[oid] = verdict
                    pbar.update()
    return verdicts


def _remove_quietly(fs, path: str) -> None:
    try:
        fs.remove(path)
    except Exception:
        logger.debug("failed to remove temporary file '%s'", path, exc_info=True)


def _repair_object(
    dest_odb: "HashFileDB",
    oid: str,
    expected_size: Optional[int],
    sources: list,
    original_status: str,
) -> Verdict:
    """Restore one object at dest_odb from a healthy copy.

    The copy is streamed to a temporary file on the destination, its hash is
    verified, and only then is it atomically moved into place and re-verified.
    Sources are never modified or removed. On failure the original defect
    status is kept so the object is still reported as broken.
    """
    from dvc_data.hashfile.hash import hash_file

    dest_fs = dest_odb.fs
    dest_path = dest_odb.oid_to_path(oid)
    errors = []
    for src_name, src_odb in sources:
        src_fs = src_odb.fs
        src_path = src_odb.oid_to_path(oid)
        tmp_path = f"{dest_path}.tmp{uuid.uuid4().hex}"
        try:
            pre = _stat(src_fs, src_path)
            dest_fs.makedirs(dest_fs.parent(dest_path), exist_ok=True)
            with (
                src_fs.open(src_path, "rb") as fsrc,
                dest_fs.open(tmp_path, "wb") as fdst,
            ):
                shutil.copyfileobj(fsrc, fdst, _CHUNK_SIZE)
            if _stat(src_fs, src_path) != pre:
                errors.append(f"{src_name}: source changed while copying")
                _remove_quietly(dest_fs, tmp_path)
                continue
            _meta, actual = hash_file(tmp_path, dest_fs, dest_odb.hash_name, None)
            if _hash_of(actual.value or "") != _hash_of(oid):
                errors.append(f"{src_name}: copied content does not match {oid}")
                _remove_quietly(dest_fs, tmp_path)
                continue
            dest_fs.move(tmp_path, dest_path)
        except Exception as exc:  # noqa: BLE001
            _remove_quietly(dest_fs, tmp_path)
            errors.append(f"{src_name}: {exc}")
            continue
        # repair is only done once the object re-verifies in place
        verdict = _verify(dest_odb, oid, expected_size)
        if verdict.status == OK:
            verdict.repair = REPAIRED
            return verdict
        errors.append(
            f"re-verification after repair failed: {verdict.error or verdict.status}"
        )
        return Verdict(original_status, error="; ".join(errors), repair=REPAIR_FAILED)
    return Verdict(
        original_status,
        error="; ".join(errors) or "no healthy copy available",
        repair=REPAIR_FAILED,
    )


def audit(  # noqa: C901, PLR0913, PLR0917
    repo: "Repo",
    targets=None,
    remote=None,
    repair: bool = False,
    recursive: bool = False,
    revs=None,
    all_branches: bool = False,
    all_tags: bool = False,
    all_commits: bool = False,
    all_experiments: bool = False,
    jobs: Optional[int] = None,
) -> AuditResult:
    """Audit content integrity of all objects in the selected scope.

    Args:
        targets: limit the audit to these data paths/stages.
        remote: names of remotes to audit in addition to the local cache.
            Each remote is audited independently.
        repair: restore missing/corrupted objects from healthy copies found
            at other audited locations, then re-verify them.
        revs/all_branches/all_tags/all_commits/all_experiments: revision
            scope. By default only the workspace is audited.
        jobs: number of parallel hashing workers.

    Returns:
        An AuditResult with one record per (rev, path, location).
    """
    objects = _collect_objects(
        repo,
        targets=targets,
        recursive=recursive,
        revs=revs,
        all_branches=all_branches,
        all_tags=all_tags,
        all_commits=all_commits,
        all_experiments=all_experiments,
    )

    locations: list[tuple[str, HashFileDB]] = [(LOCAL_LOCATION, repo.cache.local)]
    for name in remote or []:
        odb = repo.cloud.get_remote_odb(name, command="audit")
        locations.append((name, odb))

    verdicts: dict[str, dict[str, Verdict]] = {}
    for name, odb in locations:
        verdicts[name] = _verify_location(name, odb, objects, jobs)

    if repair:
        for name, odb in locations:
            for oid, verdict in verdicts[name].items():
                if verdict.status not in DEFECT_STATUSES:
                    continue
                sources = [
                    (other_name, other_odb)
                    for other_name, other_odb in locations
                    if other_name != name
                    and verdicts[other_name].get(oid)
                    and verdicts[other_name][oid].status == OK
                ]
                if not sources:
                    verdicts[name][oid] = Verdict(
                        verdict.status,
                        actual_hash=verdict.actual_hash,
                        actual_size=verdict.actual_size,
                        error="no healthy copy available",
                        repair=REPAIR_FAILED,
                    )
                    continue
                logger.info(
                    "repairing '%s' at '%s' from '%s'", oid, name, sources[0][0]
                )
                verdicts[name][oid] = _repair_object(
                    odb, oid, objects[oid].expected_size, sources, verdict.status
                )

    result = AuditResult(locations=[name for name, _ in locations])
    for name, _odb in locations:
        for oid, ref in objects.items():
            verdict = verdicts[name][oid]
            result.checked += 1
            for rev, path, kind in ref.refs:
                result.records.append(
                    AuditRecord(
                        rev=rev,
                        path=path,
                        kind=kind,
                        oid=oid,
                        location=name,
                        status=verdict.status,
                        expected_hash=oid,
                        actual_hash=verdict.actual_hash,
                        expected_size=ref.expected_size,
                        actual_size=verdict.actual_size,
                        error=verdict.error,
                        repaired=verdict.repair == REPAIRED,
                    )
                )
    return result
