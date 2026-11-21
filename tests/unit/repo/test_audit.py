import os

import pytest

from dvc.repo.audit import (
    DEFECT_STATUSES,
    EXIT_DEFECT,
    EXIT_INDETERMINATE,
    EXIT_OK,
    HASH_MISMATCH,
    INDETERMINATE_STATUSES,
    MISSING,
    OK,
    SIZE_MISMATCH,
    UNKNOWN,
    UNREADABLE,
    UNSTABLE,
    AuditRecord,
    AuditResult,
    _classify_exc,
    _verify,
)


def _make_odb(tmp_path, fs=None):
    from dvc_data.hashfile.db import get_odb

    if fs is None:
        from dvc_objects.fs import LocalFileSystem

        fs = LocalFileSystem()
    return get_odb(fs, str(tmp_path / "cache"))


def _write_obj(odb, content=b"data"):
    import hashlib

    oid = hashlib.md5(content).hexdigest()
    path = odb.oid_to_path(oid)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fobj:
        fobj.write(content)
    return oid


def test_verify_ok(tmp_path):
    odb = _make_odb(tmp_path)
    oid = _write_obj(odb)
    verdict = _verify(odb, oid, len(b"data"))
    assert verdict.status == OK
    assert verdict.actual_hash == oid


def test_verify_missing(tmp_path):
    odb = _make_odb(tmp_path)
    verdict = _verify(odb, "0" * 32, None)
    assert verdict.status == MISSING


def test_verify_size_mismatch(tmp_path):
    odb = _make_odb(tmp_path)
    oid = _write_obj(odb, b"data")
    verdict = _verify(odb, oid, 999)
    assert verdict.status == SIZE_MISMATCH
    assert verdict.actual_size == 4


def test_verify_hash_mismatch_same_size(tmp_path):
    odb = _make_odb(tmp_path)
    oid = _write_obj(odb, b"data")
    # overwrite with different content of the same size
    with open(odb.oid_to_path(oid), "wb") as fobj:
        fobj.write(b"xxxx")
    verdict = _verify(odb, oid, 4)
    assert verdict.status == HASH_MISMATCH
    assert verdict.actual_hash != oid


def test_verify_unstable_when_object_changes_during_audit(tmp_path):
    """An object swapped underneath the audit must not pass as verified."""
    from dvc_objects.fs import LocalFileSystem

    class FlakyFS(LocalFileSystem):
        calls = 0

        def info(self, path, *args, **kwargs):
            info = super().info(path, *args, **kwargs)
            type(self).calls += 1
            if type(self).calls > 1:
                # simulate a concurrent writer: mtime changed after hashing
                info = dict(info)
                info["mtime"] = (info.get("mtime") or 0) + 1
            return info

    odb = _make_odb(tmp_path, fs=FlakyFS())
    oid = _write_obj(odb)
    verdict = _verify(odb, oid, None)
    assert verdict.status == UNSTABLE
    assert verdict.status in INDETERMINATE_STATUSES


def test_verify_unstable_when_object_disappears(tmp_path):
    from dvc_objects.fs import LocalFileSystem

    class RemovingFS(LocalFileSystem):
        def info(self, path, *args, **kwargs):
            raise FileNotFoundError(path)

    odb = _make_odb(tmp_path, fs=RemovingFS())
    verdict = _verify(odb, "0" * 32, None)
    assert verdict.status == MISSING


def test_classify_exc_local_vs_remote():
    from dvc_objects.fs import LocalFileSystem

    class FakeRemoteFS:
        protocol = "s3"

    exc = OSError("boom")
    assert _classify_exc(LocalFileSystem(), exc) == UNREADABLE
    assert _classify_exc(FakeRemoteFS(), exc) == UNKNOWN


def _record(status, repaired=False):
    return AuditRecord(
        rev="workspace",
        path="p",
        kind="file",
        oid="o",
        location="local",
        status=status,
        expected_hash="o",
        repaired=repaired,
    )


@pytest.mark.parametrize("status", sorted(DEFECT_STATUSES))
def test_exit_code_defect(status):
    result = AuditResult(records=[_record(OK), _record(status)])
    assert result.exit_code == EXIT_DEFECT


@pytest.mark.parametrize("status", sorted(INDETERMINATE_STATUSES))
def test_exit_code_indeterminate(status):
    result = AuditResult(records=[_record(OK), _record(status)])
    assert result.exit_code == EXIT_INDETERMINATE


def test_exit_code_defect_beats_indeterminate():
    result = AuditResult(records=[_record(UNKNOWN), _record(HASH_MISMATCH)])
    assert result.exit_code == EXIT_DEFECT


def test_exit_code_ok():
    result = AuditResult(records=[_record(OK), _record(OK, repaired=True)])
    assert result.exit_code == EXIT_OK


def test_result_summary_and_dict():
    result = AuditResult(
        records=[_record(OK), _record(HASH_MISMATCH)], locations=["local"], checked=2
    )
    report = result.to_dict()
    assert report["summary"]["status"] == "corrupted"
    assert report["summary"]["by_location"]["local"] == {"ok": 1, "hash-mismatch": 1}
    (failure,) = report["failures"]
    assert failure["status"] == HASH_MISMATCH
    assert failure["location"] == "local"
