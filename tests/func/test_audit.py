import os

import pytest

from dvc.cli import main
from dvc.repo.audit import (
    EXIT_DEFECT,
    EXIT_INDETERMINATE,
    EXIT_OK,
    HASH_MISMATCH,
    MISSING,
    SIZE_MISMATCH,
    UNKNOWN,
)


def _obj_path(odb, oid):
    return odb.oid_to_path(oid)


def _corrupt(odb, oid, content=b"corrupted"):
    path = _obj_path(odb, oid)
    os.chmod(path, 0o644)
    with open(path, "wb") as fobj:
        fobj.write(content)


def _append(odb, oid, content=b"extra"):
    path = _obj_path(odb, oid)
    os.chmod(path, 0o644)
    with open(path, "ab") as fobj:
        fobj.write(content)


def _remove(odb, oid):
    os.remove(_obj_path(odb, oid))


@pytest.fixture
def data_repo(tmp_dir, dvc):
    tmp_dir.dvc_gen("foo", "foo content")
    tmp_dir.dvc_gen("data", {"sub1": "a" * 16, "sub2": "b" * 16})
    return dvc


def _oids(dvc):
    from dvc_data.hashfile.tree import Tree

    oids = {}
    for out in dvc.index.outs:
        hi = out.hash_info
        if not hi or not hi.value:
            continue
        if hi.isdir:
            tree = Tree.load(dvc.cache.local, hi)
            for key, (_meta, entry_hi) in tree.iteritems():
                oids["/".join([out.def_path, *key])] = entry_hi.value
        else:
            oids[out.def_path] = hi.value
    return oids


def test_clean(data_repo):
    result = data_repo.audit()
    assert result.exit_code == EXIT_OK
    assert result.failed == []
    # foo + dir manifest + 2 dir entries
    assert result.checked == 4


def test_clean_json(data_repo, capsys):
    assert main(["audit", "--json"]) == EXIT_OK
    import json

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["status"] == "ok"
    assert report["summary"]["locations"] == ["local"]
    assert report["failures"] == []


def test_size_mismatch(data_repo):
    oids = _oids(data_repo)
    _append(data_repo.cache.local, oids["foo"])
    result = data_repo.audit()
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == SIZE_MISMATCH
    assert rec.path == "foo"
    assert rec.location == "local"
    assert rec.rev == "workspace"
    assert rec.actual_size != rec.expected_size


def test_same_size_content_corruption(data_repo):
    oids = _oids(data_repo)
    oid = oids["foo"]
    path = _obj_path(data_repo.cache.local, oid)
    size = os.path.getsize(path)
    _corrupt(data_repo.cache.local, oid, content=b"x" * size)
    result = data_repo.audit()
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == HASH_MISMATCH
    assert rec.path == "foo"
    assert rec.actual_hash != rec.expected_hash


def test_dir_entry_missing(data_repo):
    oids = _oids(data_repo)
    _remove(data_repo.cache.local, oids["data/sub1"])
    result = data_repo.audit()
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == MISSING
    assert rec.path == "data/sub1"
    assert rec.kind == "dir-entry"


def test_dir_entry_truncated(data_repo):
    oids = _oids(data_repo)
    _corrupt(data_repo.cache.local, oids["data/sub2"], content=b"b")
    result = data_repo.audit()
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == HASH_MISMATCH
    assert rec.path == "data/sub2"


def test_dir_manifest_missing(data_repo):
    from dvc_data.hashfile.tree import Tree  # noqa: F401

    for out in data_repo.index.outs:
        if out.hash_info and out.hash_info.isdir:
            _remove(data_repo.cache.local, out.hash_info.value)
    result = data_repo.audit()
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == MISSING
    assert rec.kind == "dir"
    assert rec.path == "data"


def test_remote_independent(data_repo, local_remote):
    data_repo.push()
    oids = _oids(data_repo)
    remote_odb = data_repo.cloud.get_remote_odb("upstream")
    _corrupt(remote_odb, oids["foo"], content=b"z" * 11)
    result = data_repo.audit(remote=["upstream"])
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.location == "upstream"
    assert rec.status == HASH_MISMATCH
    # local cache verdict is not polluted by the remote one
    local_recs = [r for r in result.records if r.location == "local"]
    assert all(r.status == "ok" for r in local_recs)


def test_remote_missing_and_truncated(data_repo, local_remote):
    data_repo.push()
    oids = _oids(data_repo)
    remote_odb = data_repo.cloud.get_remote_odb("upstream")
    _remove(remote_odb, oids["foo"])
    _corrupt(remote_odb, oids["data/sub1"], content=b"a")
    result = data_repo.audit(remote=["upstream"])
    assert result.exit_code == EXIT_DEFECT
    failed = {(r.location, r.path): r.status for r in result.failed}
    assert failed[("upstream", "foo")] == MISSING
    assert failed[("upstream", "data/sub1")] == HASH_MISMATCH
    assert ("local", "foo") not in failed


def test_unreachable_remote(data_repo):
    with data_repo.config.edit() as conf:
        conf["remote"]["broken"] = {"url": "/nonexistent-root-xyz/a/b"}
    result = data_repo.audit(remote=["broken"])
    assert result.exit_code == EXIT_INDETERMINATE
    assert result.broken == []
    assert {r.status for r in result.failed if r.location == "broken"} == {UNKNOWN}
    # local results are unaffected
    assert all(r.status == "ok" for r in result.records if r.location == "local")


def test_all_commits_attributes_rev(tmp_dir, scm, data_repo):
    oids_v1 = _oids(data_repo)
    scm.add(["foo.dvc", "data.dvc", ".gitignore"])
    scm.commit("v1")
    tmp_dir.dvc_gen("foo", "foo content v2", commit="v2")
    # corrupt the object only referenced by v1
    _corrupt(data_repo.cache.local, oids_v1["foo"], content=b"y" * 11)
    result = data_repo.audit(all_commits=True)
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert rec.status == HASH_MISMATCH
    assert rec.rev != "workspace"
    assert rec.path == "foo"


def test_empty_repo(tmp_dir, dvc):
    result = dvc.audit()
    assert result.exit_code == EXIT_OK
    assert result.checked == 0
    assert result.failed == []


def test_no_remote_configured(data_repo):
    assert data_repo.config["remote"] == {}
    result = data_repo.audit()
    assert result.exit_code == EXIT_OK


def test_targets(data_repo):
    result = data_repo.audit(targets=["foo"])
    assert result.checked == 1
    result = data_repo.audit(targets=["data/sub1"])
    # the manifest plus the targeted entry
    assert result.checked == 2
    assert {r.path for r in result.records} == {"data", "data/sub1"}


def test_repair_from_remote(data_repo, local_remote):
    data_repo.push()
    oids = _oids(data_repo)
    oid = oids["foo"]
    _corrupt(data_repo.cache.local, oid, content=b"q" * 11)
    result = data_repo.audit(remote=["upstream"], repair=True)
    assert result.exit_code == EXIT_OK
    (rec,) = [r for r in result.records if r.oid == oid and r.location == "local"]
    assert rec.repaired
    # re-audit must be clean
    assert data_repo.audit(remote=["upstream"]).exit_code == EXIT_OK


def test_repair_remote_from_local(data_repo, local_remote):
    data_repo.push()
    oids = _oids(data_repo)
    remote_odb = data_repo.cloud.get_remote_odb("upstream")
    _remove(remote_odb, oids["data/sub1"])
    result = data_repo.audit(remote=["upstream"], repair=True)
    assert result.exit_code == EXIT_OK
    assert data_repo.audit(remote=["upstream"]).failed == []


def test_repair_no_healthy_copy(data_repo):
    oids = _oids(data_repo)
    oid = oids["foo"]
    path = _obj_path(data_repo.cache.local, oid)
    _corrupt(data_repo.cache.local, oid, content=b"q" * 11)
    result = data_repo.audit(repair=True)
    assert result.exit_code == EXIT_DEFECT
    (rec,) = result.failed
    assert "no healthy copy" in (rec.error or "")
    # the corrupted object is left in place, not deleted
    assert os.path.exists(path)


def test_repair_leaves_no_temp_files(data_repo, local_remote):
    data_repo.push()
    oids = _oids(data_repo)
    _corrupt(data_repo.cache.local, oids["foo"], content=b"q" * 11)
    assert data_repo.audit(remote=["upstream"], repair=True).exit_code == EXIT_OK
    cache_dir = data_repo.cache.local.path
    for _root, _dirs, files in os.walk(cache_dir):
        for name in files:
            assert ".tmp" not in name


def test_cli_exit_codes(data_repo, local_remote):
    assert main(["audit"]) == EXIT_OK
    oids = _oids(data_repo)
    _corrupt(data_repo.cache.local, oids["foo"], content=b"q" * 11)
    assert main(["audit"]) == EXIT_DEFECT
    with data_repo.config.edit() as conf:
        conf["remote"]["broken"] = {"url": "/nonexistent-root-xyz/a/b"}
    # corruption (exit 1) takes precedence over indeterminate (exit 2)
    assert main(["audit", "-r", "broken"]) == EXIT_DEFECT


def test_cli_json_failure_entries(data_repo, capsys):
    import json

    oids = _oids(data_repo)
    _corrupt(data_repo.cache.local, oids["foo"], content=b"q" * 11)
    assert main(["audit", "--json"]) == EXIT_DEFECT
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["status"] == "corrupted"
    (entry,) = report["failures"]
    assert entry["path"] == "foo"
    assert entry["location"] == "local"
    assert entry["rev"] == "workspace"
    assert entry["status"] == HASH_MISMATCH
    assert entry["expected_hash"] == oids["foo"]
    assert entry["actual_hash"] != oids["foo"]
