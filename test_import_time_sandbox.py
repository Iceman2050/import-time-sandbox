"""Tests for import_time_sandbox (uses real sandboxed child processes)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from import_time_sandbox import sandbox_import  # noqa: E402

PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print("PASS  " + name)
    except Exception as e:  # noqa: BLE001
        FAIL.append((name, repr(e)))
        print("FAIL  %s: %r" % (name, e))


def _pkg_dir(name, code):
    d = tempfile.mkdtemp(prefix="its-test-")
    with open(os.path.join(d, name + ".py"), "w") as fh:
        fh.write(code)
    return d


def t_benign_package_clean():
    d = _pkg_dir("benignpkg1", "X = 1\n")
    r = sandbox_import("benignpkg1", timeout=20, extra_path=d)
    assert r["import_ok"] is True, r
    assert r["findings"] == [], r
    assert r["verdict"].startswith("CLEAN")


def t_network_attempt_flagged():
    d = _pkg_dir("netpkg2", "import socket\nsocket.getaddrinfo('example.invalid', 80)\n")
    r = sandbox_import("netpkg2", timeout=20, extra_path=d)
    assert any(f["finding"] == "network-attempt" for f in r["findings"]), r


def t_credential_read_flagged():
    d = _pkg_dir("credpkg3", "open('/home/u/.ssh/id_rsa').read()\n")
    r = sandbox_import("credpkg3", timeout=20, extra_path=d)
    assert any(f["finding"] == "credential-read" and f["severity"] == "CRITICAL"
               for f in r["findings"]), r


def t_spawn_flagged():
    d = _pkg_dir("spawnpkg4", "import os\nos.system('echo hi')\n")
    r = sandbox_import("spawnpkg4", timeout=20, extra_path=d)
    assert any(f["finding"] == "process-spawn" for f in r["findings"]), r


def t_suspicious_name_refused():
    try:
        sandbox_import("../../evil", timeout=5)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def t_missing_package_import_failed_info():
    r = sandbox_import("definitely_not_a_real_pkg_xyz", timeout=20)
    assert r["import_ok"] is False
    assert any(f["finding"] == "import-failed" for f in r["findings"])


def test_all_checks():
    for name, fn in sorted(
            [(k, v) for k, v in globals().items() if k.startswith("t_")]):
        check(name, fn)
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    assert not FAIL


if __name__ == "__main__":
    test_all_checks()
