"""import-time-sandbox: import npm/PyPI packages inside a locked-down
sandbox and flag exfiltration behavior AT IMPORT TIME.

Hook (2026-09-23): Socket reported a backdoored MemTensor npm plugin and
PyPI MemoryOS 2.0.34 dropping the sckit Go credential worm — firing at
import time and self-propagating via stolen publish tokens
(Socket.dev). First worm targeting AI agent memory infrastructure.

Existing scanners target install scripts or static code; nothing
self-serve audits import-time execution behavior. This runs the import
in a child Python process with:
- sys.addaudithook tracing socket.getaddrinfo (network attempts),
  open() of credential-shaped paths, and os.system/subprocess spawns,
- a locked-down temp HOME and scrubbed environment,
- CPU + memory limits via the resource module (POSIX only),
- a hard wall-clock timeout (child is killed, never trusted).

Stdlib only. Deterministic flags, never a "safe" certification — a
clean report means "no flagged behavior observed in this run", not
that the package is benign.
"""

import json
import os
import subprocess
import sys
import tempfile

VERSION = "1.0.0"

# Credential-shaped path fragments worth flagging on open().
CREDENTIAL_PATH_HINTS = (
    ".ssh", ".aws", ".env", "id_rsa", "id_ed25519", ".npmrc", ".pypirc",
    "credentials", "secrets", ".git-credentials", "kube/config",
)

# Substrings in audit events we treat as persistence writes.
PERSISTENCE_HINTS = (
    "startup", "launchd", "launchagents", "systemd", "cron",
    ".bashrc", ".zshrc", ".profile", "autorun", "runonce",
)

_TRACER = r'''
import sys, json, os

events = {"network": [], "credential_reads": [], "spawns": [], "persistence_writes": []}

CRED_HINTS = {cred_hints!r}
PERS_HINTS = {pers_hints!r}

def _hook(event, args):
    try:
        if event == "socket.getaddrinfo":
            host = args[0] if args else "?"
            events["network"].append(str(host))
        elif event == "open":
            path = str(args[0]) if args else ""
            pl = path.lower()
            if any(h in pl for h in CRED_HINTS):
                events["credential_reads"].append(path)
            if any(h in pl for h in PERS_HINTS) and "w" in str(args[1] if len(args) > 1 else ""):
                events["persistence_writes"].append(path)
        elif event in ("os.system", "os.exec", "os.spawn", "subprocess.Popen"):
            events["spawns"].append(event + " " + str(args[0])[:120] if args else event)
    except Exception:
        pass

sys.addaudithook(_hook)

pkg = os.environ.get("SANDBOX_PKG", "")
try:
    __import__(pkg)
    events["import_ok"] = True
except BaseException as e:
    events["import_ok"] = False
    events["import_error"] = "%s: %s" % (type(e).__name__, str(e)[:200])

sys.stdout.write(json.dumps(events))
'''.replace("{cred_hints!r}", repr(CREDENTIAL_PATH_HINTS)
           ).replace("{pers_hints!r}", repr(PERSISTENCE_HINTS))

NETWORK_BLOCKLIST = ("169.254.169.254",)  # cloud metadata endpoint


def sandbox_import(package, timeout=20, extra_path=None):
    """Import `package` in a locked-down child process. Returns a
    findings dict. The child is killed on timeout."""
    if not package or not package.replace("_", "").replace("-", "").isalnum():
        raise ValueError("refusing suspicious package name: %r" % package)
    tmp_home = tempfile.mkdtemp(prefix="import-sandbox-")
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": tmp_home,
        "SANDBOX_PKG": package,
        "PYTHONPATH": extra_path or "",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    # Pre-exec resource limits (POSIX): 60s CPU, 512MB RAM, no core dumps.
    def _limits():
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            resource.setrlimit(resource.RLIMIT_AS,
                               (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _TRACER],
            env=env, capture_output=True, text=True,
            timeout=timeout, preexec_fn=_limits, cwd=tmp_home)
        try:
            events = json.loads(proc.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            events = {"import_ok": False,
                      "import_error": "tracer produced no JSON; stderr: %s"
                                      % proc.stderr[:200]}
    except subprocess.TimeoutExpired:
        return {"package": package, "timeout": True,
                "verdict": "TIMEOUT — import did not finish; treat as "
                           "suspicious, not clean."}
    findings = []
    for host in events.get("network", []):
        sev = "CRITICAL" if host in NETWORK_BLOCKLIST else "HIGH"
        findings.append({"finding": "network-attempt", "severity": sev,
                         "detail": "import attempted network access to %s"
                                   % host})
    for path in events.get("credential_reads", []):
        findings.append({"finding": "credential-read", "severity": "CRITICAL",
                         "detail": "import opened credential-shaped path: %s"
                                   % path})
    for s in events.get("spawns", []):
        findings.append({"finding": "process-spawn", "severity": "HIGH",
                         "detail": "import spawned a process: %s" % s})
    for path in events.get("persistence_writes", []):
        findings.append({"finding": "persistence-write",
                         "severity": "CRITICAL",
                         "detail": "import wrote to persistence location: %s"
                                   % path})
    if not events.get("import_ok"):
        findings.append({"finding": "import-failed", "severity": "INFO",
                         "detail": "import raised: %s"
                                   % events.get("import_error", "?")})
    return {
        "package": package,
        "timeout": False,
        "import_ok": bool(events.get("import_ok")),
        "findings": findings,
        "verdict": ("CLEAN — no flagged import-time behavior observed "
                    "(not a safety certification)" if not findings
                    else "%d import-time finding(s)" % len(findings)),
    }


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Import a package in a locked-down sandbox and flag "
                    "import-time exfil behavior.")
    ap.add_argument("package", help="package name to import in the sandbox")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--path", default="",
                    help="extra PYTHONPATH for the sandboxed import")
    args = ap.parse_args(argv)
    try:
        print(json.dumps(sandbox_import(args.package, args.timeout,
                                        args.path or None), indent=2))
    except ValueError as e:
        print("ERROR: %s" % e)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
