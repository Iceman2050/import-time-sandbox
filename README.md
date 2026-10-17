# import-time-sandbox

**The MemTensor worm (Sep 2026): malicious packages that execute the moment you `import` them.**

`pip install` is only half the attack — the payload fires at import time, phoning home or dropping files before your code runs a single line. This tool imports a package inside a restricted sandbox and reports exactly what the import tried to do: network, filesystem, subprocess.

## 30-second quickstart
```
python import_time_sandbox.py somepackage --path ./vendor
```

## Example output
```
{
  "package": "evilpkg2",
  "timeout": false,
  "import_ok": false,
  "findings": [
    {
      "finding": "network-attempt",
      "severity": "CRITICAL",
      "detail": "import attempted network access to 169.254.169.254"
    },
    {
      "finding": "import-failed",
      "severity": "INFO",
      "detail": "import raised: PermissionError: [Errno 1] Operation not permitted"
    }
  ],
  "verdict": "2 import-time finding(s)"
}
```

`--timeout` per import (default 20s), `--path` adds a vendor directory. Never run untrusted packages outside the sandbox.

## What it does NOT do
A restricted sandbox, not a VM — sophisticated malware can detect sandboxes. A clean import is not a safety certification (the tool says so on every run).

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI



> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
