# import-time-sandbox

**The worm fires when you `import` it — install-time scanners never see it.**

On 2026-09-23, Socket reported a backdoored MemTensor npm plugin and PyPI MemoryOS 2.0.34 dropping the **sckit Go credential worm** — firing at import time and self-propagating via stolen publish tokens (Socket.dev). The first worm targeting AI agent memory infrastructure. `--ignore-scripts` doesn't help: nothing is installed, the import itself is the payload.

`import-time-sandbox` imports any npm/PyPI package inside a locked-down child process and flags import-time behavior:
- **Network attempts** (`socket.getaddrinfo` audit hook) — cloud metadata endpoint (169.254.169.254) → CRITICAL
- **Credential reads** — opens of `.ssh`, `.aws`, `.env`, `id_rsa`, … → CRITICAL
- **Process spawns** (`os.system`, `subprocess`) → HIGH
- **Persistence writes** (startup/launchd/systemd/cron paths) → CRITICAL

Sandboxing: scrubbed environment, temp HOME, CPU/memory limits (POSIX), hard wall-clock timeout — the child is killed, never trusted. Stdlib only.

## What it does NOT detect
Behavior that only triggers on specific inputs, delayed timers, or native extensions that bypass audit hooks. A clean report means "no flagged behavior observed in this run" — **not** a safety certification.

## Usage
```
python -m import_time_sandbox suspicious_package --path /path/to/pkg --timeout 20
```

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
