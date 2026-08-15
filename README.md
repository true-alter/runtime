# alter-runtime - ~Alter Identity Runtime

> The local daemon that lives alongside you, subscribes to your per-`~handle`
> Cloudflare Durable Object, and renders your identity field across every surface
> your device touches - terminal, IDE, status bars, desktop tray, browser extension.
> Falls back gracefully to direct MCP polling when the edge is unreachable.

## Alpha release - filesystem key storage

**This is an alpha release.** The public API surface (CLI flags,
Unix-socket JSON schema, D-Bus interface, Python SDK signatures) may change in
backwards-incompatible ways before the stable release. Pin exact versions in
downstream tooling before upgrading.

**Private keys are stored on the filesystem, not in an OS keychain.** On first
`alter-runtime init`, the device Ed25519 keypair is written to
`~/.config/alter/keypair.json` (or `$XDG_CONFIG_HOME/alter/keypair.json` if the
XDG variable is set) with `0600` permissions. The file is readable only by the
owning user and never leaves the device. This behaviour is deliberate for the
alpha: it keeps the daemon self-contained on any POSIX host and avoids a hard
dependency on distro-specific secret stores during early testing.

**OS-native secret storage is deferred to a future release:** Linux `libsecret` /
`kwallet`, macOS Keychain, and Windows Credential Manager integration will ship
behind a `keystore = "native"` config knob. Filesystem storage will remain the
documented fallback.

**For high-stakes use during the alpha** - any deployment where a device
compromise would imply identity compromise - pair the runtime with
hardware-attested passkey registration via the browser claim flow (graduated
attestation). The filesystem-stored device key then scopes only to ambient
signal ingestion, not to high-assurance authorisations, which require a fresh
hardware passkey ceremony per session.

**Reporting issues.** Security-relevant reports: please email
`security@truealter.com` rather than filing a public issue. Non-security bugs
and feature requests: email `support@truealter.com`.

## Status

Shipped: the daemon and `AlterClient` SDK; subscribers, the Unix socket,
D-Bus, and the git watcher; systemd and launchd service units; the local
editor and shell hook surfaces; and the eBPF subscriber.

## Install

```bash
# PyPI (cross-platform)
pip install truealter

# Arch Linux (AUR)
pacman -S alter-runtime          # via your AUR helper (yay -S alter-runtime, paru -S alter-runtime, etc.)

# macOS / Linux Homebrew tap
brew install alter-runtime

# Optional extras (advanced - direct install of the runtime package)
pip install 'alter-runtime[dbus,systemd]'          # Linux desktop
pip install 'alter-runtime[windows]'                # Windows
pip install 'alter-runtime[all]'                    # Everything
```

## Quickstart

```bash
# 1. Generate device keypair, install host service unit, authenticate via alter-cli
alter-runtime init

# 2. Start the daemon
alter-runtime start            # Launches via systemd/launchd/Windows Service
# or run in the foreground for debugging
alter-runtime daemon

# 3. Query current field state
alter-runtime status
alter-runtime query attunement

# 4. Manually ingest a signal (useful for testing)
alter-runtime ingest --kind git_commit --payload '{"sha":"abc123"}'

# 5. Stop
alter-runtime stop
```

## What it does

1. **Subscribes** to your per-`~handle` Cloudflare Durable Object over Server-Sent Events
   at `https://mcp.truealter.com/events/~yourhandle/stream`. Events arrive with ~50ms
   latency worldwide.

2. **Falls back gracefully** to direct polling of the `~alter` MCP endpoint at
   `https://api.truealter.com/api/v1/mcp` when the DO is unreachable for more than 3
   seconds. Your surfaces never know which path served them.

3. **Exposes** three local transports:
   - **Unix socket** at `/run/user/$UID/alter.sock` (Linux) or
     `~/Library/Application Support/alter/runtime.sock` (macOS) - line-delimited JSON
   - **D-Bus** interface `org.alter.Identity1` on the session bus (Linux) - used by
     GNOME/KDE/Waybar modules
   - **HTTP/SSE** loopback at `http://localhost:<port>/events` - used by local
     editor hooks and shell scripts

4. **Collects ambient signals** via adapters:
   - Git commits, branch switches, pushes (via `watchdog` on `.git/refs/heads/`)
   - Editor session hook events (forwarded from local shell hooks)
   - Shell command invocations (opt-in)
   - eBPF kernel attestations (shipped)

5. **Maintains a local cache** of your last-known-good field state so the first-paint
   tilde warmth renders in <1 second, even offline. The cached state always renders,
   so your surfaces stay continuous across restarts and network drops.

## Layout

```
alter-runtime/
├── pyproject.toml
├── README.md
├── LICENSE
├── alter_runtime/
│   ├── __init__.py
│   ├── config.py                 # XDG loader, reads the CLI session.json
│   ├── daemon.py                 # asyncio supervisor
│   ├── cli.py                    # argparse entrypoint: init|start|stop|status|query|ingest|daemon
│   ├── sdk/
│   │   ├── __init__.py
│   │   └── client.py             # AlterClient (async identity MCP client)
│   ├── subscribers/
│   │   ├── do_sse.py             # primary - subscribes to the per-handle DO SSE stream
│   │   └── mcp_fallback.py       # fallback - polls api.truealter.com/api/v1/mcp
│   ├── sockets/
│   │   ├── unix.py               # /run/user/$UID/alter.sock
│   │   └── dbus.py               # org.alter.Identity1
│   ├── adapters/
│   │   └── git_watcher.py        # watchdog on .git/refs/heads/
│   └── services/
│       ├── systemd/alter-runtime.service
│       ├── launchd/com.alter.runtime.plist
│       └── windows/AlterRuntimeService.py
└── tests/
    ├── conftest.py
    ├── test_cli.py
    ├── test_daemon.py
    └── test_client.py
```

## SDK usage

```python
import asyncio
from alter_runtime import AlterClient


async def main():
    # Auto-discovers the local daemon's Unix socket first, falls back to
    # direct MCP if the daemon isn't running.
    client = AlterClient.auto_discover()

    async with client:
        whoami = await client.whoami()
        print(f"{whoami['handle']}: attunement={whoami['attunement']}")

        # Ingest an ambient signal
        await client.ingest(
            kind="tool_invocation",
            payload={"tool": "my-custom-cli", "duration_ms": 42},
        )


asyncio.run(main())
```

## Packaging

`alter-runtime` is distributed through several install channels:

- **PyPI** - `pip install alter-runtime`
- **Arch Linux (AUR)** - `alter-runtime`
- **Homebrew** - `brew install alter-runtime`

Pin an exact version in downstream tooling during the alpha before upgrading.

## Related projects

- [`@truealter/sdk`](https://www.npmjs.com/package/@truealter/sdk) - TypeScript
  SDK client for the public MCP server.
- `~alter` MCP endpoint - `https://mcp.truealter.com` (SSE per-`~handle` stream)
  and `https://api.truealter.com/api/v1/mcp` (HTTP fallback). Both are documented
  at [truealter.com](https://truealter.com).
