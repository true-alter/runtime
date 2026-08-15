"""Command-line entrypoint for alter-runtime.

Subcommands:
  init      Generate Ed25519 device keypair, install host service unit,
            verify CLI session, ensure XDG directories exist.
  start     Enable + start the host service unit (systemd/launchd/Windows Service).
  stop      Stop the host service unit.
  status    Report current daemon state (running? socket reachable? last event?).
  daemon    Run the supervisor in the foreground (for systemd Type=exec or debugging).
  query     Query the current materialised view (attunement, warmth, trust tier).
  ingest    Manually ingest a signal (for testing).
  send      Send a member-to-member message via the running daemon.

Matches the shape of the companion CLI's command handler - a simple switch-on-verb,
no external CLI framework dependency (argparse is stdlib).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys
import textwrap
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from alter_runtime.config import (
    cache_dir,
    config_dir,
    ensure_directories,
    keypair_path,
    load_config,
    load_session,
    unix_socket_path,
)
from alter_runtime.daemon import run_daemon
from alter_runtime.service_install import current_platform, service_status
from alter_runtime.service_install import install as install_service
from alter_runtime.service_install import uninstall as uninstall_service

__all__ = ["build_parser", "main"]

logger = logging.getLogger("alter_runtime.cli")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alter-runtime",
        description=(
            "~Alter Identity Runtime - local identity runtime daemon. "
            "See the project README for architectural context."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (overrides ALTER_RUNTIME_LOG_LEVEL).",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # init
    p_init = sub.add_parser(
        "init",
        help="Bootstrap: generate keypair, ensure dirs, verify session.",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Regenerate the keypair even if one already exists.",
    )
    p_init.add_argument(
        "--install-service",
        action="store_true",
        help=(
            "Also install the host service unit (systemd user unit on Linux, "
            "launchd LaunchAgent on macOS) without starting it."
        ),
    )

    # start
    p_start = sub.add_parser(
        "start",
        help="Install + enable + start the host service unit.",
    )
    p_start.add_argument(
        "--dry-run",
        action="store_true",
        help="Render the unit file and print the service commands without touching the filesystem.",
    )
    p_start.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive consent prompt (CI / package-manager use).",
    )
    p_start.add_argument(
        "--reinstall",
        action="store_true",
        help=(
            "Reinstall a previously-uninstalled artefact, bypassing the "
            "deletion-permanence tombstone."
        ),
    )

    # stop
    sub.add_parser("stop", help="Disable + stop the host service unit.")

    # status
    sub.add_parser("status", help="Report daemon state and local connectivity.")

    # daemon (foreground)
    sub.add_parser("daemon", help="Run the supervisor in the foreground.")

    # query
    p_query = sub.add_parser("query", help="Query the current materialised view.")
    p_query.add_argument(
        "field",
        nargs="?",
        choices=["handle", "attunement", "warmth", "income", "trust_tier", "all"],
        default="all",
    )

    # ingest
    p_ingest = sub.add_parser("ingest", help="Manually ingest a signal (for testing).")
    p_ingest.add_argument("--kind", required=True, help="Signal kind (e.g. tool_invocation).")
    p_ingest.add_argument(
        "--payload",
        default="{}",
        help="JSON-encoded payload for the signal.",
    )
    p_ingest.add_argument("--producer", default="cli:manual", help="Producer identifier.")

    # send
    p_send = sub.add_parser(
        "send",
        help="Send a member-to-member message via the running daemon.",
    )
    p_send.add_argument("to", help="Recipient ~handle (e.g. ~peer).")
    p_send.add_argument("body", help="Message body, markdown, <= 8 KiB.")
    p_send.add_argument(
        "--content-type",
        dest="content_type",
        default=None,
        help="Message content_type (default: text/markdown).",
    )

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Bootstrap the daemon environment."""
    ensure_directories()
    logger.info("config dir: %s", config_dir())
    logger.info("cache dir: %s", cache_dir())
    logger.info("unix socket: %s", unix_socket_path())

    # Keypair
    kp_path = keypair_path()
    if kp_path.exists() and not args.force:
        logger.info("keypair already exists at %s (use --force to regenerate)", kp_path)
    else:
        _generate_keypair(kp_path)
        logger.info("keypair generated at %s", kp_path)

    # Session check
    session = load_session()
    if session is None:
        print(
            "\nNo CLI session found. Run `alter login` to authenticate,\n"
            "then re-run `alter-runtime init` to complete bootstrap.",
            file=sys.stderr,
        )
        return 1

    print(f"\nReady. handle={session.handle} consent_tier=L{session.consent_tier}")

    if args.install_service:
        try:
            result = install_service(enable=False, dry_run=False)
        except (FileNotFoundError, NotImplementedError) as exc:
            print(f"service install skipped: {exc}", file=sys.stderr)
        else:
            print(f"service unit written to {result.unit_path} (not started)")

    print("Next: `alter-runtime start` to launch the host service.")
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    """Install + enable + start the host service unit."""
    import importlib.metadata

    from alter_runtime.consent import (
        ConsentDeclined,
        UserDeletedArtefact,
        enumerate_artefacts,
        print_consent_screen,
        prompt_consent,
        remove_tombstone,
        write_manifest_entry,
    )

    platform = current_platform()
    if platform not in ("linux", "darwin"):
        print(
            f"alter-runtime start is not yet supported on platform={platform!r}. "
            "Run `alter-runtime daemon` in the foreground for debugging.",
            file=sys.stderr,
        )
        return 1

    # C1 - consent gate. Enumerate artefacts, render the consent screen, and
    # wait for explicit confirmation before touching the filesystem.
    # Skipped on --dry-run (no writes happen) and bypassed by --yes.
    if not args.dry_run:
        artefacts = enumerate_artefacts()
        print_consent_screen(artefacts, uninstall_cmd="alter-runtime stop")
        try:
            prompt_consent(yes=args.yes)
        except ConsentDeclined:
            print("Install cancelled.")
            return 1
    else:
        artefacts = enumerate_artefacts()

    try:
        result = install_service(
            enable=True,
            dry_run=args.dry_run,
            reinstall=getattr(args, "reinstall", False),
        )
    except UserDeletedArtefact as exc:
        print(
            f"  {exc.args[0]} was previously deleted by the user.\n"
            "  ~alter will not recreate it automatically.\n"
            "  To reinstall, run: alter-runtime start --reinstall",
            file=sys.stderr,
        )
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except NotImplementedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("--- rendered unit ---")
        print(result.rendered)
        print("--- service commands ---")
        for cmd in result.service_commands:
            print(" ".join(cmd))
        return 0

    # C2 - post-install manifest. Write a manifest entry for every artefact
    # that was successfully installed.
    try:
        version = importlib.metadata.version("alter-runtime")
    except importlib.metadata.PackageNotFoundError:
        version = "unknown"

    for artefact in artefacts:
        try:
            write_manifest_entry(artefact, version=version)
        except OSError as exc:
            # Manifest write failure is non-fatal - the install succeeded.
            print(f"  warning: could not write manifest entry: {exc}", file=sys.stderr)

    # C3 - if --reinstall was passed and succeeded, clear the tombstone so
    # subsequent starts don't need --reinstall again.
    if getattr(args, "reinstall", False):
        for artefact in artefacts:
            try:
                remove_tombstone(artefact["path"])
            except OSError:
                pass

    print(f"installed {result.unit_path}")
    for cmd, exit_code in result.command_results:
        tag = "ok" if exit_code == 0 else f"exit={exit_code}"
        print(f"  {' '.join(cmd)}  [{tag}]")
    # Non-zero exit for any service command is non-fatal - the unit file
    # was still written, so re-running `alter-runtime start` or enabling
    # the unit manually will pick up where we left off.
    return 0


def cmd_stop(_args: argparse.Namespace) -> int:
    """Disable + stop the host service unit."""
    from alter_runtime.consent import _sha256_file, write_tombstone
    from alter_runtime.service_install import (
        launchd_plist_install_path,
        systemd_unit_install_path,
    )

    platform = current_platform()
    if platform not in ("linux", "darwin"):
        print(
            f"alter-runtime stop is not yet supported on platform={platform!r}.",
            file=sys.stderr,
        )
        return 1

    # C3 - tombstone the unit file before uninstalling so that a subsequent
    # `alter-runtime start` does not silently recreate it.
    if platform == "linux":
        unit_path = systemd_unit_install_path()
    else:
        unit_path = launchd_plist_install_path()

    if unit_path.exists():
        sha = _sha256_file(unit_path)
        try:
            write_tombstone(unit_path, sha256_at_deletion=sha, source="user_explicit")
        except OSError as exc:
            print(f"  warning: could not write tombstone: {exc}", file=sys.stderr)

    try:
        results = uninstall_service()
    except NotImplementedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for cmd, exit_code in results:
        tag = "ok" if exit_code == 0 else f"exit={exit_code}"
        print(f"  {' '.join(cmd)}  [{tag}]")
    print("service unit removed")
    return 0


#: How stale the daemon's auth-health file may be before status stops
#: reporting it as current. The daemon rewrites on every state transition and
#: at most every few seconds while authenticated traffic flows, so a file this
#: old means the daemon stopped writing, which is itself worth saying.
AUTH_HEALTH_STALE_AFTER_SECONDS: float = 900.0


def _auth_health_lines() -> list[str]:
    """Render the daemon's own view of whether its session is being accepted.

    The session block above reports what is on DISK. This block reports what
    the backend actually did with it, which is the only thing that answers
    whether the session is alive. They can disagree: a credential can sit on
    disk looking healthy while every authenticated request it makes is
    refused, and that disagreement is precisely the failure this reports.
    """
    from alter_runtime.auth_health import auth_health_path, read_auth_health

    path = auth_health_path()
    lines = [f"auth health:     {path}"]

    health = read_auth_health(path)
    if health is None:
        # Absence is not health. Say what is unknown and why, and never let a
        # missing file read as a passing check.
        lines.append("  state:         unknown (no report from the daemon)")
        lines.append("                 the daemon has not written one; is it running?")
        return lines

    state = str(health.get("state", "unknown"))
    updated_at = str(health.get("updated_at", "?"))
    lines.append(f"  state:         {state}")
    lines.append(f"  reported:      {updated_at}")

    age = _iso_age_seconds(updated_at)
    if age is not None and age > AUTH_HEALTH_STALE_AFTER_SECONDS:
        lines.append(
            f"                 stale by {int(age // 60)}m; the daemon has stopped reporting"
        )

    components = health.get("components")
    if isinstance(components, dict):
        for name, entry in components.items():
            if not isinstance(entry, dict):
                continue
            fails = entry.get("consecutive_failures", 0)
            marker = "failing" if entry.get("failing") else "ok"
            lines.append(f"    {name}: {marker} (consecutive failures: {fails})")

    remedy = str(health.get("remedy") or "").strip()
    if remedy:
        lines.append("  what to do:")
        for chunk in textwrap.wrap(remedy, width=64, break_on_hyphens=False):
            lines.append(f"                 {chunk}")
    return lines


def _iso_age_seconds(value: str) -> float | None:
    """Seconds since an ISO-8601 ``Z`` timestamp, or ``None`` if unparseable."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        return None
    return (datetime.now(timezone.utc) - parsed).total_seconds()


def cmd_status(_args: argparse.Namespace) -> int:
    """Report daemon state - does the socket exist? Is the session valid?"""
    lines: list[str] = []

    socket = unix_socket_path()
    lines.append(f"unix socket:     {socket}")
    if socket.exists():
        lines.append("  state:         present")
    else:
        lines.append("  state:         absent (daemon not running or socket path mismatched)")

    kp = keypair_path()
    lines.append(f"keypair:         {kp}")
    lines.append(f"  state:         {'present' if kp.exists() else 'absent'}")

    session = load_session()
    if session is None:
        lines.append("session:         none (run `alter login`)")
    else:
        lines.append(f"session:         handle={session.handle} tier=L{session.consent_tier}")
        lines.append(f"  api:           {session.api}")
        lines.append(f"  expires:       {session.jwt_expires_at}")

    lines.extend(_auth_health_lines())

    config = load_config()
    lines.append(f"config:          {config_dir() / 'runtime.yaml'}")
    lines.append(f"  do_sse:        {config.do_sse_endpoint}")
    lines.append(f"  mcp_fallback:  {config.mcp_fallback_endpoint}")
    lines.append(f"  log_level:     {config.log_level}")

    svc = service_status()
    lines.append(f"service unit:    {svc.unit_path}")
    lines.append(f"  platform:      {svc.platform}")
    lines.append(f"  installed:     {svc.installed}")
    lines.append(f"  active:        {svc.active} ({svc.status_line})")

    print("\n".join(lines))
    return 0


def cmd_daemon(_args: argparse.Namespace) -> int:
    """Run the supervisor in the foreground."""
    try:
        asyncio.run(run_daemon())
    except KeyboardInterrupt:
        logger.info("interrupted")
        return 130
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    """Query the local cache / daemon socket for current field state.

    Currently reads only the local identity cache file at
    ~/.cache/alter/identity.json. A future release adds a live
    socket query path.
    """
    cache_file = cache_dir() / "identity.json"
    if not cache_file.exists():
        print("no cached identity state - run `alter-runtime daemon`")
        return 1

    try:
        data = json.loads(cache_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"failed to read cache: {exc}", file=sys.stderr)
        return 1

    field = args.field
    if field == "all":
        print(json.dumps(data, indent=2))
        return 0

    alias = {
        "handle": "handle",
        "attunement": "attunement",
        "warmth": "level",
        "income": "income",
        "trust_tier": "trust_tier",
    }
    key = alias.get(field, field)
    value = data.get(key)
    if value is None:
        print(f"field '{field}' not present in local cache")
        return 1
    print(value)
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Manually ingest a signal.

    Currently validates the payload shape and prints what would be sent.
    A future release wires the actual socket send and server ingest path.
    """
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        print(f"invalid --payload JSON: {exc}", file=sys.stderr)
        return 1

    session = load_session()
    if session is None:
        print("no session - run `alter login`", file=sys.stderr)
        return 1

    envelope = {
        "v": "alter1",
        "handle": session.handle,
        "kind": args.kind,
        "payload": payload,
        "producer": args.producer,
        "consent_tier": session.consent_tier,
    }

    print("Would ingest:")
    print(json.dumps(envelope, indent=2))
    print("\n(Not yet wired: send path via unix socket to daemon to server.)")
    return 0


def _daemon_token() -> str | None:
    """Read the daemon auth token written beside the socket, or None."""
    token_file = unix_socket_path().parent / "alter-daemon-token"
    try:
        return token_file.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


async def _socket_request(request: dict[str, object]) -> dict[str, object]:
    """Connect to the daemon socket, authenticate, send one request, return the reply.

    Mirrors the same auth handshake the local MCP bridge performs: read the
    daemon token file, present it via ``{"method":"auth",...}``, then send the
    request line and read one JSON reply line.
    """
    socket = unix_socket_path()
    reader, writer = await asyncio.open_unix_connection(str(socket))
    try:
        token = _daemon_token()
        if token:
            writer.write((json.dumps({"method": "auth", "token": token}) + "\n").encode("utf-8"))
            await writer.drain()
            auth_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            auth_resp = json.loads(auth_line or b"{}")
            if not auth_resp.get("ok"):
                return {"ok": False, "error": f"auth failed: {auth_resp.get('error', 'unknown')}"}
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        # A send does a backend Durable-Object round-trip that can exceed a
        # minute; wait above the daemon's own send timeout so the CLI does not
        # give up before the daemon answers.
        line = await asyncio.wait_for(reader.readline(), timeout=90.0)
        if not line:
            return {"ok": False, "error": "no response from daemon"}
        reply = json.loads(line)
        if not isinstance(reply, dict):
            return {"ok": False, "error": "malformed reply from daemon"}
        return reply
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def cmd_send(args: argparse.Namespace) -> int:
    """Send a member-to-member message via the running daemon.

    The daemon performs the authenticated send (it holds the session bearer
    and signing key); this verb is a thin socket client. Default-closed: the
    recipient must have granted you messaging permission first.
    """
    socket = unix_socket_path()
    if not socket.exists():
        print(
            "daemon socket absent - is alter-runtime running? (`alter-runtime status`)",
            file=sys.stderr,
        )
        return 1
    request: dict[str, object] = {"method": "send", "to": args.to, "body": args.body}
    if args.content_type:
        request["content_type"] = args.content_type
    try:
        reply = asyncio.run(_socket_request(request))
    except (OSError, ConnectionError) as exc:
        print(f"failed to reach daemon socket: {exc}", file=sys.stderr)
        return 1
    if reply.get("ok"):
        mid = reply.get("message_id") or reply.get("id") or ""
        print(f"sent to {args.to}" + (f" (message {mid})" if mid else ""))
        return 0
    print(f"send failed: {reply.get('error', 'unknown error')}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------


COMMANDS: dict[str, object] = {
    "init": cmd_init,
    "start": cmd_start,
    "stop": cmd_stop,
    "status": cmd_status,
    "daemon": cmd_daemon,
    "query": cmd_query,
    "ingest": cmd_ingest,
    "send": cmd_send,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help(sys.stderr)
        return 2
    return handler(args)  # type: ignore[operator]


# ---------------------------------------------------------------------------
# Keypair generation (stub - writes a placeholder; a future release wires
# real Ed25519 generation via `cryptography` package)
# ---------------------------------------------------------------------------


def _generate_keypair(path: Path) -> None:
    """Generate a placeholder keypair file.

    Writes a JSON scaffold without actually generating an Ed25519 key.
    A future release will use `cryptography` to generate a real keypair
    and bind it to the device passkey root.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    placeholder = {
        "version": 1,
        "algorithm": "ed25519",
        "generated_at": None,
        "public_key_b64": None,
        "private_key_b64": None,
        "_notice": (
            "Scaffold only - real keypair generation is not yet wired. "
            "A future release adds cryptography package support and device passkey binding."
        ),
    }
    # Create the file with 0o600 from the outset. A write_text()-then-chmod()
    # sequence leaves a brief window in which the keypair file exists
    # world-readable (the chmod TOCTOU); a concurrent local process can open
    # it before the mode is tightened. Opening with the restrictive mode
    # closes that window. Matches the atomic-secure-write pattern in
    # consent.py / subscribers/inbox_writer.py. The mode is advisory on
    # filesystems without POSIX permissions (e.g. NTFS); harmless there.
    payload = json.dumps(placeholder, indent=2).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with contextlib.suppress(OSError, AttributeError):
            os.fchmod(fd, 0o600)
        os.write(fd, payload)
    finally:
        os.close(fd)


if __name__ == "__main__":
    raise SystemExit(main())
