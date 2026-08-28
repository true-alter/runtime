"""Install / enable / disable host service units for alter-runtime.

Handles three platforms:

* **Linux** via systemd *user* units. We install to
  ``~/.config/systemd/user/alter-runtime.service``, run
  ``systemctl --user daemon-reload`` + ``systemctl --user enable --now``,
  and tear down symmetrically on uninstall. User units avoid needing
  sudo and match the per-user security model (JWT, XDG paths, etc.).
* **macOS** via launchd *LaunchAgents*. We install to
  ``~/Library/LaunchAgents/com.alter.runtime.plist``, bootstrap into
  the current GUI session with ``launchctl bootstrap``, and log to
  ``~/Library/Logs/alter-runtime/``.
* **Windows** - not yet supported. A ``pywin32``-based Windows Service wrapper
  is planned for a future release.

The module exposes a small, testable surface:

* :func:`render_systemd_unit` / :func:`render_launchd_plist` - pure string
  templating (read the template, substitute placeholders, return the
  rendered body). No filesystem writes, so tests can assert on the output.
* :func:`install` / :func:`uninstall` - platform-dispatching wrappers
  that call into the concrete implementations.
* :func:`service_status` - reports whether the unit is installed /
  loaded / running. Used by ``alter-runtime status``.

All writes are idempotent; re-running ``install`` overwrites the existing
unit file with a freshly rendered copy so operators can pick up template
changes by re-running a single command.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from alter_runtime.services import (
    launchd_template_path,
    systemd_template_path,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "ServiceStatus",
    "current_platform",
    "install",
    "launchd_plist_install_path",
    "render_launchd_plist",
    "render_systemd_unit",
    "resolve_runtime_binary",
    "service_status",
    "systemd_unit_install_path",
    "uninstall",
]

logger = logging.getLogger("alter_runtime.service_install")

SYSTEMD_UNIT_NAME: str = "alter-runtime.service"
LAUNCHD_LABEL: str = "com.alter.runtime"
LAUNCHD_PLIST_NAME: str = f"{LAUNCHD_LABEL}.plist"


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def current_platform() -> str:
    """Return one of ``"linux"``, ``"darwin"``, ``"windows"``, or ``"other"``.

    Kept as a public helper so the CLI can produce helpful error messages
    on unsupported platforms without duplicating the platform-check logic.
    """
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform == "win32":
        return "windows"
    return "other"


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------


def resolve_runtime_binary() -> Path:
    """Return the absolute path of the installed ``alter-runtime`` entry point.

    ``pip install alter-runtime`` drops a console script at whatever bin
    directory the active Python environment is using; we find it via
    ``shutil.which`` (which respects ``$PATH``) and fall back to
    ``sys.executable + ` -m alter_runtime.cli``` semantics as a last
    resort. Returning a ``Path`` (rather than a string) lets callers
    cleanly assert on filesystem checks.
    """
    from_path = shutil.which("alter-runtime")
    if from_path:
        return Path(from_path).resolve()

    # Fallback: try the same directory as the current Python interpreter.
    sibling = Path(sys.executable).parent / "alter-runtime"
    if sibling.exists():
        return sibling.resolve()

    raise FileNotFoundError(
        "alter-runtime entry point not found on PATH or next to the current "
        "Python interpreter. Install the package first with `pip install -e .` "
        "from the source checkout, or `pip install alter-runtime`."
    )


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


def _substitute(body: str, mapping: dict[str, str]) -> str:
    """Replace ``@KEY@`` placeholders in ``body`` using ``mapping``."""
    out = body
    for key, value in mapping.items():
        out = out.replace(f"@{key}@", value)
    return out


def render_systemd_unit(
    binary_path: Path | None = None,
    home: Path | None = None,
) -> str:
    """Render the systemd unit template with the current binary path.

    Parameters
    ----------
    binary_path:
        Override for the ``@ALTER_RUNTIME_BIN@`` placeholder. Defaults to
        :func:`resolve_runtime_binary`.
    home:
        Override for the ``@ALTER_RUNTIME_HOME@`` placeholder. Defaults to
        ``Path.home()``.
    """
    binary_path = binary_path or resolve_runtime_binary()
    home = home or Path.home()
    template = systemd_template_path().read_text(encoding="utf-8")
    return _substitute(
        template,
        {
            "ALTER_RUNTIME_BIN": str(binary_path),
            "ALTER_RUNTIME_HOME": str(home),
        },
    )


def render_launchd_plist(
    binary_path: Path | None = None,
    log_dir: Path | None = None,
    home: Path | None = None,
) -> str:
    """Render the launchd plist template with the current binary path."""
    binary_path = binary_path or resolve_runtime_binary()
    home = home or Path.home()
    log_dir = log_dir or (home / "Library" / "Logs" / "alter-runtime")
    template = launchd_template_path().read_text(encoding="utf-8")
    return _substitute(
        template,
        {
            "ALTER_RUNTIME_BIN": str(binary_path),
            "ALTER_RUNTIME_HOME": str(home),
            "ALTER_RUNTIME_LOG_DIR": str(log_dir),
        },
    )


# ---------------------------------------------------------------------------
# Install paths
# ---------------------------------------------------------------------------


def systemd_unit_install_path() -> Path:
    """Return the path where the systemd user unit should be written."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "systemd" / "user" / SYSTEMD_UNIT_NAME


def launchd_plist_install_path() -> Path:
    """Return the path where the launchd LaunchAgent plist should be written."""
    return Path.home() / "Library" / "LaunchAgents" / LAUNCHD_PLIST_NAME


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------


@dataclass
class InstallResult:
    """Outcome of an :func:`install` call - what was written + what ran."""

    platform: str
    unit_path: Path
    rendered: str
    service_commands: list[list[str]]
    command_results: list[tuple[list[str], int]]


def install(
    *,
    enable: bool = True,
    dry_run: bool = False,
    binary_path: Path | None = None,
    reinstall: bool = False,
) -> InstallResult:
    """Install the host service unit for the current platform.

    Parameters
    ----------
    enable:
        When ``True`` (the default), also run ``systemctl --user enable
        --now`` (Linux) or ``launchctl bootstrap`` (macOS) to start the
        daemon immediately. Set to ``False`` for a file-only install.
    dry_run:
        When ``True``, render + return the rendered unit body but do not
        touch the filesystem or invoke any service manager command. Used
        by the CLI to preview without side effects.
    binary_path:
        Override for the resolved ``alter-runtime`` binary - tests pass a
        fake path to check templating without requiring the script to be
        installed.
    reinstall:
        When ``True``, bypass the deletion-permanence tombstone check.
        Corresponds to the ``--reinstall`` CLI flag.
    """
    platform = current_platform()
    if platform == "linux":
        return _install_systemd(
            enable=enable, dry_run=dry_run, binary_path=binary_path, reinstall=reinstall
        )
    if platform == "darwin":
        return _install_launchd(
            enable=enable, dry_run=dry_run, binary_path=binary_path, reinstall=reinstall
        )
    if platform == "windows":
        raise NotImplementedError("Windows Service install is not yet supported.")
    raise NotImplementedError(f"unsupported platform: {sys.platform}")


def uninstall() -> list[tuple[list[str], int]]:
    """Disable + remove the host service unit for the current platform.

    Returns a list of ``(command, exit_code)`` tuples for every shell
    invocation the uninstaller ran (empty on platforms that only need a
    file delete).
    """
    platform = current_platform()
    if platform == "linux":
        return _uninstall_systemd()
    if platform == "darwin":
        return _uninstall_launchd()
    if platform == "windows":
        raise NotImplementedError("Windows Service uninstall is not yet supported.")
    raise NotImplementedError(f"unsupported platform: {sys.platform}")


# ---------------------------------------------------------------------------
# systemd (Linux)
# ---------------------------------------------------------------------------


def _install_systemd(
    *,
    enable: bool,
    dry_run: bool,
    binary_path: Path | None,
    reinstall: bool = False,
) -> InstallResult:
    unit_body = render_systemd_unit(binary_path=binary_path)
    unit_path = systemd_unit_install_path()

    commands: list[list[str]] = [
        ["systemctl", "--user", "daemon-reload"],
    ]
    if enable:
        commands.append(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT_NAME],
        )

    if dry_run:
        return InstallResult(
            platform="linux",
            unit_path=unit_path,
            rendered=unit_body,
            service_commands=commands,
            command_results=[],
        )

    # C3 - deletion-permanence guard. Refuse to recreate a unit file the
    # user previously removed unless --reinstall was passed explicitly.
    if not reinstall:
        from alter_runtime.consent import UserDeletedArtefact, is_tombstoned

        if is_tombstoned(unit_path):
            raise UserDeletedArtefact(unit_path)

    unit_path.parent.mkdir(parents=True, exist_ok=True)
    unit_path.write_text(unit_body, encoding="utf-8")
    try:
        unit_path.chmod(0o644)
    except OSError:
        pass
    logger.info("wrote systemd unit to %s", unit_path)

    results = _run_commands(commands)
    return InstallResult(
        platform="linux",
        unit_path=unit_path,
        rendered=unit_body,
        service_commands=commands,
        command_results=results,
    )


def _uninstall_systemd() -> list[tuple[list[str], int]]:
    results = _run_commands(
        [
            ["systemctl", "--user", "disable", "--now", SYSTEMD_UNIT_NAME],
            ["systemctl", "--user", "daemon-reload"],
        ]
    )
    unit_path = systemd_unit_install_path()
    if unit_path.exists():
        try:
            unit_path.unlink()
            logger.info("removed systemd unit %s", unit_path)
        except OSError as exc:
            logger.warning("could not delete %s: %s", unit_path, exc)
    return results


# ---------------------------------------------------------------------------
# launchd (macOS)
# ---------------------------------------------------------------------------


def _install_launchd(
    *,
    enable: bool,
    dry_run: bool,
    binary_path: Path | None,
    reinstall: bool = False,
) -> InstallResult:
    plist_body = render_launchd_plist(binary_path=binary_path)
    plist_path = launchd_plist_install_path()
    log_dir = Path.home() / "Library" / "Logs" / "alter-runtime"

    try:
        uid = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        uid = 0  # pragma: no cover - macOS always has getuid

    commands: list[list[str]] = []
    if enable:
        commands.append(
            ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
        )
        commands.append(
            ["launchctl", "kickstart", "-k", f"gui/{uid}/{LAUNCHD_LABEL}"],
        )

    if dry_run:
        return InstallResult(
            platform="darwin",
            unit_path=plist_path,
            rendered=plist_body,
            service_commands=commands,
            command_results=[],
        )

    # C3 - deletion-permanence guard (launchd).
    if not reinstall:
        from alter_runtime.consent import UserDeletedArtefact, is_tombstoned

        if is_tombstoned(plist_path):
            raise UserDeletedArtefact(plist_path)

    plist_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    plist_path.write_text(plist_body, encoding="utf-8")
    try:
        plist_path.chmod(0o644)
    except OSError:
        pass
    logger.info("wrote launchd plist to %s", plist_path)

    results = _run_commands(commands)
    return InstallResult(
        platform="darwin",
        unit_path=plist_path,
        rendered=plist_body,
        service_commands=commands,
        command_results=results,
    )


def _uninstall_launchd() -> list[tuple[list[str], int]]:
    try:
        uid = os.getuid()  # type: ignore[attr-defined]
    except AttributeError:
        uid = 0

    results = _run_commands(
        [
            ["launchctl", "bootout", f"gui/{uid}/{LAUNCHD_LABEL}"],
        ]
    )
    plist_path = launchd_plist_install_path()
    if plist_path.exists():
        try:
            plist_path.unlink()
            logger.info("removed launchd plist %s", plist_path)
        except OSError as exc:
            logger.warning("could not delete %s: %s", plist_path, exc)
    return results


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass
class ServiceStatus:
    """Snapshot of the host service's installation and running state."""

    platform: str
    installed: bool
    active: bool
    unit_path: Path
    status_line: str


def service_status() -> ServiceStatus:
    """Report whether the service unit is installed + running.

    The active-state probe is a best-effort ``systemctl is-active`` /
    ``launchctl print`` call - if the service manager itself is missing
    (e.g. headless container without systemd) we return
    ``active=False`` and a status line explaining why.
    """
    platform = current_platform()
    if platform == "linux":
        unit_path = systemd_unit_install_path()
        installed = unit_path.exists()
        active = False
        status_line = "not installed"
        if installed:
            exit_code, stdout = _capture(["systemctl", "--user", "is-active", SYSTEMD_UNIT_NAME])
            active = exit_code == 0 and stdout.strip() == "active"
            status_line = stdout.strip() or f"systemctl exit={exit_code}"
        return ServiceStatus(
            platform=platform,
            installed=installed,
            active=active,
            unit_path=unit_path,
            status_line=status_line,
        )

    if platform == "darwin":
        plist_path = launchd_plist_install_path()
        installed = plist_path.exists()
        active = False
        status_line = "not installed"
        if installed:
            try:
                uid = os.getuid()  # type: ignore[attr-defined]
            except AttributeError:
                uid = 0
            exit_code, stdout = _capture(["launchctl", "print", f"gui/{uid}/{LAUNCHD_LABEL}"])
            active = exit_code == 0 and "state = running" in stdout
            status_line = "running" if active else f"launchctl exit={exit_code}"
        return ServiceStatus(
            platform=platform,
            installed=installed,
            active=active,
            unit_path=plist_path,
            status_line=status_line,
        )

    return ServiceStatus(
        platform=platform,
        installed=False,
        active=False,
        unit_path=Path("/"),
        status_line=f"unsupported platform: {sys.platform}",
    )


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _run_commands(commands: Sequence[Sequence[str]]) -> list[tuple[list[str], int]]:
    """Run each command in order, collecting exit codes. Non-fatal on failure.

    We log warnings on non-zero exits rather than raising so that a missing
    ``systemctl`` (e.g. inside a non-systemd container) doesn't crash
    ``alter-runtime install`` - the file write still succeeds and the
    operator can enable the unit manually.
    """
    results: list[tuple[list[str], int]] = []
    for cmd in commands:
        cmd_list = list(cmd)
        try:
            completed = subprocess.run(  # noqa: S603 - trusted args
                cmd_list,
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            logger.warning("command not found: %s - skipping", cmd_list[0])
            results.append((cmd_list, 127))
            continue
        if completed.returncode != 0:
            logger.warning(
                "%s exited %d stderr=%r",
                " ".join(cmd_list),
                completed.returncode,
                completed.stderr.strip()[:256],
            )
        results.append((cmd_list, completed.returncode))
    return results


def _capture(cmd: Sequence[str]) -> tuple[int, str]:
    """Run ``cmd`` and return ``(exit_code, stdout)``.

    Missing binaries yield ``(127, "")`` so callers can treat them as
    "not installed" without branching on ``FileNotFoundError``.
    """
    try:
        completed = subprocess.run(  # noqa: S603
            list(cmd),
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return 127, ""
    return completed.returncode, completed.stdout
