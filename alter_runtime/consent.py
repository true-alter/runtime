"""Install-consent gate, artefact manifest, and deletion-permanence guard.

Implements the following install-transparency countermeasures:

* Visible install-consent gate. Before any byte lands, the user
  sees which artefacts will be written, their sizes, SHA-256 digests, and
  sigstore verification status. They must confirm ``[Y/n]`` (or pass
  ``--yes``).
* Queryable post-install manifest. Every successfully installed
  artefact is recorded in ``install-manifest.json`` under the XDG data
  directory with path, SHA-256, sigstore URL, install timestamp, and
  version. The manifest is atomically written (tmp + rename) at mode
  0o600 and survives subsequent installs as a log.
* Deletion permanence. When the user removes a service unit via
  ``alter-runtime stop`` (or manually), a tombstone entry is written to
  ``deleted-tombstones.json``. Subsequent ``alter-runtime start`` calls
  check the tombstone table before writing the unit file; if the path is
  tombstoned, the install is refused with an actionable message. The user
  can explicitly clear the tombstone with ``--reinstall``.

~Alter does not use a silent-install pattern.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from alter_runtime.config import data_dir

__all__ = [
    "ConsentDeclined",
    "UserDeletedArtefact",
    "enumerate_artefacts",
    "is_tombstoned",
    "manifest_path",
    "manifest_version_for",
    "print_consent_screen",
    "prompt_consent",
    "remove_tombstone",
    "tombstone_path",
    "write_manifest_entry",
    "write_tombstone",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConsentDeclined(Exception):
    """User declined the install consent prompt."""


class UserDeletedArtefact(Exception):
    """Artefact was previously tombstoned by user; refuse silent reinstall."""


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file.  Returns empty string if the
    file does not exist (artefact not yet installed - pre-consent phase)."""
    if not path.exists():
        return ""
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Artefact enumeration
# ---------------------------------------------------------------------------


def enumerate_artefacts(
    binary_path: Path | None = None,
    *,
    binary_sigstore_bundle_url: str | None = None,
) -> list[dict[str, Any]]:
    """Return a list of artefacts that ``alter-runtime start`` will write.

    Each entry is a dict::

        {
            "path":               Path,
            "size_bytes":         int | None,  # None if not yet on disk
            "sha256":             str,          # empty str if not yet on disk
            "sigstore_bundle_url": str | None,
        }

    For v1 the set is:

    * The systemd user unit *or* launchd plist (platform-appropriate). This is
      a locally-rendered template, not a signed release artefact, so its
      ``sigstore_bundle_url`` is always ``None``.
    * The ``alter-runtime`` binary itself (resolved via
      :func:`~alter_runtime.service_install.resolve_runtime_binary`, with
      a graceful fallback to ``None`` if the binary is not yet installed).

    Parameters
    ----------
    binary_sigstore_bundle_url:
        The sigstore bundle URL for the runtime binary, read from the release
        manifest entry for the running platform. When supplied it is stamped
        onto the binary artefact so the consent screen and the post-install
        manifest record the signature provenance. ``None`` (the default) means
        no bundle is known for this install path, e.g. a local source build.
    """
    from alter_runtime.service_install import (
        current_platform,
        launchd_plist_install_path,
        systemd_unit_install_path,
    )

    artefacts: list[dict[str, Any]] = []

    # Unit file
    platform = current_platform()
    if platform == "linux":
        unit_path: Path = systemd_unit_install_path()
    elif platform == "darwin":
        unit_path = launchd_plist_install_path()
    else:
        unit_path = Path("/dev/null")  # Windows stub - not yet supported

    unit_size: int | None = unit_path.stat().st_size if unit_path.exists() else None
    artefacts.append(
        {
            "path": unit_path,
            "size_bytes": unit_size,
            "sha256": _sha256_file(unit_path),
            "sigstore_bundle_url": None,
        }
    )

    # Runtime binary
    resolved_binary: Path | None = binary_path
    if resolved_binary is None:
        try:
            from alter_runtime.service_install import resolve_runtime_binary

            resolved_binary = resolve_runtime_binary()
        except FileNotFoundError:
            resolved_binary = None

    if resolved_binary is not None:
        bin_size: int | None = resolved_binary.stat().st_size if resolved_binary.exists() else None
        artefacts.append(
            {
                "path": resolved_binary,
                "size_bytes": bin_size,
                "sha256": _sha256_file(resolved_binary),
                "sigstore_bundle_url": binary_sigstore_bundle_url,
            }
        )

    return artefacts


# ---------------------------------------------------------------------------
# Consent screen
# ---------------------------------------------------------------------------


def _human_size(size_bytes: int | None) -> str:
    """Format bytes as a human-readable string."""
    if size_bytes is None:
        return "?"
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KiB"
    return f"{size_bytes / (1024 * 1024):.1f} MiB"


def print_consent_screen(
    artefacts: list[dict[str, Any]],
    uninstall_cmd: str,
    *,
    verified: bool = False,
) -> None:
    """Render the pre-install consent screen to stdout.

    Format::

        ALTER Runtime - install consent
        ================================
        The following artefacts will be written to your system:
          /path/to/unit  (12.3 KiB)  sha256:abcd1234  sigstore: unverified
        ...
        Sigstore-keyless verification: UNVERIFIED
        To remove everything:  alter-runtime stop

    Parameters
    ----------
    verified:
        Whether an actual sigstore-verified verdict has been obtained for the
        release artefacts (e.g. from ``alter runtime verify`` / the
        verified-apply path). The headline status reads ``VERIFIED`` ONLY when
        this is ``True``; it is ``UNVERIFIED`` otherwise. A bundle URL being
        merely *present* on an artefact is no longer treated as proof of
        verification: an unverified install must never claim it passed.
    """
    print("ALTER Runtime - install consent")
    print("================================")
    print("The following artefacts will be written to your system:")

    for artefact in artefacts:
        path = artefact["path"]
        size_str = _human_size(artefact.get("size_bytes"))
        sha = artefact.get("sha256") or ""
        short_sha = sha[:12] if sha else "(not yet on disk)"
        bundle_url = artefact.get("sigstore_bundle_url")
        # Per-artefact label is driven by the verdict, not URL presence: a
        # bundle URL with no verified verdict is "pending", never "verified".
        if verified and bundle_url:
            sig_label = "verified"
        elif bundle_url:
            sig_label = "pending"
        else:
            sig_label = "unverified"
        print(f"  {path}  ({size_str})  sha256:{short_sha}  sigstore: {sig_label}")

    sig_status = "VERIFIED" if verified else "UNVERIFIED"
    print(f"Sigstore-keyless verification: {sig_status}")
    print(f"To remove everything:  {uninstall_cmd}")
    print()


# ---------------------------------------------------------------------------
# Consent prompt
# ---------------------------------------------------------------------------


def prompt_consent(yes: bool = False) -> bool:
    """Prompt the user to confirm installation.

    Parameters
    ----------
    yes:
        When ``True`` the prompt is skipped and the function returns
        immediately - intended for CI / package-manager post-install hooks
        that cannot be interactive.

    Returns
    -------
    bool
        Always ``True`` when the user confirms (or ``yes=True``).

    Raises
    ------
    ConsentDeclined
        When the user answers ``n`` / ``N``, when the process is not
        attached to a TTY and ``yes=False``, or on EOF / KeyboardInterrupt.
    """
    if yes:
        return True

    if not sys.stdin.isatty():
        raise ConsentDeclined(
            "stdin is not a TTY and --yes was not passed. "
            "Use `alter-runtime start --yes` for non-interactive installs."
        )

    try:
        answer = input("Proceed with install? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise ConsentDeclined("install cancelled by user")

    if answer in ("n", "no"):
        raise ConsentDeclined("install declined by user")

    # Any other input (empty = Enter, 'y', 'yes', or unrecognised) proceeds.
    return True


# ---------------------------------------------------------------------------
# Install manifest
# ---------------------------------------------------------------------------


def manifest_path() -> Path:
    """Resolve the install-manifest path under ``data_dir()``."""
    return data_dir() / "install-manifest.json"


def _read_manifest() -> dict[str, Any]:
    """Load the manifest or return an empty scaffold on missing/corrupt file."""
    path = manifest_path()
    if not path.exists():
        return {"schema_version": 1, "entries": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 1, "entries": {}}
    if not isinstance(raw, dict):
        return {"schema_version": 1, "entries": {}}
    if "entries" not in raw:
        raw["entries"] = {}
    return raw


def _atomic_json_write(path: Path, data: Any) -> None:
    """Write ``data`` as JSON to ``path`` atomically (tmp + rename) at mode 0o600."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o600)
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(tmp_path, path)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


def write_manifest_entry(artefact: dict[str, Any], version: str) -> None:
    """Append / upsert an entry in ``install-manifest.json``, keyed on path.

    The manifest schema::

        {
            "schema_version": 1,
            "entries": {
                "/absolute/path/to/unit": {
                    "path": "...",
                    "sha256": "...",
                    "sigstore_bundle_url": null,
                    "installed_at": "2026-05-07T00:00:00+00:00",
                    "version": "0.1.0"
                },
                ...
            }
        }

    Writes are atomic (tmp + rename) at mode 0o600.
    """
    manifest = _read_manifest()
    entries: dict[str, Any] = manifest.setdefault("entries", {})

    path_str = str(artefact["path"])
    entries[path_str] = {
        "path": path_str,
        "sha256": artefact.get("sha256") or "",
        "sigstore_bundle_url": artefact.get("sigstore_bundle_url"),
        "installed_at": datetime.now(tz=timezone.utc).isoformat(),
        "version": version,
    }
    manifest["entries"] = entries
    _atomic_json_write(manifest_path(), manifest)


def manifest_version_for(path: Path) -> str | None:
    """Return the recorded version for *path* in the manifest, or ``None``."""
    manifest = _read_manifest()
    entry = manifest.get("entries", {}).get(str(path))
    if entry is None:
        return None
    return entry.get("version")


# ---------------------------------------------------------------------------
# Tombstone store
# ---------------------------------------------------------------------------


def tombstone_path() -> Path:
    """Resolve the deleted-tombstones path under ``data_dir()``."""
    return data_dir() / "deleted-tombstones.json"


def _read_tombstones() -> dict[str, Any]:
    """Load tombstones or return an empty scaffold."""
    path = tombstone_path()
    if not path.exists():
        return {"schema_version": 1, "tombstones": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 1, "tombstones": {}}
    if not isinstance(raw, dict):
        return {"schema_version": 1, "tombstones": {}}
    if "tombstones" not in raw:
        raw["tombstones"] = {}
    return raw


def is_tombstoned(path: Path) -> bool:
    """Return ``True`` if *path* has a tombstone entry.

    Never raises - returns ``False`` on any read error (missing file, corrupt
    JSON, etc.) so the install path is not blocked by a bad tombstone file.
    """
    try:
        tombstones = _read_tombstones()
        return str(path) in tombstones.get("tombstones", {})
    except Exception:  # noqa: BLE001 - intentional broad catch for install safety
        return False


def write_tombstone(
    path: Path,
    sha256_at_deletion: str | None = None,
    source: str = "user_explicit",
) -> None:
    """Record a tombstone entry for *path*.

    Parameters
    ----------
    path:
        The artefact path that was deleted.
    sha256_at_deletion:
        The SHA-256 of the file at deletion time, if available.
    source:
        How the deletion happened - ``"user_explicit"`` (via
        ``alter-runtime stop``) or ``"user_manual"`` (detected out-of-band).
    """
    data = _read_tombstones()
    data["tombstones"][str(path)] = {
        "path": str(path),
        "sha256_at_deletion": sha256_at_deletion,
        "deleted_at": datetime.now(tz=timezone.utc).isoformat(),
        "source": source,
    }
    _atomic_json_write(tombstone_path(), data)


def remove_tombstone(path: Path) -> None:
    """Remove the tombstone entry for *path* (used by ``--reinstall`` flow)."""
    data = _read_tombstones()
    data["tombstones"].pop(str(path), None)
    _atomic_json_write(tombstone_path(), data)
