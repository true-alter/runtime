"""Host service unit templates for alter-runtime.

Contains the platform-specific unit files that make the daemon a long-lived
system service:

* ``systemd/alter-runtime.service.in`` - template for a systemd *user* unit
  installed to ``~/.config/systemd/user/alter-runtime.service``. User units
  are preferred over system units because the daemon holds a user-scoped
  JWT and writes into ``$XDG_RUNTIME_DIR`` / ``$XDG_DATA_HOME`` - both of
  which live under the user's account.
* ``launchd/com.alter.runtime.plist.in`` - template for a launchd
  *LaunchAgent* installed to ``~/Library/LaunchAgents/com.alter.runtime.plist``
  on macOS. Agents run at per-user login (as opposed to daemons which run
  at boot and need elevated privileges).
* ``windows/`` - reserved for the Windows Service wrapper (not yet implemented).

The unit files are templates because the installed binary path is not
known until install time: ``pip install alter-runtime`` drops the entry
point at whatever ``scripts`` directory the active Python environment uses
(``~/.local/bin``, ``$VIRTUAL_ENV/bin``, ``/usr/local/bin``, …), and a
fixed ``ExecStart`` path would only work for one of those. The install
helper in :mod:`alter_runtime.service_install` resolves the current
binary via ``shutil.which`` and renders the template before writing.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "SERVICES_DIR",
    "launchd_template_path",
    "systemd_template_path",
]

SERVICES_DIR: Path = Path(__file__).parent


def systemd_template_path() -> Path:
    """Return the absolute path of the bundled systemd unit template."""
    return SERVICES_DIR / "systemd" / "alter-runtime.service.in"


def launchd_template_path() -> Path:
    """Return the absolute path of the bundled launchd plist template."""
    return SERVICES_DIR / "launchd" / "com.alter.runtime.plist.in"
