# Changelog

All notable changes to alter-runtime are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.13] - 2026-08-15

### Fixed

- The Durable Object SSE subscriber spun instead of waiting when a stream closed
  cleanly. Every other way that connection can end, an HTTP error or a transport
  fault, ran the disconnect handler and then backed off before trying again. A
  clean end-of-stream ran the disconnect handler and went straight back to
  reconnecting, with no delay at all. The result is a loop that reconnects as
  fast as the machine allows and never yields, so the process stops doing
  anything else it was asked to do while burning a core. Anyone running 0.4.12
  is exposed to this the moment their stream closes cleanly, which is an
  ordinary thing for a stream to do.
- The comment above that branch already said the intent was to disconnect and
  back off. The backoff call was simply absent beneath it, which is why reading
  the code did not catch it and why it survived from the commit that wired the
  subscriber into the refresh path.
- The test suite hung on this rather than failing, because a busy loop starves
  the event loop instead of raising, so it presented as an environment problem
  rather than a defect. The continuous-integration matrix had excluded a Python
  version on that theory. The exclusion is removed, because the hang reproduces
  identically on newer interpreters, so it was never about the version, and the
  suite now completes in seconds.

### Added

- This changelog now ships inside the source distribution. It was never in the
  sdist's allow-list, so anyone installing from PyPI received the package with
  no record of what had changed between versions, and the release gate that
  scans the shipped documentation had nothing to scan. Both are fixed by the
  same line. The allow-list stays strict and nothing else was added to it.

### Note

- 0.4.11 was tagged and never reached PyPI. The publish gate refused it for the
  missing changelog described above, so the version was skipped rather than
  published in a half-gated state. Everything 0.4.11 carried is in this release.

## [0.4.11] - 2026-08-10

### Added

- Development code removed at 0.4.7 was restored to the repository outside the
  packaged tree. The wheel packages only `alter_runtime` and the sdist uses a
  strict allow-list, so none of it reaches a published artefact, confirmed
  against a real build rather than the packaging configuration alone. Nothing
  in this release's contents changes as a result.

- `alter-runtime status` now reports whether the daemon's session is actually being accepted, not merely whether a session exists on disk. The two can disagree. A credential can sit on disk looking healthy while every authenticated request it makes is refused, and until now that disagreement was visible only in the journal, so a daemon failing continuously looked exactly like a daemon working. The daemon records the outcome of every authenticated request it already makes and writes the result to `$XDG_STATE_HOME/alter/auth-health.json`, which `status` reads back with the remedy for the state it is in. A session that is being refused everywhere reports as dead and points at `alter login`. Requests failing on one path while another still succeeds reports as degraded and says plainly that it is a fault to report rather than a login to redo. No report at all reports as unknown, never as healthy.

### Fixed

- A rejected member JWT on the session-claims publisher now actually requests a session refresh. The call omitted a required argument, so it raised inside a suppressor and the refresh was never requested; the publisher then backed off against a token nothing was rotating. The covering test passed throughout because its stand-in for the refresh trigger declared a different signature from the real one, so it now exercises the real trigger instead.
- The doctrine projection now reconciles its checkpoint against the JSONL that checkpoint describes, instead of trusting it on its own. The checkpoint is a cursor over the server, so a projection file truncated or deleted underneath the poller stayed empty indefinitely. The cursor still carried the server's newest row, so the etag gate reported nothing new and the `since` delta asked only for rows newer than the cursor, and neither path could rebuild what was lost. The checkpoint now also records how many rows it projected. A file holding strictly fewer forces a full re-pull rather than a delta. A legacy checkpoint written before that count existed falls back to the server's row count for one bootstrap re-pull only, because the append-only JSONL retains superseded rows that the server's current-entry count excludes.
- The doctrine projection no longer advances its checkpoint when a list drain stops at the page cap, which previously moved the cursor past rows it had never fetched.

### Changed

- The call that requests a session-ingest capability is now named for what it does, across the seven modules that carried the old shorthand. The error class it raises is `_CapabilityRequestError`. The old name was jargon that read as an operation rather than as a description, and it surfaced in error strings a user could actually see. No behaviour changes with it, and the endpoint path is untouched, since a client has to name the URL it requests.

## [0.4.10] - 2026-07-12

### Fixed

- Raised the systemd unit `TasksMax` default from 64 to 512 so the daemon does not exhaust its task budget and crash-loop under higher subscriber and background-worker counts. Applied consistently across the CLI-installed unit, the deb/rpm package unit, and the nix module.

## [0.4.9] - 2026-07-01

### Added

- `send` command and matching `send` socket method: deliver a member-to-member message through the running daemon (`alter-runtime send ~handle "body"`). The daemon performs the authenticated send over the same signed member-tool path it already uses for its read-only polls, so no new credential or scope is introduced. Default-closed: the recipient must have granted the sender permission first. Delivery is plain member-to-member, so a recipient's app surfaces it as a normal message.

## [0.4.8] - 2026-06-18

### Added

- Entry-point discovery seam for out-of-tree adapters: adapters published as a separate installed package register under the `alter_runtime.adapters` entry-point group and are discovered at start-up. The daemon imports no out-of-tree adapter by name; an adapter the host has not installed is simply absent. Dormant until such a package is installed.

### Changed

- Inline comments and docstrings across the notifier tier, the update loop,
  the session-presence cache, and the packaging extras were reworded for
  clarity and hygiene. No behaviour, configuration key, public identifier, or
  dependency changed; `ORG_ALTER_STATE_DIR` and every other environment
  override continues to work exactly as before.

## [0.4.7] - 2026-06-18

### Changed

- Inline code comments were tidied for clarity and hygiene, with no change to
  behaviour, the authentication flow, or any functional identifier. Package
  version metadata stays aligned across `pyproject.toml` and
  `alter_runtime/__init__.py`.

### Removed

- Thirty-nine files of development code were deleted from the package. They had
  landed for 0.3.0 and shipped inside every wheel and sdist from 0.3.0 through
  0.3.3, because they sat within the packaged `alter_runtime` tree. This entry
  is written retroactively. The release recorded only the comment tidy above, so
  a reader of this file had no way to learn that anything had left. The deletion
  itself was right, since the code was reaching published artefacts, but it was
  carried out by removal rather than relocation and against a separation design
  that had not yet been reviewed.

## [0.4.6] - 2026-06-18

### Changed

- Documentation and inline comments were tidied for clarity, with no change to
  the authentication flow or any other behaviour. The daemon continues to
  authenticate every request with your member bearer token. Package version
  metadata stays aligned across `pyproject.toml` and `alter_runtime/__init__.py`.

## [0.4.0] - 2026-06-14

### Added

- Inbound messages now raise a desktop notification on arrival. The daemon renders a freedesktop toast (`notify-send` plus the system message chime) the instant a message addressed to your handle lands, the same arrival cue every other messaging surface gives you. Default on; set `ALTER_DESKTOP_NOTIFIER_DISABLED=1` to suppress it. One-way render only: no read receipt, presence beacon, or typing indicator is sent back.
- The daemon now signs its MCP tool calls. Each authenticated call is signed with your handle's signing key, resolved from the environment, a per-handle key file, then the legacy key, and degrades quietly to unsigned with a warning when no key is present rather than failing the caller.
- A self-contained binary build. The packaging step produces a standalone `alter-runtime` binary, alongside a build driver and a multi-OS/arch release matrix. Linux x64 is built and verified; linux arm64, macOS x64/arm64, and windows x64 build on native runners.

## [0.3.0] - 2026-06-08

### Added

- The active-sessions publisher now batches: it sends up to 100 session envelopes per tick in a single request instead of one request per record, cutting request volume. On a server without the batch route it falls back to the per-record path; on an over-limit or malformed batch it falls back rather than retrying the identical body forever.

### Fixed

- Headless hosts can now read the session after the encrypted-store cutover. A build could fall back to only the legacy plaintext session file and return no session on headless hosts. The session resolution order is keyring, then encrypted file, then legacy file.
- The active-sessions publisher no longer replays the entire session log on every tick after a log rotation. The read cursor now seeds from the correct base after a rotation, and a detected shrink persists the reset position immediately.

## [0.2.0] - 2026-05-18

### Added

- A daemon-side auto-update observer polls the public release manifest on cadence, compares the advertised version against the running daemon, and logs what it sees. Scope is strictly observation: no download, no signature verification, no automatic replace. Channel selection matches the CLI surface so a stable-channel install never resolves a beta-only release. Operators can disable the poll for air-gapped fleets.

### Fixed

- The git watcher no longer schedules a task per `.git/HEAD` read. Modern watchdog versions emit open and close events on every read of a watched file, which `git status` callers trigger thousands of times per second; the dispatch handler now drops those read events before scheduling anything, ending an unbounded-memory growth path.
- The SSE reconnect watchdog now exceeds the server keepalive interval, ending a tight reconnect cycle where the watchdog fired before any keepalive arrived.

### Security

- Frame-signature enforcement is now default-on. Operators who genuinely need migration-mode pass-through must opt out explicitly. The subscriber refuses to construct when enforcement is on without a pinned public key, so misconfigurations fail loudly at startup rather than accepting unsigned frames silently.
- The frame-signature public-key shape gate was tightened so a key shorter than a valid 32-byte Ed25519 key is rejected at construct time.
- The ingest kind whitelist is now enforced on the D-Bus path as well as the Unix-socket path, closing a gap where a same-session-bus peer could publish arbitrary kinds onto the bus.
- The Unix-socket parent directory is enforced owner-only (`0o700`) and user-owned, and binding the socket directly under `/tmp` is refused.
- The git watcher refuses symlinked `.git` directories and sanitises branch names against a conservative shape gate before publishing.

## [0.1.0] - 2026-05

### Added

- First public release of the alter-runtime daemon and the `AlterClient` SDK: subscribers, the Unix socket, the D-Bus interface, the git watcher, systemd and launchd service units, and the eBPF subscriber (kernel attestation runs through a separate optional component).
