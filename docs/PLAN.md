# Proofpacket v0.1 implementation plan

## User job and required demo

Record a local test as evidence, attach it to a completion claim, then modify a selected source and show the same evidence becoming stale. Include a second claim with no evidence and an explicit assumption. The demo must work without Git or a network.

## CLI

```sh
python -m proofpacket init --task fixtures/task.md --claims fixtures/claims.json --root fixtures/project --path sharing.py --path test_sharing.py --out packet.json
python -m proofpacket run packet.json --root fixtures/project --id check-guests -- python -m unittest test_sharing.py
python -m proofpacket link packet.json --claim guest-reshare --check check-guests
python -m proofpacket verify packet.json --root fixtures/project --out verification.json
python -m proofpacket report packet.json --root fixtures/project --out report.md
```

`init` selects existing regular files only, rejects duplicate relative paths, embeds the task text, and creates a packet. `run` executes argv directly (`shell=False`) in the supplied root, with `--timeout` default 60 seconds, no automatic retry. A failed command is successfully recorded: run returns 1, a passing command 0, malformed invocation/launch failure 2. A timeout is recorded with `status: timeout`, `exit_code: null`, and exit 1. Refuse duplicate check IDs. `link` validates both IDs and avoids duplicate links. `verify` returns 1 for stale/missing/changed-during-run evidence or failed/timed-out checks; an unlinked claim alone is reported but does not redefine check freshness. `report` writes its report and returns 0 when valid, even when concerns are present.

## Data format

`claims.json` is `{schema_version:1, claims:[{id,text,check_ids:[]}], assumptions:[{id,text}]}`. Initial check_ids must be empty. A packet embeds these fields plus `task`, `selected_paths`, and `checks`. IDs are nonempty unique strings in their collection.

A check has `{id, argv:[string], cwd:".", started_at, finished_at, status:"completed"|"timeout", exit_code:int|null, stdout, stderr, stdout_truncated:bool, stderr_truncated:bool, stdout_sha256, stderr_sha256, before:{path:sha256}, after:{path:sha256|null}}`. Output excerpts preserve the first 65536 decoded characters per stream; hashes are of the full captured raw bytes. Decode subprocess output with replacement so binary noise cannot destroy the evidence record. Explain that capture is for ordinary bounded test commands, not streaming unbounded output. Selected files must all be readable before execution; a missing file afterward becomes null. Validate references and field types before any execution or packet write. Write mutated packet JSON atomically using a temporary sibling plus replace.

Root is a runtime argument and not an absolute machine path stored in the portable packet. Source selection is explicit, includes no directories/globs, and must be nonempty. The initial file hashes can be stored for context but never stand in for the per-check snapshots. A check's evidence applies only to its selected files and recorded command, not to the entire repository or runtime environment.

## Core API

- `fingerprint_files(root: Path, paths: list[str]) -> dict[str, str]`
- `validate_packet(data: dict) -> None` raises a domain `ValidationError`.
- `capture_check(root: Path, paths: list[str], check_id: str, argv: list[str], timeout: float = 60) -> dict`
- `assess_packet(packet: dict, root: Path) -> dict`
- `render_report(packet: dict, assessment: dict) -> str`

Assessment contains each check's `execution` and `freshness` separately. Freshness is `current`, `stale`, `changed_during_run`, or `unavailable`. `changed_during_run` takes precedence over current/stale; any unreadable current source is unavailable and retains details. Compare current hashes to the check's `before`; before/after must also match to call evidence current. Check success is `completed` and exit 0. A claim reports `unlinked`, `has_current_passing_evidence`, or `needs_review` plus every linked check's state. Even the first status is labeled “author-linked evidence; semantic support not verified.”

## Invariants and useful report

Never run commands from packet JSON automatically. Only `run … -- argv` executes. Never silently refresh old evidence. Never fabricate a timestamp or return code for an unexecuted command. A launch failure leaves the existing packet untouched and explains the failure. The report shows task, selected file scope, claims with check references, assumptions, every command/exit/freshness state, changed paths, output excerpts with truncation markers, and the evidence limitation. Escape any Markdown table syntax or use fenced blocks safely.

## Acceptance tests and fixtures

1. Fixture `sharing.py` and `test_sharing.py` implement a small role check; a successful capture stores argv, output, real exit 0, and equal before/after hashes. Linking changes only the intended claim's references.
2. Alter `sharing.py` after capture: verify returns 1, names the changed path, and no longer gives that claim current evidence. Unrelated files outside selected scope do not affect freshness and the report discloses that scope.
3. Run a command that edits a selected file before exiting 0: evidence is `changed_during_run` immediately and remains unsuitable as current evidence.
4. Run a failing command and a short timed-out command: both records persist with distinguishable execution status; neither appears as passing evidence.
5. Remove a selected file after capture: verify reports unavailable without traceback. An unlinked fixture claim remains unlinked.
6. Reject duplicate IDs, broken links, empty argv, negative timeout, root escapes, and symlinks escaping root; packet bytes remain unchanged on failed mutation.
7. CLI smoke test creates, runs, links, verifies, and reports from a temporary fixture copy. Output excerpt truncation is labeled and full-byte hash remains correct.

## Failure modes, non-goals, milestone

Capture cannot prove a command was meaningful, prevent the command from modifying arbitrary files, or identify undeclared inputs. Running a command is an explicit trusted-user action. Whole-file hashing intentionally marks irrelevant edits stale; do not implement semantic hashes. No Git integration, signatures, CI ingestion, review UI, sandbox, auto-discovery, or agent log parsing in this milestone.

Build schema validation and freshness first; then direct subprocess capture and atomic mutation; then the report, fixtures, and end-to-end tests. Done means the README demonstrates a previously passing but now stale claim with exact evidence, in about five commands.
