<p align="center"><img src="assets/logo.svg" alt="Proofpacket" width="310"></p>

Proofpacket records which local command ran against a selected set of files, what it returned, and whether those files still match the versions observed around the run. It gives reviewers inspectable evidence for a completion claim; it does not judge whether the claim is true.

## Quickstart

Requires Python 3.11 or newer. The package uses only the standard library. Run these commands from this repository root. They copy the fixture into a temporary workspace so the demo can edit a selected source without changing the shipped fixture.

```sh
demo_dir="$(mktemp -d)"
cp -R fixtures/project "$demo_dir/project"
python -m proofpacket init --task fixtures/task.md --claims fixtures/claims.json --root "$demo_dir/project" --path sharing.py --path test_sharing.py --out "$demo_dir/packet.json"
python -m proofpacket run "$demo_dir/packet.json" --root "$demo_dir/project" --id check-guests -- python -m unittest test_sharing.py
python -m proofpacket link "$demo_dir/packet.json" --claim guest-reshare --check check-guests
python -m proofpacket verify "$demo_dir/packet.json" --root "$demo_dir/project" --out "$demo_dir/verification.json"
python -m proofpacket report "$demo_dir/packet.json" --root "$demo_dir/project" --out "$demo_dir/report.md"
```

The unit command exits `0`; its recorded result is a completed check with exit code `0` and equal before/after hashes. The claim `guest-reshare` is linked to that check. `all-paths` stays unlinked. The report says the claim has current passing evidence and explicitly notes that semantic support is not verified.

Now edit one selected file and verify again:

```sh
python -c 'from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_text(p.read_text() + "\\n# policy changed after check\\n")' "$demo_dir/project/sharing.py"
python -m proofpacket verify "$demo_dir/packet.json" --root "$demo_dir/project" --out "$demo_dir/verification-after-edit.json"
```

The second `verify` exits `1` and writes its complete result. Its relevant output is:

```json
{
  "checks": [
    {
      "changed_paths": ["sharing.py"],
      "execution": "passed",
      "freshness": "stale",
      "id": "check-guests",
      "passing": true,
      "unavailable_paths": []
    }
  ],
  "claims": [
    {"checks": [{"execution": "passed", "freshness": "stale", "id": "check-guests"}], "id": "guest-reshare", "status": "needs_review"},
    {"checks": [], "id": "all-paths", "status": "unlinked"}
  ],
  "adverse": true
}
```

IDs and hashes are stable for identical inputs; observation timestamps are real UTC times and therefore vary. The report shows the selected scope, every command and outcome, output excerpts, changed or unavailable paths, linked claims, assumptions, and the limits of the evidence.

## Use it in a review

Choose a small explicit set of source files that the check depends on, then create a claims file. Claim text and relevance links are supplied by the author. A check that exits nonzero or times out remains useful recorded evidence, but it cannot count as passing evidence. After a selected file changes, the old result remains in the packet and becomes stale; Proofpacket never refreshes it silently. Add a new check with a new ID to capture a later run.

The `init` input uses this shape:

```json
{
  "schema_version": 1,
  "claims": [{"id": "guest-reshare", "text": "Guests cannot reshare.", "check_ids": []}],
  "assumptions": [{"id": "guest-role", "text": "guest means an external collaborator."}]
}
```

See [the packet schema](docs/packet.schema.json) and [the fixture claims](fixtures/claims.json). The executable validator checks required fields and types, unique IDs, references, selected path scope, timestamp/hash formats, and consistency between command status and exit code. It also rejects root escapes through symlinks. Unknown object keys are accepted and are never treated as commands. The JSON Schema documents the packet shape; runtime validation additionally checks cross-references and root-relative path safety.

## Commands and exit codes

| Command | Purpose | Exit |
| --- | --- | --- |
| `init --task FILE --claims FILE --root DIR --path REL --out FILE` | Build a packet and initial selected-file fingerprints. Repeat `--path`; all selected files must exist as regular files. | `0` success, `2` invalid input or I/O failure |
| `run PACKET --root DIR --id ID [--timeout SECONDS] -- ARGV...` | Run exactly the supplied argv with `shell=False`, capture both streams, and atomically append the observation. Default timeout is 60 seconds. | `0` command passed; `1` command failed or timed out; `2` invalid input or launch failure |
| `link PACKET --claim ID --check ID` | Add one author-supplied claim-to-check link. | `0` success, `2` invalid or duplicate link |
| `verify PACKET --root DIR --out FILE` | Write machine-readable execution, freshness, claim, and adverse status. | `0` no failed/stale check; `1` any failed, timed-out, stale, changed-during-run, or unavailable check; `2` invalid input or I/O failure |
| `report PACKET --root DIR --out FILE` | Write a reviewable Markdown report, including adverse states. | `0` report written, `2` invalid input or I/O failure |

Expected input errors go to stderr without a traceback. JSON is written only to the requested file. `--help` and `--version` are available.

## Evidence and boundaries

Proofpacket hashes original file bytes with SHA-256. For each check it snapshots every selected file immediately before and after command execution. A selected file changed during execution gets `changed_during_run`, which takes precedence over current and stale outcomes. At review time, missing or unreadable selected files are `unavailable`; differing current bytes are `stale`; otherwise evidence is `current`. A current check counts as passing only when it completed with exit code `0`.

Paths are relative to the runtime `--root` (current directory by default), and symlinks resolving outside that root are rejected. The root itself is not stored in the portable packet. Commands run as the current user and are not sandboxed. On POSIX, a timeout terminates the command’s process group; on other platforms it terminates the direct process. Descendants that deliberately detach are outside this capture tool’s control. Only an explicit `run ... -- command args...` executes a process; packet JSON never triggers execution.

**Limitations:** a passing command does not prove a behavioral claim. Claim links are author assertions. Whole-file hashing intentionally marks unrelated edits within selected files stale. The selected list cannot reveal undeclared inputs, runtime environment or dependency changes, or edits outside its scope. Output excerpts preserve the first 65,536 decoded characters per stream, with replacement for malformed UTF-8; SHA-256 covers the full captured bytes. Subprocess output is collected in memory, so capture is intended for ordinary bounded tests, not unbounded streaming output. There is no Git integration, sandbox, CI import, signature, automatic test discovery, or semantic analysis.

## Development

```sh
python -m unittest discover -s tests -v
```

The package has no runtime dependencies. Core API entry points are `fingerprint_files`, `validate_packet`, `capture_check`, `assess_packet`, and `render_report` in `proofpacket.core`.

## Data integrity

Report and initialization outputs refuse to overwrite their input artifacts or selected source files. Packet changes happen only through the explicit initialization, run, and link operations.

See [verification coverage](docs/VERIFICATION.md) and [the design plan](docs/PLAN.md) for tested behavior and remaining limits.
