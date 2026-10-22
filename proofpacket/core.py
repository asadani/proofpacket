"""Core evidence capture and review logic for Proofpacket."""

from __future__ import annotations

import hashlib
import json
import math
import math
import os
import re
import signal
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


class ValidationError(ValueError):
    """An actionable error in a packet or command configuration."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative_path(value: Any) -> str:
    _need(isinstance(value, str) and bool(value), "path must be a non-empty string")
    _need("\\" not in value, f"path must use forward slashes: {value!r}")
    p = PurePosixPath(value)
    _need(not p.is_absolute() and ".." not in p.parts, f"path must stay relative to root: {value!r}")
    _need(value not in (".", ""), "path must name a file")
    _need(value == p.as_posix(), "path must use canonical relative spelling (no ./ or repeated slashes)")
    return value


def _resolve(root: Path, relative: str) -> Path:
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*PurePosixPath(_relative_path(relative)).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValidationError(f"cannot read selected file {relative!r}: {exc}") from exc
    _need(resolved == root_resolved or root_resolved in resolved.parents,
          f"path escapes root through a symlink: {relative!r}")
    _need(resolved.is_file(), f"selected path is not a regular file: {relative!r}")
    return resolved


def _read_hash(root: Path, relative: str) -> str:
    try:
        return _sha(_resolve(root, relative).read_bytes())
    except ValidationError:
        raise
    except OSError as exc:
        raise ValidationError(f"cannot read selected file {relative!r}: {exc}") from exc


def fingerprint_files(root: Path, paths: list[str]) -> dict[str, str]:
    """Hash the bytes of selected regular files, rejecting unsafe references."""
    _need(isinstance(paths, list) and bool(paths), "select at least one source path")
    result: dict[str, str] = {}
    for path in paths:
        rel = _relative_path(path)
        _need(rel not in result, f"duplicate selected path: {rel}")
        result[rel] = _read_hash(root, rel)
    return result


def _string(value: Any, label: str, allow_empty: bool = False) -> None:
    _need(isinstance(value, str), f"{label} must be a string")
    _need(allow_empty or bool(value.strip()), f"{label} must not be empty")


def _unique_ids(items: list[dict], label: str) -> set[str]:
    seen: set[str] = set()
    for i, item in enumerate(items):
        _string(item.get("id"), f"{label}[{i}].id")
        _need(item["id"] not in seen, f"duplicate {label} id: {item['id']!r}")
        seen.add(item["id"])
        _string(item.get("text"), f"{label}[{i}].text")
    return seen


def validate_packet(data: dict) -> None:
    """Validate packet shape, types, IDs, references, timestamps and hashes."""
    _need(isinstance(data, dict), "packet must be a JSON object")
    _need(data.get("schema_version") == 1 and _is_int(data.get("schema_version")),
          "schema_version must be integer 1")
    _string(data.get("task"), "task")
    paths = data.get("selected_paths")
    _need(isinstance(paths, list) and bool(paths), "selected_paths must be a non-empty array")
    path_names: set[str] = set()
    for i, item in enumerate(paths):
        _need(isinstance(item, dict), f"selected_paths[{i}] must be an object")
        rel = _relative_path(item.get("path"))
        _need(rel not in path_names, f"duplicate selected path: {rel}")
        path_names.add(rel)
        _need(isinstance(item.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
              f"selected_paths[{i}].sha256 must be a lowercase SHA-256 digest")
    claims, assumptions, checks = data.get("claims"), data.get("assumptions"), data.get("checks")
    _need(isinstance(claims, list), "claims must be an array")
    _need(isinstance(assumptions, list), "assumptions must be an array")
    _need(isinstance(checks, list), "checks must be an array")
    _need(all(isinstance(item, dict) for item in claims), "each claims entry must be an object")
    _need(all(isinstance(item, dict) for item in assumptions), "each assumptions entry must be an object")
    _need(all(isinstance(item, dict) for item in checks), "each checks entry must be an object")
    claim_ids = _unique_ids(claims, "claims")
    _unique_ids(assumptions, "assumptions")
    check_ids: set[str] = set()
    for i, check in enumerate(checks):
        _string(check.get("id"), f"checks[{i}].id")
        _need(check["id"] not in check_ids, f"duplicate checks id: {check['id']!r}")
        check_ids.add(check["id"])
    for i, claim in enumerate(claims):
        refs = claim.get("check_ids")
        _need(isinstance(refs, list), f"claims[{i}].check_ids must be an array")
        _need(all(isinstance(ref, str) for ref in refs), f"claims[{i}].check_ids must contain strings")
        _need(len(refs) == len(set(refs)), f"claims[{i}].check_ids contains duplicates")
        for ref in refs:
            _need(ref in check_ids, f"claim {claim['id']!r} references unknown check {ref!r}")
    for i, check in enumerate(checks):
        prefix = f"checks[{i}]"
        argv = check.get("argv")
        _need(isinstance(argv, list) and bool(argv), f"{prefix}.argv must be a non-empty array")
        _need(all(isinstance(a, str) for a in argv), f"{prefix}.argv must contain strings")
        _need(check.get("cwd") == ".", f"{prefix}.cwd must be '.'")
        _need(check.get("status") in ("completed", "timeout"), f"{prefix}.status is invalid")
        ec = check.get("exit_code")
        _need(ec is None or _is_int(ec), f"{prefix}.exit_code must be an integer or null")
        _need((check["status"] == "timeout") == (ec is None), f"{prefix}.status and exit_code disagree")
        for key in ("started_at", "finished_at"):
            _string(check.get(key), f"{prefix}.{key}")
            try:
                parsed = datetime.fromisoformat(check[key].replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValidationError(f"{prefix}.{key} must be an ISO 8601 timestamp") from exc
            _need(parsed.tzinfo is not None, f"{prefix}.{key} must include a timezone")
        for key in ("stdout", "stderr"):
            _string(check.get(key), f"{prefix}.{key}", allow_empty=True)
        for key in ("stdout_truncated", "stderr_truncated"):
            _need(isinstance(check.get(key), bool), f"{prefix}.{key} must be boolean")
        for key in ("stdout_sha256", "stderr_sha256"):
            _need(isinstance(check.get(key), str) and re.fullmatch(r"[0-9a-f]{64}", check[key]) is not None,
                  f"{prefix}.{key} must be a lowercase SHA-256 digest")
        for key in ("before", "after"):
            snapshots = check.get(key)
            _need(isinstance(snapshots, dict), f"{prefix}.{key} must be an object")
            _need(set(snapshots) == path_names, f"{prefix}.{key} must contain exactly the selected paths")
            for path, digest in snapshots.items():
                _need((digest is None or isinstance(digest, str)) if key == "after" else isinstance(digest, str),
                      f"{prefix}.{key}[{path!r}] has an invalid digest")
                if digest is not None:
                    _need(re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                          f"{prefix}.{key}[{path!r}] must be a lowercase SHA-256 digest")
        _need(isinstance(check.get("changed_during_run"), list) and all(isinstance(c, str) for c in check["changed_during_run"]),
              f"{prefix}.changed_during_run must contain strings")
        expected_changed = [p for p in check["before"] if check["before"][p] != check["after"][p]]
        _need(set(check["changed_during_run"]) == set(expected_changed),
              f"{prefix}.changed_during_run must agree with before/after snapshots")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def capture_check(root: Path, paths: list[str], check_id: str, argv: list[str], timeout: float = 60) -> dict:
    """Run a caller-supplied argv and record real output and source snapshots."""
    _string(check_id, "check id")
    _need(isinstance(argv, list) and bool(argv) and all(isinstance(a, str) for a in argv),
          "argv must be a non-empty array of strings")
    _need(isinstance(timeout, (float, int)) and not isinstance(timeout, bool) and math.isfinite(timeout) and timeout > 0,
          "timeout must be a positive number")
    before = fingerprint_files(root, paths)
    started = _now()
    try:
        proc = subprocess.Popen(argv, cwd=root.resolve(strict=True), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, shell=False, start_new_session=(os.name == "posix"))
    except (OSError, ValueError) as exc:
        raise ValidationError(f"could not launch command: {exc}") from exc
    status, exit_code = "completed", 0
    try:
        out, err = proc.communicate(timeout=float(timeout))
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        status, exit_code = "timeout", None
        if os.name == "posix":
            # Ordinary child processes inherit this session; close their output pipes too.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        out, err = proc.communicate()
    finished = _now()
    after: dict[str, str | None] = {}
    for path in paths:
        try:
            after[path] = _read_hash(root, path)
        except ValidationError:
            after[path] = None
    changed = [p for p in paths if before[p] != after[p]]
    limit = 65536
    out_text = out.decode("utf-8", errors="replace")
    err_text = err.decode("utf-8", errors="replace")
    return {
        "id": check_id, "argv": list(argv), "cwd": ".", "started_at": started,
        "finished_at": finished, "status": status, "exit_code": exit_code,
        "stdout": out_text[:limit],
        "stderr": err_text[:limit],
        "stdout_truncated": len(out_text) > limit, "stderr_truncated": len(err_text) > limit,
        "stdout_sha256": _sha(out), "stderr_sha256": _sha(err),
        "before": before, "after": after, "changed_during_run": changed,
    }


def assess_packet(packet: dict, root: Path) -> dict:
    validate_packet(packet)
    results = []
    by_id: dict[str, dict] = {}
    for check in packet["checks"]:
        unavailable: list[str] = []
        current: dict[str, str] = {}
        for path in packet["selected_paths"]:
            rel = path["path"]
            try:
                current[rel] = _read_hash(root, rel)
            except ValidationError:
                unavailable.append(rel)
        if unavailable:
            freshness = "unavailable"
        elif check.get("changed_during_run", []) or any(check["before"][p] != check["after"][p] for p in check["before"]):
            freshness = "changed_during_run"
        elif any(current[p] != check["before"][p] for p in current):
            freshness = "stale"
        else:
            freshness = "current"
        passing = check["status"] == "completed" and check["exit_code"] == 0
        result = {"id": check["id"], "execution": "passed" if passing else check["status"] if check["status"] == "timeout" else "failed",
                  "freshness": freshness, "changed_paths": [p for p in current if current[p] != check["before"][p]],
                  "unavailable_paths": unavailable, "passing": passing}
        results.append(result)
        by_id[check["id"]] = result
    claim_results = []
    for claim in packet["claims"]:
        states = [by_id[ref] for ref in claim["check_ids"]]
        if not states:
            state = "unlinked"
        elif any(s["passing"] and s["freshness"] == "current" for s in states):
            state = "has_current_passing_evidence"
        else:
            state = "needs_review"
        claim_results.append({"id": claim["id"], "status": state,
                              "checks": [{"id": s["id"], "execution": s["execution"], "freshness": s["freshness"]} for s in states]})
    adverse = any(r["execution"] != "passed" or r["freshness"] != "current" for r in results)
    return {"checks": results, "claims": claim_results, "adverse": adverse}


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def _code_fence(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text or '(empty)'}\n{fence}"


def render_report(packet: dict, assessment: dict) -> str:
    validate_packet(packet)
    claims = {c["id"]: c for c in packet["claims"]}
    checks = {c["id"]: c for c in packet["checks"]}
    assessed_checks = {c["id"]: c for c in assessment["checks"]}
    assessed_claims = {c["id"]: c for c in assessment["claims"]}
    out = ["# Proofpacket review", "", "## Task", "", packet["task"], "", "## Evidence scope", "",
           "Selected files are the complete freshness scope for these checks:", ""]
    out.extend(f"- `{p['path']}` — initial SHA-256 `{p['sha256']}`" for p in packet["selected_paths"])
    out += ["", "Changes outside this selected file set do not affect freshness and are not covered.", "", "## Claims", ""]
    for claim in packet["claims"]:
        result = assessed_claims[claim["id"]]
        refs = ", ".join(f"`{r}` ({assessed_checks[r]['execution']}, {assessed_checks[r]['freshness']})" for r in claim["check_ids"]) or "none"
        out += [f"### {claim['id']} — {result['status']}", "", claim["text"], "", f"Linked checks: {refs}.",
                "Author-linked evidence; semantic support is not verified.", ""]
    if packet["assumptions"]:
        out += ["## Assumptions", ""]
        out.extend(f"- **{a['id']}** — {a['text']}" for a in packet["assumptions"])
        out.append("")
    out += ["## Recorded checks", ""]
    for check in packet["checks"]:
        result = assessed_checks[check["id"]]
        command = json.dumps(check["argv"], ensure_ascii=False)
        out += [f"### {check['id']} — {result['execution']}; freshness: {result['freshness']}", "",
                "Command argv:", "", _code_fence(command), "",
                f"Exit: {check['exit_code'] if check['exit_code'] is not None else 'timeout (no exit code)'}; started {check['started_at']}; finished {check['finished_at']}.", ""]
        if result["changed_paths"]:
            out.append("Changed selected paths: " + ", ".join(f"`{p}`" for p in result["changed_paths"]) + ".")
        if result["unavailable_paths"]:
            out.append("Unavailable selected paths: " + ", ".join(f"`{p}`" for p in result["unavailable_paths"]) + ".")
        if check["changed_during_run"]:
            out.append("Changed while the command ran: " + ", ".join(f"`{p}`" for p in check["changed_during_run"]) + ".")
        for stream in ("stdout", "stderr"):
            excerpt = check[stream]
            if check[stream + "_truncated"]:
                excerpt += "\n[excerpt truncated after 65,536 decoded characters]"
            out += [f"{stream.upper()} (full-byte SHA-256 `{check[stream + '_sha256']}`):", "", _code_fence(excerpt), ""]
    out += ["## Limitations", "", "A passing command does not prove that a claim is true. Claim links are author assertions. Whole-file hashes intentionally mark any selected-file edit stale. The packet does not capture undeclared inputs, environment changes, dependencies, or changes outside the selected scope. Commands are run as the current user and are not sandboxed. Output excerpts are capped at 65,536 decoded characters per stream; hashes cover all captured bytes. Capture is intended for ordinary bounded test commands, not unbounded streaming output.", ""]
    return "\n".join(out)


def atomic_write(path: Path, content: bytes) -> None:
    """Replace a file atomically after its complete replacement is ready."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def packet_bytes(packet: dict) -> bytes:
    validate_packet(packet)
    return (json.dumps(packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
