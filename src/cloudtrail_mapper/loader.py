"""Read local CloudTrail log files.

Supports plain JSON (*.json) and gzip-compressed JSON (*.json.gz), which is
the format CloudTrail delivers to S3. Works only on local files; no AWS
access or credentials are used.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any, Iterable

from .normalize import deduplicate, normalize_records
from .schemas import LoadResult, ValidationIssue

SUPPORTED_SUFFIXES = (".json", ".json.gz")


def _error(path: Path, message: str) -> ValidationIssue:
    return ValidationIssue("error", message, source_file=str(path))


def read_records(path: str | Path) -> tuple[list[Any], list[ValidationIssue]]:
    """Read one file and return its raw "Records" list plus any file-level issues.

    Never raises for bad input: problems are returned as ValidationIssues.
    Records are returned untouched; validating them is normalize.py's job.
    """
    path = Path(path)

    if not path.is_file():
        return [], [_error(path, "file not found")]

    try:
        raw_bytes = path.read_bytes()
        if path.name.endswith(".gz"):
            raw_bytes = gzip.decompress(raw_bytes)
        # "utf-8-sig" also strips a byte-order mark that some editors add.
        text = raw_bytes.decode("utf-8-sig")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        return [], [_error(path, f"could not read file: {exc}")]

    if not text.strip():
        return [], [ValidationIssue("warning", "file is empty; no records loaded", str(path))]

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [_error(path, f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}")]

    if not isinstance(document, dict):
        return [], [_error(path, f"top level is a {type(document).__name__}, expected an object with a 'Records' array")]

    if "Records" not in document:
        return [], [_error(path, "no 'Records' key found; this does not look like a CloudTrail log file")]

    records = document["Records"]
    if not isinstance(records, list):
        return [], [_error(path, f"'Records' is a {type(records).__name__}, expected an array")]

    if not records:
        return [], [ValidationIssue("warning", "'Records' array is empty", str(path))]

    return records, []


def expand_paths(paths: Iterable[str | Path]) -> list[Path]:
    """Turn a mix of files and directories into a sorted list of files.

    Directories are searched (non-recursively) for *.json and *.json.gz files.
    """
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(
                sorted(f for f in p.iterdir() if f.is_file() and f.name.endswith(SUPPORTED_SUFFIXES))
            )
        else:
            files.append(p)  # missing files are reported later by read_records
    return files


def load_events(paths: str | Path | Iterable[str | Path]) -> LoadResult:
    """Full pipeline: read files -> normalize records -> remove duplicates.

    Accepts one path or a list of paths; each may be a file or a directory.
    Duplicate eventIDs are detected across ALL files, not just within one.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]

    result = LoadResult()
    all_events = []

    for path in expand_paths(paths):
        records, file_issues = read_records(path)
        result.issues.extend(file_issues)
        if path.is_file():
            result.files_read += 1
        result.records_seen += len(records)

        events, record_issues = normalize_records(records, source_file=str(path))
        result.issues.extend(record_issues)
        all_events.extend(events)

    result.events, duplicate_issues = deduplicate(all_events)
    result.issues.extend(duplicate_issues)
    return result
