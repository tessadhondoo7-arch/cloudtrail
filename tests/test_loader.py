"""Tests for loader.py: reading files safely."""

import gzip
import json

from cloudtrail_mapper.loader import expand_paths, load_events, read_records


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


VALID_RECORD = {
    "eventTime": "2026-01-15T10:00:00Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "ListBuckets",
    "eventID": "id-1",
}


# ---- valid input ----

def test_reads_valid_file(tmp_path):
    f = write_json(tmp_path / "ok.json", {"Records": [VALID_RECORD]})
    records, issues = read_records(f)
    assert records == [VALID_RECORD]
    assert issues == []


def test_reads_gzip_file(tmp_path):
    f = tmp_path / "ok.json.gz"
    f.write_bytes(gzip.compress(json.dumps({"Records": [VALID_RECORD]}).encode()))
    records, issues = read_records(f)
    assert len(records) == 1
    assert issues == []


def test_reads_file_with_utf8_bom(tmp_path):
    f = tmp_path / "bom.json"
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps({"Records": [VALID_RECORD]}).encode())
    records, issues = read_records(f)
    assert len(records) == 1
    assert issues == []


# ---- empty files ----

def test_empty_file_is_warning_not_crash(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text("", encoding="utf-8")
    records, issues = read_records(f)
    assert records == []
    assert len(issues) == 1
    assert issues[0].severity == "warning"
    assert "empty" in issues[0].message


def test_whitespace_only_file_is_treated_as_empty(tmp_path):
    f = tmp_path / "blank.json"
    f.write_text("   \n\n  ", encoding="utf-8")
    records, issues = read_records(f)
    assert records == []
    assert issues[0].severity == "warning"


def test_empty_records_array_is_warning(tmp_path):
    f = write_json(tmp_path / "none.json", {"Records": []})
    records, issues = read_records(f)
    assert records == []
    assert issues[0].severity == "warning"


# ---- malformed files ----

def test_missing_file_is_error(tmp_path):
    records, issues = read_records(tmp_path / "does_not_exist.json")
    assert records == []
    assert issues[0].severity == "error"
    assert "not found" in issues[0].message


def test_invalid_json_reports_location(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text('{"Records": [ {"a": 1}, ', encoding="utf-8")
    records, issues = read_records(f)
    assert records == []
    assert issues[0].severity == "error"
    assert "invalid JSON" in issues[0].message
    assert "line" in issues[0].message


def test_missing_records_key_is_error(tmp_path):
    f = write_json(tmp_path / "x.json", {"Events": []})
    records, issues = read_records(f)
    assert records == []
    assert "Records" in issues[0].message


def test_records_not_a_list_is_error(tmp_path):
    f = write_json(tmp_path / "x.json", {"Records": {"eventName": "oops"}})
    _, issues = read_records(f)
    assert issues[0].severity == "error"
    assert "expected an array" in issues[0].message


def test_top_level_list_is_error(tmp_path):
    f = write_json(tmp_path / "x.json", [VALID_RECORD])
    _, issues = read_records(f)
    assert issues[0].severity == "error"


def test_corrupt_gzip_is_error(tmp_path):
    f = tmp_path / "bad.json.gz"
    f.write_bytes(b"this is not gzip data")
    records, issues = read_records(f)
    assert records == []
    assert issues[0].severity == "error"


# ---- directories and the full pipeline ----

def test_expand_paths_finds_json_files_only(tmp_path):
    write_json(tmp_path / "b.json", {"Records": []})
    write_json(tmp_path / "a.json", {"Records": []})
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    files = expand_paths([tmp_path])
    assert [f.name for f in files] == ["a.json", "b.json"]


def test_one_bad_file_does_not_stop_others(tmp_path):
    write_json(tmp_path / "good.json", {"Records": [VALID_RECORD]})
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    result = load_events(tmp_path)
    assert result.files_read == 2
    assert len(result.events) == 1
    assert len(result.errors) == 1


def test_duplicates_detected_across_files(tmp_path):
    write_json(tmp_path / "one.json", {"Records": [VALID_RECORD]})
    write_json(tmp_path / "two.json", {"Records": [VALID_RECORD]})
    result = load_events(tmp_path)
    assert len(result.events) == 1
    assert len(result.warnings) == 1
    assert "duplicate" in result.warnings[0].message
