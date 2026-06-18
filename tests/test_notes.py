from pathlib import Path
from datetime import datetime, timezone

from recon.notes import create_evidence_note


def test_create_evidence_note_sanitizes_path_traversal_title(monkeypatch, tmp_path):
    evidence_dir = tmp_path / "evidence"
    monkeypatch.setattr("recon.notes.EVIDENCE_DIR", evidence_dir)

    result = create_evidence_note({"title": "../../outside", "summary": "Safe note"})

    assert result["ok"] is True
    path = Path(result["path"]).resolve()
    assert path.parent == evidence_dir.resolve()
    assert ".." not in path.name
    assert path.suffix == ".md"


def test_create_evidence_note_rejects_symlinked_evidence_dir(monkeypatch, tmp_path):
    evidence_dir = tmp_path / "evidence"
    monkeypatch.setattr("recon.notes.EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(type(evidence_dir), "is_symlink", lambda self: self == evidence_dir)

    result = create_evidence_note({"title": "Symlinked evidence"})

    assert result["ok"] is False
    assert "symlink" in result["error"].lower()


def test_evidence_note_unique_filenames_for_similar_titles(monkeypatch, tmp_path):
    class FixedDatetime:
        @staticmethod
        def now(tz=None):
            return datetime(2026, 6, 17, 12, 0, 0, tzinfo=timezone.utc)

    evidence_dir = tmp_path / "evidence"
    title = "A" * 100
    monkeypatch.setattr("recon.notes.EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr("recon.notes.datetime", FixedDatetime)

    first = create_evidence_note({"title": title})
    second = create_evidence_note({"title": title})

    assert first["ok"] is True
    assert second["ok"] is True
    assert first["path"] != second["path"]
    assert Path(first["path"]).exists()
    assert Path(second["path"]).exists()
