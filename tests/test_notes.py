from pathlib import Path

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
