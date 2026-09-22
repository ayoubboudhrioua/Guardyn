import pytest
from tools.package_release import publication_files


def test_release_rejects_tracked_environment_file(tmp_path, monkeypatch):
    (tmp_path / '.env').write_text('not-a-real-secret')
    monkeypatch.setattr('tools.package_release.subprocess.check_output', lambda *a, **k: b'.env\0')
    with pytest.raises(ValueError, match='Environment file'):
        publication_files(tmp_path)


def test_release_includes_new_source_and_skips_deleted_file(tmp_path, monkeypatch):
    source = tmp_path / 'new.py'
    source.write_text('pass\n')
    monkeypatch.setattr('tools.package_release.subprocess.check_output', lambda *a, **k: b'new.py\0old.py\0new.py\0')
    assert publication_files(tmp_path) == [source]
