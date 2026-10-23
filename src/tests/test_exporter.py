import json
import os
import stat

import pytest

from unsealer import __version__
from unsealer.common.exporter import DataExporter


def test_failed_export_preserves_previous_file(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("previous backup", encoding="utf-8")
    with pytest.raises(TypeError):
        DataExporter().export({"accounts": [{"invalid": object()}]}, output, "json")
    assert output.read_text(encoding="utf-8") == "previous backup"
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits do not describe Windows ACLs")
@pytest.mark.parametrize("fmt", ["json", "md", "txt", "csv"])
def test_exports_are_private_even_with_permissive_umask(tmp_path, fmt):
    old_mask = os.umask(0)
    try:
        actual = DataExporter().export({"accounts": [{"title": "test"}]}, tmp_path / f"report.{fmt}", fmt)
    finally:
        os.umask(old_mask)
    output = actual / "accounts.csv" if fmt == "csv" else actual
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_json_export_uses_package_version(tmp_path):
    output = tmp_path / "report.json"
    DataExporter().export({"accounts": [{"title": "test"}]}, output, "json")
    assert json.loads(output.read_text(encoding="utf-8"))["metadata"]["version"] == __version__


def test_markdown_does_not_create_links_or_html_from_credentials(tmp_path):
    output = tmp_path / "report.md"
    DataExporter().export({"accounts": [{"title": "<script>", "note": "[link](https://example.com)"}]}, output, "md")
    content = output.read_text(encoding="utf-8")
    assert "<script>" not in content
    assert "[link](https://example.com)" not in content
    assert "\\[link\\]" in content
