"""Shared exports with atomic writes and explicit output destinations."""

import csv
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from unsealer import __version__


@contextmanager
def _open_output(path: Path, encoding="utf-8", newline=None):
    """Do not truncate a previous backup if serialization or writing fails."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".unsealer-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding=encoding, newline=newline) as stream:
            yield stream
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class DataExporter:
    def __init__(self, banner: str = ""):
        self.banner = banner.strip() if banner else ""
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def destination(output_path: Path, fmt: str) -> Path:
        path = Path(output_path)
        if fmt.lower() == "csv" and path.suffix:
            return path.parent / f"{path.stem}_export"
        return path

    def export(self, data: Dict[str, List[Dict]], output_path: Path, fmt: str) -> Path:
        fmt = fmt.lower()
        writers = {"json": self._to_json, "csv": self._to_csv,
                   "md": self._to_markdown, "txt": self._to_text}
        if fmt not in writers:
            raise ValueError(f"Unsupported export format: {fmt}")
        if not data or not any(data.values()):
            raise ValueError("No records to export")
        destination = self.destination(output_path, fmt)
        writers[fmt](data, destination)
        return destination

    def _to_json(self, data: Dict, path: Path):
        payload = {**data, "metadata": {"generated_at": self.timestamp, "version": __version__}}
        with _open_output(path) as stream:
            json.dump(payload, stream, indent=4, ensure_ascii=False)

    def _to_csv(self, data: Dict, path: Path):
        if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name) for name in data):
            raise ValueError("Invalid table name for CSV export")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for table_name, rows in data.items():
            if not rows:
                continue
            headers = sorted(set().union(*(row.keys() for row in rows)))
            with _open_output(path / f"{table_name}.csv", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

    @staticmethod
    def _markdown_text(value):
        text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return re.sub(r"([\\\x60*_{}\[\]()#+.!|~>-])", r"\\\1", text).replace("\n", "  \n")

    def _to_markdown(self, data: Dict, path: Path):
        lines = [f"~~~\n{self.banner}\n~~~\n" if self.banner else "# Unsealer Decryption Report"]
        lines.append(f"> **Export Time**: {self.timestamp}\n")
        for table_name, rows in data.items():
            lines.append(f"\n## {self._markdown_text(table_name.upper())} ({len(rows)} items)")
            for index, entry in enumerate(rows, 1):
                lines.append(f"\n### {index}. {self._markdown_text(self._get_title(entry))}")
                for key, value in entry.items():
                    if value is None or value == "" or key == "title":
                        continue
                    label = self._markdown_text(key.replace("_", " ").title())
                    lines.append(f"- **{label}**: {self._markdown_text(value)}")
                lines.append("\n---")
        with _open_output(path) as stream:
            stream.write("\n".join(lines))

    def _to_text(self, data: Dict, path: Path):
        lines = [self.banner or "UNSEALER REPORT", f"Export Time: {self.timestamp}\n" + "=" * 40]
        for table_name, rows in data.items():
            lines.append(f"\n[{table_name.upper()}]")
            for entry in rows:
                lines.append("-" * 30)
                for key, value in entry.items():
                    lines.append(f"{key.replace('_', ' ').title():<18}: {value}")
        with _open_output(path) as stream:
            stream.write("\n".join(lines))

    def _get_title(self, entry: Dict) -> str:
        for key in ["title", "name", "issuer", "note_title", "full_name", "bank_name", "account"]:
            if entry.get(key):
                return str(entry[key])
        return "Unnamed Record"
