"""Optional QR support; importing the CLI must not require a native ZBar library."""

from pathlib import Path
from typing import Set


def _load_decoder():
    try:
        from pyzbar.pyzbar import decode
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "QR scanning requires ZBar. Install libzbar0 on Linux or zbar with "
            "Homebrew on macOS; on Windows reinstall pyzbar and its native dependencies. "
            "Migration URI and JSON input do not require ZBar."
        ) from exc
    return decode


def extract_uris_from_path(path_str: str) -> Set[str]:
    path = Path(path_str)
    if not path.exists():
        return set()

    from PIL import Image, UnidentifiedImageError

    decode = _load_decoder()
    supported_extensions = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
    files = [path] if path.is_file() else sorted(path.iterdir())
    found_uris = set()
    for file in files:
        if not file.is_file() or file.suffix.lower() not in supported_extensions:
            continue
        try:
            with Image.open(file) as img:
                decoded_objects = decode(img.convert("L"))
        except (OSError, UnidentifiedImageError):
            continue
        for obj in decoded_objects:
            try:
                content = obj.data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if content.startswith("otpauth-migration://"):
                found_uris.add(content)
    return found_uris
