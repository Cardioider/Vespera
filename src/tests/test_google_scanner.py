from types import SimpleNamespace
from pathlib import Path

import pytest
from PIL import Image

from unsealer.google import scanner


def test_extract_uris_from_path_filtering(mocker, tmp_path):
    Image.new("RGB", (10, 10), "white").save(tmp_path / "image.png")
    (tmp_path / "text.txt").write_text("not an image", encoding="utf-8")
    decoder = mocker.Mock(return_value=[
        SimpleNamespace(data=b"otpauth-migration://found_data"),
        SimpleNamespace(data=b"not-a-migration-uri"),
        SimpleNamespace(data=b"\xff"),
    ])
    mocker.patch.object(scanner, "_load_decoder", return_value=decoder)
    assert scanner.extract_uris_from_path(str(tmp_path)) == {"otpauth-migration://found_data"}
    assert decoder.call_count == 1


def test_extract_uris_corrupted_image(mocker, tmp_path):
    image = tmp_path / "bad.jpg"
    image.write_bytes(b"broken image")
    decoder = mocker.Mock()
    mocker.patch.object(scanner, "_load_decoder", return_value=decoder)
    assert scanner.extract_uris_from_path(str(image)) == set()
    decoder.assert_not_called()


def test_missing_zbar_reports_actionable_error(mocker, tmp_path):
    image = tmp_path / "image.png"
    Image.new("RGB", (10, 10)).save(image)
    mocker.patch.dict("sys.modules", {"pyzbar.pyzbar": None})
    with pytest.raises(RuntimeError, match="ZBar"):
        scanner.extract_uris_from_path(str(image))


def test_decoder_failure_is_not_silently_ignored(mocker, tmp_path):
    image = tmp_path / "image.png"
    Image.new("RGB", (10, 10)).save(image)
    mocker.patch.object(scanner, "_load_decoder", return_value=mocker.Mock(side_effect=RuntimeError("decoder failed")))
    with pytest.raises(RuntimeError, match="decoder failed"):
        scanner.extract_uris_from_path(str(image))


def test_macos_homebrew_library_outside_default_search_path(mocker):
    library = SimpleNamespace(find_library=lambda name: None)
    mocker.patch.object(scanner.sys, "frozen", False, create=True)
    mocker.patch.object(Path, "is_file", autospec=True,
                        side_effect=lambda path: path.as_posix() == "/opt/homebrew/opt/zbar/lib/libzbar.dylib")
    scanner._configure_macos_zbar(library)
    assert library.find_library("zbar") == str(Path("/opt/homebrew/opt/zbar/lib/libzbar.dylib"))
    assert library.find_library("unrelated-library") is None


def test_macos_prefers_bundled_zbar(mocker, tmp_path):
    bundled = tmp_path / "libzbar.dylib"
    bundled.touch()
    library = SimpleNamespace(find_library=lambda name: "/system/libzbar.dylib")
    mocker.patch.object(scanner.sys, "frozen", True, create=True)
    mocker.patch.object(scanner.sys, "_MEIPASS", str(tmp_path), create=True)
    scanner._configure_macos_zbar(library)
    assert library.find_library("zbar") == str(bundled)
