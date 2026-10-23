"""Exercise an installed package or frozen executable with synthetic data."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import qrcode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", type=Path)
    args = parser.parse_args()
    command = [str(args.executable.resolve())] if args.executable else [sys.executable, "-m", "unsealer"]
    uri = "otpauth-migration://offline?data=ChkKCHBhc3N3b3JkEgR1c2VyGgdzZXJ2aWNl"
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)

        def run(arguments, expected=0):
            result = subprocess.run(command + arguments, cwd=folder, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=60)
            if result.returncode != expected:
                raise RuntimeError(f"Smoke check failed ({result.returncode}): {result.stderr.decode(errors='replace')}")

        run(["--help"])
        run(["samsung", "--help"])
        run(["google", "--help"])
        run(["google", uri, "-o", "uri.json"])
        assert json.loads((folder / "uri.json").read_text(encoding="utf-8"))["google_authenticator"][0]["username"] == "user"
        run(["google", uri, "--preview", "-o", "preview.json"])
        assert not (folder / "preview.json").exists()
        run(["google", "otpauth-migration://offline?data=!!!!"], expected=1)
        run(["google"], expected=1)
        run(["google", "uri.json", "-o", "roundtrip.json"])
        assert json.loads((folder / "uri.json").read_text(encoding="utf-8"))["google_authenticator"] == json.loads((folder / "roundtrip.json").read_text(encoding="utf-8"))["google_authenticator"]
        image = folder / "synthetic-qr.png"
        qrcode.make(uri).save(image)
        run(["google", str(image), "-o", "qr.json"])
        assert json.loads((folder / "qr.json").read_text(encoding="utf-8"))["google_authenticator"][0]["username"] == "user"
    print("Installed CLI smoke checks passed, including real QR decoding.")


if __name__ == "__main__":
    main()
