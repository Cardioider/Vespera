"""Google Authenticator imports from migration URIs, JSON, and QR images."""

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from unsealer.common.exporter import DataExporter
from unsealer.common.models import Credential
from .decrypter import decrypt_google_auth_uri
from .scanner import extract_uris_from_path

console = Console(stderr=True)


def _load_json(path):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    entries = data.get("google_authenticator") if isinstance(data, dict) else data
    if not isinstance(entries, list) or not entries:
        raise ValueError("JSON must contain a non-empty account list or google_authenticator list")
    credentials = []
    fields = set(Credential.__dataclass_fields__) - {"extra"}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each JSON account must be an object")
        extra = entry.get("extra")
        if extra is None:
            extra = {}
        if not isinstance(extra, dict):
            raise ValueError("Account extra must be an object")
        base = {key: value for key, value in entry.items() if key in fields}
        if any(not isinstance(value, str) for value in base.values()):
            raise ValueError("Account fields must be strings")
        if not base.get("secret"):
            raise ValueError("Account secret is required")
        base.setdefault("title", base.get("issuer") or base.get("username") or "Google Authenticator")
        base.setdefault("category", str(entry.get("original_type", extra.get("original_type", "TOTP"))).lower())
        extra = {**extra, **{key: value for key, value in entry.items() if key not in fields and key != "extra"}}
        credentials.append(Credential(**base, extra=extra))
    return credentials


def main(argv=None):
    parser = argparse.ArgumentParser(description="Recover Google Authenticator accounts from local inputs.")
    parser.add_argument("inputs", nargs="*", help="Migration URIs, JSON files, QR images, or image directories")
    parser.add_argument("-o", "--output", type=Path, help="Output .md, .csv, .txt, or .json path")
    parser.add_argument("--preview", action="store_true", help="Show account labels without writing any files")
    args = parser.parse_args(sys.argv[2:] if argv is None else argv)
    fmt = args.output.suffix[1:].lower() if args.output and args.output.suffix else "md"
    if args.output and not args.preview and fmt not in {"md", "csv", "json", "txt"}:
        parser.error("Output extension must be .md, .csv, .json, or .txt")

    all_credentials = []
    source_files = set()
    failed = False

    def ingest(item):
        nonlocal failed
        item = item.strip().strip("'\"")
        if not item:
            failed = True
            console.print("Empty input.", style="red")
            return
        try:
            if item.startswith("otpauth-migration://"):
                credentials = decrypt_google_auth_uri(item)
            else:
                path = Path(item)
                if not path.exists():
                    raise ValueError("Input path does not exist")
                if path.is_file():
                    source_files.add(path.resolve())
                if path.is_file() and path.suffix.lower() == ".json":
                    credentials = _load_json(path)
                else:
                    uris = extract_uris_from_path(str(path))
                    if not uris:
                        raise ValueError("No migration QR codes found in the input")
                    credentials = []
                    for uri in sorted(uris):
                        credentials.extend(decrypt_google_auth_uri(uri))
            if not credentials:
                raise ValueError("Input contains no accounts")
            all_credentials.extend(credentials)
        except (ValueError, OSError, RuntimeError) as exc:
            failed = True
            console.print(Text(f"Import failed: {exc}", style="red"))

    if args.inputs:
        for item in args.inputs:
            ingest(item)
    elif sys.stdin.isatty():
        console.print("Paste a migration URI or a local path. Leave empty to finish.")
        try:
            while True:
                value = Prompt.ask("URI or path").strip()
                if not value:
                    break
                ingest(value)
        except (EOFError, KeyboardInterrupt):
            return 1
    else:
        console.print("No input supplied. Pass a URI, JSON file, or image path.", style="red")
        return 1

    if failed or not all_credentials:
        console.print("No export written: fix failed inputs and include all export QR codes.", style="red")
        return 1

    # A shared secret can belong to different labels, algorithms, or counters.
    unique = {}
    for credential in all_credentials:
        key = json.dumps(credential.to_dict(), sort_keys=True, ensure_ascii=False)
        unique.setdefault(key, credential)
    credentials = sorted(unique.values(), key=lambda item: (item.issuer or item.title).lower())
    table = Table(title=f"Recovered {len(credentials)} accounts")
    table.add_column("Issuer")
    table.add_column("Account")
    table.add_column("Type")
    for credential in credentials:
        table.add_row(Text(credential.issuer or credential.title),
                      Text(credential.username), Text(credential.category.upper()))
    console.print(table)

    if args.preview:
        return 0
    if args.output:
        destination = DataExporter.destination(args.output, fmt)
        if destination.resolve() in source_files:
            console.print("Output must not overwrite an input file.", style="red")
            return 1
        payload = {"google_authenticator": [credential.to_dict() for credential in credentials]}
        try:
            actual = DataExporter(banner="GOOGLE AUTHENTICATOR RECOVERY REPORT").export(payload, args.output, fmt)
        except (OSError, ValueError, TypeError) as exc:
            console.print(Text(f"Export failed: {exc}", style="red"))
            return 1
        console.print(Text(f"Export saved to: {actual}", style="green"))
    else:
        console.print("Use -o backup.json to save the recovered secrets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
