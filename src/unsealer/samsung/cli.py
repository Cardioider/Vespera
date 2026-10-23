"""Samsung Pass command line interface."""

import argparse
import sys
from pathlib import Path

import pyfiglet
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from unsealer.common.exporter import DataExporter
from .decrypter import decrypt_and_parse

console = Console(stderr=True)


def _display_banner() -> str:
    banner = pyfiglet.figlet_format("Unsealer", font="slant")
    console.print(Panel(banner, title="Vespera", subtitle="freedom beyond locks", expand=False))
    return banner


def main(argv=None):
    parser = argparse.ArgumentParser(description="Decrypt a local Samsung Pass backup.")
    parser.add_argument("input_file", type=Path, help="Path to a .spass backup")
    parser.add_argument("-f", "--format", choices=["md", "csv", "txt", "json"], default="md",
                        help="Export format (default: md)")
    parser.add_argument("-o", "--output", type=Path, help="Output path (CSV creates a directory of tables)")
    parser.add_argument("--preview", action="store_true", help="Show table counts without writing files")
    args = parser.parse_args(sys.argv[2:] if argv is None else argv)
    if not args.input_file.is_file():
        console.print("Input must be an existing backup file.", style="red")
        return 1

    output = args.output or args.input_file.with_suffix(f".{args.format}")
    if not args.preview and DataExporter.destination(output, args.format).resolve() == args.input_file.resolve():
        console.print("Output must not overwrite the input backup.", style="red")
        return 1

    try:
        password = Prompt.ask("Enter the backup/export password", password=True)
        banner = _display_banner()
        with console.status("Decrypting and processing..."):
            tables = decrypt_and_parse(args.input_file.read_bytes(), password)
        if not tables or not any(tables.values()):
            console.print("No records found. No export written.", style="red")
            return 1
        if args.preview:
            summary = Text()
            for name, rows in tables.items():
                summary.append(f"{name.upper()}: {len(rows)} items\n")
            console.print(Panel(summary, title="Decryption successful"))
            return 0
        actual = DataExporter(banner=banner).export(tables, output, args.format)
        console.print(Text(f"Export saved to: {actual}", style="green"))
        return 0
    except (EOFError, KeyboardInterrupt):
        console.print("Cancelled.")
        return 1
    except (OSError, ValueError, TypeError) as exc:
        console.print(Text(f"Error: {exc}", style="red"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
