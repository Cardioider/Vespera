"""Command dispatch; load only the selected module."""

import argparse
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = argparse.ArgumentParser(
        prog="unsealer",
        description="Reclaim your digital credentials from local backups.",
        epilog="Use 'unsealer <command> --help' for module options.",
    )
    parser.add_argument("command", choices=["samsung", "google"], help="Backup format to import")
    args = parser.parse_args(argv[:1])
    try:
        if args.command == "samsung":
            from unsealer.samsung import cli
        else:
            from unsealer.google import cli
        return cli.main(argv[1:])
    except (ImportError, OSError) as exc:
        print(f"Unable to load the selected module: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
