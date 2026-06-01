import json
import sys
import argparse
from pathlib import Path

from security.core.demo import run_guidance_demo
from security.core.scanner import Scanner
from security.models.finding import Severity
from security.reporters.demo import DemoReporter
from security.reporters.json_reporter import JsonReporter
from security.reporters.text import TextReporter

DEFAULT_DEMO_SAMPLE = "samples/privacy_showcase_vulnerable.py"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibecodeguide",
        description="VibeCodeGuide — static security and privacy analyzer for Python code.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", help="Scan a Python file or directory.")
    scan.add_argument("path", help="Path to a Python file or directory.")
    scan.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text).",
    )
    scan.add_argument(
        "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    scan.add_argument(
        "--severity", choices=["low", "medium", "high"],
        help="Minimum severity level to report.",
    )
    scan.add_argument("--quiet", action="store_true", help="Suppress non-finding output.")
    scan.add_argument(
        "--no-snippet", dest="include_snippet", action="store_false",
        help="Exclude code snippets from output.",
    )
    scan.add_argument(
        "--no-guidance",
        action="store_true",
        help="Baseline mode: security rules only (disable privacy & security guidance module).",
    )
    scan.set_defaults(include_snippet=True)

    demo = sub.add_parser(
        "demo",
        help="Side-by-side comparison: baseline analyzer vs guidance-enabled analysis.",
    )
    demo.add_argument(
        "path",
        nargs="?",
        default=DEFAULT_DEMO_SAMPLE,
        help=f"Python file to analyze (default: {DEFAULT_DEMO_SAMPLE}).",
    )
    demo.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text).",
    )
    demo.add_argument(
        "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    demo.add_argument(
        "--severity", choices=["low", "medium", "high"],
        help="Minimum severity level to report.",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    target = args.path
    if not Path(target).exists():
        print(f"vibecodeguide: error: path does not exist: {target}", file=sys.stderr)
        return 2

    min_severity = Severity[args.severity.upper()] if args.severity else None
    scanner = Scanner(
        min_severity=min_severity,
        include_snippet=args.include_snippet,
        enable_guidance=not args.no_guidance,
    )
    result = scanner.scan(target)

    writing_to_file = bool(args.output)
    if args.format == "json":
        reporter: JsonReporter | TextReporter = JsonReporter()
    else:
        reporter = TextReporter(use_color=not writing_to_file)

    output = reporter.report(result)
    if args.no_guidance and args.format == "text" and not writing_to_file:
        output = (
            "Mode: baseline (Privacy & Security Guidance disabled)\n\n"
            + output
        )

    if writing_to_file:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if not args.quiet:
            print(f"Report written to {args.output}")
    else:
        print(output)

    return 1 if result.findings else 0


def _run_demo(args: argparse.Namespace) -> int:
    target = args.path
    if not Path(target).exists():
        print(f"vibecodeguide: error: path does not exist: {target}", file=sys.stderr)
        return 2

    code = Path(target).read_text(encoding="utf-8", errors="replace")
    min_severity = Severity[args.severity.upper()] if args.severity else None
    comparison = run_guidance_demo(
        code,
        filename=str(target),
        min_severity=min_severity,
        sample_label=str(target),
    )

    if args.format == "json":
        output = json.dumps(comparison.to_dict(), indent=2)
    else:
        output = DemoReporter().report(comparison)

    writing_to_file = bool(args.output)
    if writing_to_file:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if not getattr(args, "quiet", False):
            print(f"Demo report written to {args.output}")
    else:
        print(output)

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(2)

    if args.command == "demo":
        sys.exit(_run_demo(args))
    if args.command == "scan":
        sys.exit(_run_scan(args))

    parser.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
