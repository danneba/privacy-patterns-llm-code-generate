import json
import sys
import argparse
from pathlib import Path

from benchmarks.runner import (
    DEFAULT_OWASP_PATH,
    check_owasp_benchmark,
    ensure_owasp_benchmark,
    format_owasp_status,
    format_report_text,
    run_benchmarks,
)
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

    benchmark = sub.add_parser(
        "benchmark",
        help="Evaluate the analyzer on internal and/or OWASP Benchmark for Python.",
    )
    benchmark.add_argument(
        "--dataset",
        choices=["internal", "owasp", "both"],
        default="both",
        help="Which benchmark dataset to run (default: both).",
    )
    benchmark.add_argument(
        "--scope",
        choices=["security", "privacy", "all"],
        default="security",
        help="Internal benchmark scope (default: security). OWASP is security-only.",
    )
    benchmark.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text).",
    )
    benchmark.add_argument(
        "--output", metavar="FILE",
        help="Write output to FILE instead of stdout.",
    )
    benchmark.add_argument(
        "--owasp-path",
        metavar="DIR",
        help="Path to cloned OWASP BenchmarkPython repo "
        "(default: benchmarks/data/BenchmarkPython).",
    )
    benchmark.add_argument(
        "--clone-owasp",
        action="store_true",
        help="Clone OWASP Benchmark for Python if missing or incomplete.",
    )
    benchmark.add_argument(
        "--force-clone-owasp",
        action="store_true",
        help="Delete and re-clone OWASP Benchmark for Python.",
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


def _prepare_owasp_benchmark(args: argparse.Namespace, owasp_path: Path) -> None:
    if args.dataset not in ("owasp", "both"):
        return

    if args.force_clone_owasp:
        print("Re-cloning OWASP Benchmark for Python…")
        status = ensure_owasp_benchmark(owasp_path, force=True)
        print(format_owasp_status(status))
        return

    status = check_owasp_benchmark(owasp_path)
    if status.is_ready:
        print(format_owasp_status(status))
        return

    if args.clone_owasp or status.state in ("missing", "incomplete"):
        print("Cloning OWASP Benchmark for Python…")
        status = ensure_owasp_benchmark(owasp_path)
        print(format_owasp_status(status))
        return

    print(format_owasp_status(status), file=sys.stderr)
    raise FileNotFoundError(status.detail)


def _run_benchmark(args: argparse.Namespace) -> int:
    owasp_path = Path(args.owasp_path) if args.owasp_path else DEFAULT_OWASP_PATH

    try:
        _prepare_owasp_benchmark(args, owasp_path)
        reports = run_benchmarks(
            dataset=args.dataset,
            scope=args.scope,
            owasp_path=owasp_path,
            ensure_owasp=False,
        )
    except FileNotFoundError as exc:
        print(f"vibecodeguide: error: {exc}", file=sys.stderr)
        print(
            "Hint: run with --clone-owasp to fetch OWASP Benchmark for Python.",
            file=sys.stderr,
        )
        return 2
    except ValueError as exc:
        print(f"vibecodeguide: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = json.dumps([report.to_dict() for report in reports], indent=2)
    else:
        output = format_report_text(reports)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
        print(f"Benchmark report written to {args.output}")
    else:
        print(output)

    any_failures = any(
        sample.passed is False
        for report in reports
        for sample in report.samples
    ) or any(
        test.passed is False
        for report in reports
        for test in report.owasp_tests
    )
    return 1 if any_failures else 0


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
    if args.command == "benchmark":
        sys.exit(_run_benchmark(args))

    parser.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
