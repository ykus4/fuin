"""fuin packer — CLI entry point.

fuin-pack pack <input.apk> <output.apk> [options]
fuin-pack analyze <input.apk>
"""

import argparse
import json
import logging

from fuin import config
from fuin._utils import fmt_size
from fuin.packer import PackOptions, pack_apk
from fuin.report import format_report, generate_report

log = logging.getLogger(__name__)


def _pack(args: argparse.Namespace) -> None:
    options = PackOptions(
        app_class=args.app_class or None,
        encrypt_native=not args.no_native_encrypt,
        encrypt_assets=not args.no_resource_encrypt,
        encrypt_strings=args.encrypt_strings,
        root_detection=args.root_detection,
        emulator_detection=args.emulator_detection,
        strict_manifest_patch=args.strict_manifest_patch,
        verify_signature=args.verify_signature,
        keystore_path=args.keystore,
        keystore_alias=args.key_alias,
        keystore_store_pass=args.store_pass,
        keystore_key_pass=args.key_pass,
    )
    pack_apk(args.input, args.output, options=options)

    if args.report or args.report_json:
        report = generate_report(args.input, args.output)
        if args.report_json:
            print(json.dumps(report, indent=2))
        else:
            print(format_report(report))


def _analyze(args: argparse.Namespace) -> None:
    from fuin.analyze import analyze_targets

    result = analyze_targets(args.input)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    _print_analysis(result)


def _print_analysis(result: dict) -> None:
    print("=== Fuin Encryption Analysis ===")
    print()

    sections = (
        ("DEX files", result["dex"]),
        ("Native libraries", result["native_libs"]),
        ("User assets", result["assets"]),
    )
    for label, section in sections:
        files = section["files"]
        if not files and label != "DEX files":
            print(f"{label}: none found")
            print()
            continue
        print(f"{label} ({len(files)} total, {fmt_size(section['total_size'])}):")
        for f in files:
            print(f"  ✓ {f['name']}  ({fmt_size(f['size'])})")
        print()

    summary = result["summary"]
    print("--- Summary ---")
    print(f"  Total encryptable files: {summary['total_files']}")
    print(f"  Total encryptable size:  {fmt_size(summary['total_size'])}")
    print(f"  APK total size:          {fmt_size(summary['apk_size'])}")
    print(f"  Protection coverage:     {summary['coverage_percent']:.1f}% of APK content")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuin", description="Android DEX Packer")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    pack_p = sub.add_parser("pack", help="Pack and encrypt an APK")
    pack_p.add_argument("input", help="Input APK path")
    pack_p.add_argument("output", help="Output (protected) APK path")
    pack_p.add_argument("--app-class", help="Original Application class name (optional)")
    pack_p.add_argument("--keystore", help="Keystore path (overrides FUIN_KEYSTORE_PATH)")
    pack_p.add_argument("--key-alias", help="Key alias (overrides FUIN_KEYSTORE_ALIAS)")
    pack_p.add_argument(
        "--store-pass", help="Keystore password (overrides FUIN_KEYSTORE_STORE_PASS)"
    )
    pack_p.add_argument("--key-pass", help="Key password (overrides FUIN_KEYSTORE_KEY_PASS)")
    pack_p.add_argument("--report", action="store_true", help="Print pack diff report")
    pack_p.add_argument("--report-json", action="store_true", help="Print pack diff report as JSON")
    pack_p.add_argument("--root-detection", action="store_true", help="Enable root detection")
    pack_p.add_argument(
        "--emulator-detection", action="store_true", help="Enable emulator detection"
    )
    pack_p.add_argument("--no-native-encrypt", action="store_true", help="Disable .so encryption")
    pack_p.add_argument(
        "--no-resource-encrypt", action="store_true", help="Disable asset encryption"
    )
    pack_p.add_argument(
        "--encrypt-strings", action="store_true", help="Enable DEX string obfuscation"
    )
    pack_p.add_argument(
        "--no-strict-manifest-patch",
        dest="strict_manifest_patch",
        action="store_false",
        default=config.STRICT_MANIFEST_PATCH,
        help="Allow best-effort packing when StubApplication cannot be inserted",
    )
    pack_p.add_argument(
        "--verify-signature",
        action="store_true",
        default=config.VERIFY_SIGNATURE,
        help="Run apksigner verify after signing",
    )

    analyze_p = sub.add_parser("analyze", help="Preview what will be encrypted in an APK")
    analyze_p.add_argument("input", help="Input APK path")
    analyze_p.add_argument("--json", action="store_true", help="Output as JSON")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.command == "pack":
        _pack(args)
    elif args.command == "analyze":
        _analyze(args)


if __name__ == "__main__":
    main()
