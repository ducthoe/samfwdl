# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

import requests

from . import __version__, fus

_HISTORY_WRAP_WIDTH = 100
_FIRMWARE_HELP = "Firmware version to use, for example S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2Z"
_HISTORY_DETAIL_SKIP_TAGS = {
    "ANDROID_VERSION",
    "BINARY_ANDROID_VERSION",
    "BINARY_DISPLAY_NAME",
    "BINARY_DISPLAY_VERSION",
    "BINARY_INDEX",
    "BINARY_LOCAL_CODE",
    "BINARY_MODEL_DISPLAYNAME",
    "BINARY_MODEL_NAME",
    "BINARY_NATURE",
    "BINARY_OPEN_DATE",
    "BINARY_OS_NAME",
    "BINARY_OS_VERSION",
    "BINARY_SEQUENCE",
    "BINARY_SW_DISPLAYVERSION",
    "BINARY_SW_VERSION",
    "DEVICE_DISPLAY_NAME",
    "DEVICE_LOCAL_CODE",
    "DEVICE_MODEL_NAME",
    "DISPLAY_NAME",
    "DISPLAY_VERSION",
    "LOCAL_CODE",
    "MODEL_NAME",
    "OS_NAME",
    "OS_VERSION",
    "SW_DISPLAYVERSION",
}


def _join_history_values(values: tuple[str, ...]) -> str:
    return " | ".join(value for value in values if value)


def _format_labeled_value(label: str, value: str, *, indent: str = "  ", label_width: int = 12) -> list[str]:
    text = str(value or "")
    prefix = f"{indent}{label:<{label_width}}: "
    continuation = " " * len(prefix)
    wrap_width = max(24, _HISTORY_WRAP_WIDTH - len(prefix))
    wrapped = textwrap.wrap(
        text,
        width=wrap_width,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [""]
    return [prefix + wrapped[0], *(continuation + line for line in wrapped[1:])]


def _format_history_entry(row: fus.FirmwareHistoryEntry) -> str:
    title_parts = [f"sequence {row.sequence or '?'}", f"index {row.index or '?'}"]
    if row.open_date:
        title_parts.append(row.open_date)
    lines = [", ".join(title_parts)]

    fields = [
        ("Firmware", row.firmware_version),
        ("Android", row.android_version),
        ("Nature", _join_history_values(row.natures)),
        ("OS", row.os_name),
        ("Model", row.model_name),
        ("Name", row.display_name),
        ("Region", row.local_code),
        ("Display", row.display_version),
    ]
    if row.sw_display_version and row.sw_display_version != row.firmware_version:
        fields.append(("SW display", row.sw_display_version))
    for label, value in fields:
        if value:
            lines.extend(_format_labeled_value(label, value))

    extra_fields = []
    for tag, values in row.fields.items():
        if tag in _HISTORY_DETAIL_SKIP_TAGS:
            continue
        value = _join_history_values(values)
        if value:
            extra_fields.append((tag, value))
    if extra_fields:
        lines.append("  Extra")
        for tag, value in extra_fields:
            lines.extend(_format_labeled_value(tag, value, indent="    ", label_width=24))

    return "\n".join(lines)


def _add_device_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("model")
    parser.add_argument("region")


def _add_firmware_override_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firmware", help=_FIRMWARE_HELP)
    parser.add_argument(
        "--force-firmware",
        action="store_true",
        help="Use --firmware instead of the latest firmware returned by FUS",
    )


def _download_output_args(output: str) -> tuple[Path | None, Path | None]:
    path = Path(output).expanduser()
    if path.is_dir() or path.suffix == "":
        return path, None
    return None, path


def _print_error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="asgard", description=f"asgard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("checkupdate", help="Get the latest firmware version")
    _add_device_args(check_parser)

    history_parser = subparsers.add_parser("history", help="Show firmware history for a device and CSC")
    _add_device_args(history_parser)
    history_parser.add_argument("--json", action="store_true", help="Output all SmartHistory fields as JSON")

    download_parser = subparsers.add_parser("download", help="Download firmware from FUS")
    _add_device_args(download_parser)
    _add_firmware_override_args(download_parser)
    download_parser.add_argument("-o", "--output", required=True, help="Output file or directory")
    download_parser.add_argument("--resume", action="store_true")
    download_parser.add_argument("--decrypt", action="store_true", help="Decrypt while downloading")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted FUS package")
    _add_device_args(decrypt_parser)
    decrypt_parser.add_argument("input")
    decrypt_parser.add_argument("-o", "--output")
    _add_firmware_override_args(decrypt_parser)
    decrypt_parser.add_argument("--enc-ver", type=int, choices=[2, 4], default=4)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "checkupdate":
            version = fus.get_latest_version(args.model, args.region)
            print(version)
            return 0

        if args.command == "history":
            rows = fus.get_firmware_history(args.model, args.region)
            if not rows:
                print("No history found.")
                return 0
            if args.json:
                print(json.dumps([row.to_dict() for row in rows], indent=2, sort_keys=True))
                return 0
            for idx, row in enumerate(rows):
                if idx:
                    print()
                print(_format_history_entry(row))
            return 0

        if args.command == "download":
            out_dir, out_file = _download_output_args(args.output)
            result = fus.download_firmware(
                model=args.model,
                region=args.region,
                firmware_version=args.firmware,
                force_firmware=args.force_firmware,
                out_dir=out_dir,
                out_file=out_file,
                resume=args.resume,
                auto_decrypt=args.decrypt,
            )
            print(result.decrypted_path or result.encrypted_path)
            return 0

        out_path = Path(args.output).expanduser() if args.output else fus.decrypted_output_path(args.input)
        final_path = fus.decrypt_firmware(
            version=args.firmware,
            model=args.model,
            region=args.region,
            in_file=args.input,
            out_file=out_path,
            enc_ver=args.enc_ver,
            force_firmware=args.force_firmware,
        )
        print(final_path)
        return 0
    except ValueError as exc:
        parser.error(str(exc))
    except FileNotFoundError as exc:
        _print_error(f"file not found: {exc}")
        return 2
    except fus.FUSError as exc:
        _print_error(str(exc))
        return 1
    except requests.RequestException as exc:
        _print_error(f"request failed: {exc}")
        return 1

    return 1
