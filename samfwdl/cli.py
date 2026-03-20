from __future__ import annotations

import argparse
from pathlib import Path

import requests

from . import fus


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="samfwdl", description="samfwdl 1.0.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("checkupdate", help="Get the latest firmware version")
    check_parser.add_argument("model")
    check_parser.add_argument("region")

    download_parser = subparsers.add_parser("download", help="Download firmware from FUS")
    download_parser.add_argument("model")
    download_parser.add_argument("region")
    download_parser.add_argument(
        "--firmware",
        help="Firmware version to use, for example S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2Z",
    )
    download_parser.add_argument(
        "--force-firmware",
        action="store_true",
        help="Use --firmware instead of the latest firmware returned by FUS",
    )
    download_parser.add_argument("-o", "--output", required=True, help="Output file or directory")
    download_parser.add_argument("--resume", action="store_true")
    download_parser.add_argument("--decrypt", action="store_true", help="Decrypt while downloading")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt an encrypted FUS package")
    decrypt_parser.add_argument("model")
    decrypt_parser.add_argument("region")
    decrypt_parser.add_argument("input")
    decrypt_parser.add_argument("-o", "--output")
    decrypt_parser.add_argument(
        "--firmware",
        help="Firmware version to use, for example S721BXXSACZB2/S721BOXMACZB2/S721BXXSACZB2/S721BXXSACZB2Z",
    )
    decrypt_parser.add_argument(
        "--force-firmware",
        action="store_true",
        help="Use --firmware instead of the latest firmware returned by FUS",
    )
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

        if args.command == "download":
            output = Path(args.output).expanduser()
            out_dir = output if output.suffix == "" else None
            out_file = None if out_dir is output else output
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
        print(f"error: file not found: {exc}")
        return 2
    except fus.FUSError as exc:
        print(f"error: {exc}")
        return 1
    except requests.RequestException as exc:
        print(f"error: request failed: {exc}")
        return 1

    return 1
