from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import requests
from Cryptodome.Cipher import AES


_AUTH_PARAM_NAME = "auth_param.dat"
_FUS_USER_AGENT = "SMART 2.0"
_FUS_LEGACY_USER_AGENT = "Kies2.0_FUS"
_FUS_BASE_URL = "https://neofussvr.sslcs.cdngc.net/"
_FUS_DOWNLOAD_URL = "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do"
_FUS_PLACEHOLDER = "." * 16
_AUTH_SIGNATURE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_PROGRESS_REFRESH_S = 0.1
_SPEED_WINDOW_S = 1.5
_RANGE_CHUNK_SIZE = 0x10000
_DOWNLOAD_THREADS = 5
_DECRYPT_THREADS = 4
_DOWNLOAD_RETRIES = 5
_RETRY_BACKOFF_S = 0.75
_THREAD_STAGGER_S = 0.1
_SHIFT_INDICES = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)


class FUSError(RuntimeError):
    pass


@dataclass(frozen=True)
class BinaryInfo:
    model_path: str
    filename: str
    size: int
    latest_version: str | None = None
    logic_value_factory: str | None = None
    logic_value_home: str | None = None
    firmware_version: str | None = None
    model_type: str | None = None

    @property
    def logic_value(self) -> str | None:
        return self.logic_value_factory or self.logic_value_home

    @property
    def binary_version(self) -> str | None:
        return self.firmware_version or self.latest_version


@dataclass(frozen=True)
class DownloadResult:
    encrypted_path: Path
    decrypted_path: Path | None
    firmware_version: str
    filename: str
    size: int


@dataclass(frozen=True)
class _AuthHeaderBlock:
    offset: int
    size: int


@dataclass(frozen=True)
class _AuthHeader:
    magic: int
    alignment: int
    block1: _AuthHeaderBlock
    block2: _AuthHeaderBlock
    block3: _AuthHeaderBlock
    block4: _AuthHeaderBlock
    block5: _AuthHeaderBlock
    block6: _AuthHeaderBlock


def _print_info(message: str) -> None:
    print(message, flush=True)


def _format_bytes(size: float) -> str:
    value = float(size)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB"


def _render_progress(label: str, done: int, total: int, started_at: float, *, complete: bool = False) -> None:
    elapsed = max(time.monotonic() - started_at, 0.001)
    speed = done / elapsed
    if total > 0:
        percent = min(100.0, (done / total) * 100.0)
        total_text = _format_bytes(total)
    else:
        percent = 0.0
        total_text = "?"
    line = f"{label}: {percent:6.2f}% {_format_bytes(done)}/{total_text} {_format_bytes(speed)}/s"
    sys.stdout.write(f"\r\033[2K{line}")
    if complete:
        sys.stdout.write("\n")
    sys.stdout.flush()


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise FUSError("invalid PKCS#7 payload")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise FUSError("invalid PKCS#7 padding")
    return data[:-pad_len]


def _resolve_auth_param_path() -> Path:
    path = Path(__file__).with_name(_AUTH_PARAM_NAME)
    if path.is_file():
        return path
    raise FileNotFoundError(f"missing {_AUTH_PARAM_NAME}")


@lru_cache(maxsize=1)
def _load_auth_param_data() -> bytes:
    return _resolve_auth_param_path().read_bytes()


def _create_auth_header(raw_data: bytes) -> _AuthHeader:
    if len(raw_data) < 56:
        raise FUSError("auth_param.dat is truncated")
    values = [int.from_bytes(raw_data[idx : idx + 4], "little", signed=True) for idx in range(0, 56, 4)]
    return _AuthHeader(
        magic=values[0],
        alignment=values[1],
        block1=_AuthHeaderBlock(offset=values[2], size=values[3]),
        block2=_AuthHeaderBlock(offset=values[4], size=values[5]),
        block5=_AuthHeaderBlock(offset=values[6], size=values[7]),
        block6=_AuthHeaderBlock(offset=values[8], size=values[9]),
        block3=_AuthHeaderBlock(offset=values[10], size=values[11]),
        block4=_AuthHeaderBlock(offset=values[12], size=values[13]),
    )


def _authenticate_block(in_block: bytes) -> bytes:
    if len(in_block) < 16:
        raise FUSError("nonce block is too short")
    raw_data = _load_auth_param_data()
    header = _create_auth_header(raw_data)
    stream = memoryview(raw_data)[56:]
    temp_block = [0] * 320
    for idx in range(16):
        temp_block[idx] = in_block[idx]
    out_block = bytearray(16)
    scratch = [0] * 64
    base_final = header.block1.size
    final_src_start = 288

    for round_idx in range(9):
        src_start = round_idx * 32
        next_src_start = (round_idx + 1) * 32
        block_id_base = round_idx * 16
        src_mid = src_start + 16

        for idx in range(16):
            temp_block[src_start + 16 + idx] = temp_block[src_start + _SHIFT_INDICES[idx]]

        for row in range(4):
            row4 = row << 2
            row16 = row << 4
            block_id_row = block_id_base + row4
            table_base = base_final + header.block2.size + header.block3.size + (6144 * (row + (round_idx << 2)))

            for column in range(4):
                index_value = temp_block[src_mid + row4 + column]
                block_id = block_id_row + column
                source_base = (block_id << 12) + (index_value << 4)
                selector_base = base_final + header.block2.size + (block_id << 5)
                source_chunk = stream[source_base : source_base + 16]
                selector_chunk = stream[selector_base : selector_base + 32]
                out_start = row16 + (column << 2)

                for out_idx in range(4):
                    acc = 0
                    selector_offset = out_idx << 3
                    for bit_idx in range(8):
                        selector_byte = selector_chunk[selector_offset + bit_idx]
                        source_idx = (selector_byte >> 3) & 0x1F
                        bit_pos = 7 - (selector_byte & 0x07)
                        source_byte = source_chunk[source_idx] if source_idx < 16 else 0
                        acc |= ((source_byte >> bit_pos) & 1) << (7 - bit_idx)
                    scratch[out_start + out_idx] = acc & 0xFF

            for column in range(4):
                a1 = scratch[row16 + column]
                a2 = scratch[row16 + column + 4]
                a3 = scratch[row16 + column + 8]
                a4 = scratch[row16 + column + 12]
                table = stream[table_base + (1536 * column) : table_base + (1536 * (column + 1))]
                hi1 = ((a1 & 0xF0) | (a2 >> 4)) & 0xFF
                lo1 = (((a1 & 0x0F) << 4) | (a2 & 0x0F)) & 0xFF
                v6 = ((16 * table[hi1]) ^ table[256 + lo1]) & 0xFF
                hi2 = ((a3 & 0xF0) | (a4 >> 4)) & 0xFF
                lo2 = (((a3 & 0x0F) << 4) | (a4 & 0x0F)) & 0xFF
                v7 = ((16 * table[512 + hi2]) ^ table[768 + lo2]) & 0xFF
                hi3 = ((v6 & 0xF0) | (v7 >> 4)) & 0xFF
                lo3 = (((v6 & 0x0F) << 4) | (v7 & 0x0F)) & 0xFF
                temp_block[next_src_start + row4 + column] = ((16 * table[1024 + hi3]) ^ table[1280 + lo3]) & 0xFF

    for idx in range(16):
        pos = base_final + (idx << 8) + temp_block[_SHIFT_INDICES[idx] + final_src_start]
        out_block[idx] = stream[pos]

    return bytes(out_block)


def decrypt_nonce(enc_nonce: str) -> str:
    seed = enc_nonce[:16].ljust(16, "0").encode("utf-8")
    return _authenticate_block(seed).hex()


def normalize_version_code(version_code: str) -> str:
    parts = [part.strip() for part in str(version_code or "").split("/")]
    if len(parts) == 3:
        parts.append(parts[0])
    if len(parts) >= 3 and not parts[2]:
        parts[2] = parts[0]
    return "/".join(parts)


def get_logic_check(value: str, nonce: str) -> str:
    if len(value) < 16:
        raise FUSError("logic check input too short")
    return "".join(value[ord(ch) & 0xF] for ch in nonce)


def _xml_text(root: ET.Element, path: str) -> str | None:
    node = root.find(path)
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text or None


def _first_xml_text(root: ET.Element, *paths: str) -> str | None:
    for path in paths:
        text = _xml_text(root, path)
        if text is not None:
            return text
    return None


def _build_xml_request(*, proto_ver: str = "1") -> tuple[ET.Element, ET.Element]:
    fus_msg = ET.Element("FUSMsg")
    fus_hdr = ET.SubElement(fus_msg, "FUSHdr")
    ET.SubElement(fus_hdr, "ProtoVer").text = proto_ver
    ET.SubElement(fus_hdr, "SessionID").text = "0"
    ET.SubElement(fus_hdr, "MsgID").text = "1"
    fus_body = ET.SubElement(fus_msg, "FUSBody")
    put = ET.SubElement(fus_body, "Put")
    return fus_msg, put


def _append_data_node(parent: ET.Element, tag: str, value: str | int) -> None:
    elem = ET.SubElement(parent, tag)
    ET.SubElement(elem, "Data").text = str(value)


def build_binaryinform_request(
    model: str,
    region: str,
    *,
    firmware_version: str | None = None,
    nonce: str | None = None,
) -> bytes:
    version = normalize_version_code(firmware_version) if str(firmware_version or "").strip() else _FUS_PLACEHOLDER
    logic_check = get_logic_check(version, nonce or "") if firmware_version and nonce else _FUS_PLACEHOLDER
    fus_msg, put = _build_xml_request(proto_ver="1")
    fus_body = fus_msg.find("./FUSBody")
    ET.SubElement(put, "CmdID").text = "1"
    for tag, value in (
        ("ACCESS_MODE", "1"),
        ("BINARY_NATURE", "1"),
        ("REQUEST_TYPE", "2"),
        ("LOGIC_CHECK", logic_check),
        ("BINARY_SW_VERSION", version),
        ("DEVICE_SN_NUMBER", ""),
        ("BINARY_LOCAL_CODE", str(region).strip().upper()),
        ("BINARY_MODEL_NAME", str(model).strip().upper()),
    ):
        _append_data_node(put, tag, value)
    get = ET.SubElement(fus_body, "Get")
    ET.SubElement(get, "CmdID").text = "2"
    ET.SubElement(get, "BINARY_SW_VERSION")
    return ET.tostring(fus_msg, encoding="utf-8")


def build_legacy_binaryinform_request(model: str, region: str) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1.0")
    for tag, value in (
        ("ACCESS_MODE", 5),
        ("BINARY_NATURE", 1),
        ("CLIENT_PRODUCT", "Smart Switch"),
        ("CLIENT_VERSION", "5.0.0.0"),
        ("DEVICE_FW_VERSION", _FUS_PLACEHOLDER),
        ("DEVICE_LOCAL_CODE", str(region).strip().upper()),
        ("DEVICE_AID_CODE", str(region).strip().upper()),
        ("DEVICE_CC_CODE", "DE"),
        ("DEVICE_MODEL_NAME", str(model).strip().upper()),
        ("LOGIC_CHECK", _FUS_PLACEHOLDER),
        ("DEVICE_INITIALIZE", 2),
    ):
        _append_data_node(put, tag, value)
    return ET.tostring(fus_msg, encoding="utf-8")


def _binary_init_logic_input(filename: str) -> str:
    name = str(filename or "")
    if len(name) >= 25:
        return name[-25:-9]
    return name.split(".")[0][-16:]


def build_binaryinit_request(
    filename: str,
    nonce: str,
    *,
    firmware_version: str | None = None,
    model_type: str | None = None,
    region: str | None = None,
) -> bytes:
    fus_msg, put = _build_xml_request(proto_ver="1")
    _append_data_node(put, "BINARY_NAME", filename)
    if firmware_version:
        _append_data_node(put, "BINARY_SW_VERSION", normalize_version_code(firmware_version))
    if region:
        _append_data_node(put, "DEVICE_LOCAL_CODE", str(region).strip().upper())
    if model_type:
        _append_data_node(put, "DEVICE_MODEL_TYPE", model_type)
    _append_data_node(put, "LOGIC_CHECK", get_logic_check(_binary_init_logic_input(filename), nonce))
    return ET.tostring(fus_msg, encoding="utf-8")


def decrypted_output_path(path: str | os.PathLike[str]) -> Path:
    in_path = Path(path).expanduser()
    if in_path.suffix.lower() in {".enc2", ".enc4"}:
        return in_path.with_suffix("")
    return in_path.with_name(f"{in_path.name}.dec")


def _partial_output_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.part")


def _resume_state_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.resume.json")


def _build_range_parts(total_size: int, part_count: int = _DOWNLOAD_THREADS) -> list[dict[str, int]]:
    if total_size <= 0:
        return []
    block_size = 16
    max_parts = max(1, total_size // block_size)
    parts = max(1, min(int(part_count), max_parts))
    ranges: list[dict[str, int]] = []
    start = 0
    for idx in range(parts):
        if idx == parts - 1:
            end = total_size - 1
        else:
            remaining_parts = parts - idx
            remaining_bytes = total_size - start
            seg_len = max(block_size, (remaining_bytes // remaining_parts) // block_size * block_size)
            max_len = remaining_bytes - (remaining_parts - 1) * block_size
            seg_len = min(seg_len, max_len)
            end = start + seg_len - 1
        ranges.append({"start": start, "end": end, "offset": start})
        start = end + 1
    return ranges


def _save_range_resume_state(meta_path: Path, total_size: int, ranges: list[dict[str, int]]) -> None:
    tmp_path = meta_path.with_name(f"{meta_path.name}.tmp")
    tmp_path.write_text(json.dumps({"size": total_size, "ranges": ranges}), encoding="utf-8")
    tmp_path.replace(meta_path)


def _resume_done_bytes(ranges: list[dict[str, int]]) -> int:
    return sum(max(0, int(item["offset"]) - int(item["start"])) for item in ranges)


def _prepare_range_resume_state(data_path: Path, total_size: int, resume: bool) -> tuple[list[dict[str, int]], Path]:
    meta_path = _resume_state_path(data_path)
    default_ranges = _build_range_parts(total_size)
    ranges = default_ranges
    if resume and meta_path.is_file():
        try:
            payload = json.loads(meta_path.read_text(encoding="utf-8"))
            raw_ranges = payload.get("ranges")
            if (
                isinstance(raw_ranges, list)
                and int(payload.get("size", -1)) == total_size
                and len(raw_ranges) == len(default_ranges)
            ):
                loaded: list[dict[str, int]] = []
                valid = True
                for raw, default in zip(raw_ranges, default_ranges):
                    start = int(raw.get("start", -1))
                    end = int(raw.get("end", -1))
                    offset = int(raw.get("offset", start))
                    if start != default["start"] or end != default["end"]:
                        valid = False
                        break
                    loaded.append({"start": start, "end": end, "offset": max(start, min(end + 1, offset))})
                if valid:
                    ranges = loaded
        except Exception:
            ranges = default_ranges

    data_path.parent.mkdir(parents=True, exist_ok=True)
    if resume and data_path.exists():
        with data_path.open("r+b") as fh:
            fh.truncate(total_size)
    else:
        with data_path.open("wb") as fh:
            fh.truncate(total_size)
    return (ranges if resume else default_ranges), meta_path


class FUSClient:
    LEGACY_BINARY_INFORM_PATH = "NF_DownloadBinaryInform.do"
    GENERATE_NONCE_PATH = "NF_SmartDownloadGenerateNonce.do"
    BINARY_INFORM_PATH = "NF_SmartDownloadBinaryInform.do"
    BINARY_INIT_PATH = "NF_SmartDownloadBinaryInitForMass.do"

    def __init__(self, *, timeout_s: int = 30, session: requests.Session | None = None):
        self.timeout_s = int(timeout_s)
        self.session = session or requests.Session()
        self.auth = ""
        self.sessid = ""
        self.encnonce = ""
        self.nonce = ""
        self.make_request(self.GENERATE_NONCE_PATH)

    def _make_signature_hash(self, signature: str | None) -> str | None:
        if not signature:
            return None
        a_hash = hashlib.md5(f"auth:{self.nonce}:00000001".encode("utf-8")).hexdigest()
        b_hash = hashlib.md5(f"interface:{signature}".encode("utf-8")).hexdigest()
        return hashlib.md5(f"{a_hash}:FUS:{b_hash}".encode("utf-8")).hexdigest()

    def _build_auth_header(self, *, include_nonce: bool = True, signature: str | None = None, cloud: bool = False) -> str:
        has_signature = bool(signature)
        if include_nonce and has_signature:
            nonce = "".join(secrets.choice(_AUTH_SIGNATURE_ALPHABET) for _ in range(16))
        elif include_nonce:
            nonce = self.encnonce
        else:
            nonce = ""
        hashed_signature = self._make_signature_hash(signature)
        auth_signature = hashed_signature or self.auth
        nc = "00000001" if has_signature else ""
        auth_type = "auth" if has_signature else ""
        header_nonce = nonce if cloud else ""
        return (
            f'FUS nonce="{header_nonce}", signature="{auth_signature}", '
            f'nc="{nc}", type="{auth_type}", realm="{auth_type}"'
        )

    def _post_headers(self) -> dict[str, str]:
        headers = {"Authorization": self._build_auth_header(cloud=False), "User-Agent": _FUS_USER_AGENT}
        if self.sessid:
            headers["Cookie"] = f"JSESSIONID={self.sessid}"
            headers["Set-Cookie"] = f"JSESSIONID={self.sessid}"
        return headers

    def _legacy_post_headers(self) -> dict[str, str]:
        headers = {
            "Authorization": (
                f'FUS nonce="{self.encnonce}", signature="{self.auth}", nc="", type="", realm="", newauth="1"'
            ),
            "User-Agent": _FUS_LEGACY_USER_AGENT,
        }
        if self.sessid:
            headers["Cookie"] = f"JSESSIONID={self.sessid}"
        return headers

    def _download_headers(self) -> dict[str, str]:
        return {
            "Authorization": self._build_auth_header(cloud=True),
            "User-Agent": _FUS_USER_AGENT,
            "Cache-Control": "no-cache",
        }

    def _response_is_401(self, response: requests.Response, body: str) -> bool:
        if response.status_code == 401:
            return True
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return False
        return _xml_text(root, "./FUSBody/Results/Status") == "401"

    def _update_nonce_state(self, response: requests.Response) -> None:
        enc_nonce = response.headers.get("NONCE") or response.headers.get("nonce")
        if not enc_nonce:
            return
        self.encnonce = enc_nonce
        self.nonce = enc_nonce
        try:
            self.auth = decrypt_nonce(enc_nonce)
        except Exception:
            pass

    def _update_session_cookie(self, response: requests.Response) -> None:
        set_cookie_values: list[str] = []
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "get_all"):
            try:
                set_cookie_values = list(raw_headers.get_all("Set-Cookie") or [])
            except Exception:
                set_cookie_values = []
        if not set_cookie_values:
            header = response.headers.get("Set-Cookie")
            if header:
                set_cookie_values = [header]
        for cookie_value in set_cookie_values:
            for part in cookie_value.split(";"):
                cookie = part.strip()
                if cookie.startswith("JSESSIONID=") or cookie.startswith("JSESSIONID_SVR="):
                    _, value = cookie.split("=", 1)
                    self.sessid = value
                    return

    def make_request(self, path: str, data: bytes | str = b"") -> str:
        for attempt in range(2):
            if not self.nonce and path != self.GENERATE_NONCE_PATH:
                self.make_request(self.GENERATE_NONCE_PATH)
            response = self.session.post(
                f"{_FUS_BASE_URL}{path}",
                data=data,
                headers=self._post_headers(),
                timeout=self.timeout_s,
            )
            body = response.text
            if path != self.GENERATE_NONCE_PATH and self._response_is_401(response, body) and attempt == 0:
                self.make_request(self.GENERATE_NONCE_PATH)
                continue
            response.raise_for_status()
            self._update_nonce_state(response)
            self._update_session_cookie(response)
            return body
        raise FUSError("FUS authorization failed after nonce refresh")

    def make_legacy_request(self, path: str, data: bytes | str = b"") -> str:
        response = self.session.post(
            f"{_FUS_BASE_URL}{path}",
            data=data,
            headers=self._legacy_post_headers(),
            timeout=self.timeout_s,
        )
        response.raise_for_status()
        self._update_session_cookie(response)
        return response.text

    def download_file(
        self,
        remote_path: str,
        *,
        start: int = 0,
        end: int | None = None,
    ) -> requests.Response:
        url = f"{_FUS_DOWNLOAD_URL}?file={remote_path}"
        headers = self._download_headers()
        if end is not None:
            headers["Range"] = f"bytes={start}-{end}"
        elif start > 0:
            headers["Range"] = f"bytes={start}-"
        response = self.session.get(url, headers=headers, stream=True, timeout=self.timeout_s)
        response.raise_for_status()
        return response


def _parse_binary_info(response_text: str) -> BinaryInfo:
    root = ET.fromstring(response_text)
    status = _xml_text(root, "./FUSBody/Results/Status")
    if status not in {"200", "S00"}:
        raise FUSError(f"DownloadBinaryInform returned {status or 'unknown'}")
    filename = _first_xml_text(root, "./FUSBody/Put/BINARY_NAME/Data", "./FUSBody/Put/BINARY_FILE_NAME/Data")
    size_text = _xml_text(root, "./FUSBody/Put/BINARY_BYTE_SIZE/Data")
    model_path = _xml_text(root, "./FUSBody/Put/MODEL_PATH/Data")
    if not filename or not size_text or model_path is None:
        raise FUSError("FUS response did not include a downloadable firmware bundle")
    return BinaryInfo(
        model_path=model_path,
        filename=filename,
        size=int(size_text),
        latest_version=_first_xml_text(
            root, "./FUSBody/Results/LATEST_FW_VERSION/Data", "./FUSBody/Results/BINARY_SW_VERSION/Data"
        ),
        logic_value_factory=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_FACTORY/Data"),
        logic_value_home=_xml_text(root, "./FUSBody/Put/LOGIC_VALUE_HOME/Data"),
        firmware_version=_xml_text(root, "./FUSBody/Put/BINARY_SW_VERSION/Data"),
        model_type=_xml_text(root, "./FUSBody/Put/DEVICE_MODEL_TYPE/Data"),
    )


def _parse_binary_version(response_text: str) -> str:
    root = ET.fromstring(response_text)
    status = _xml_text(root, "./FUSBody/Results/Status")
    if status not in {"200", "S00"}:
        raise FUSError(f"DownloadBinaryInform returned {status or 'unknown'}")
    version = _first_xml_text(
        root,
        "./FUSBody/Results/LATEST_FW_VERSION/Data",
        "./FUSBody/Results/BINARY_SW_VERSION/Data",
        "./FUSBody/Put/BINARY_SW_VERSION/Data",
    )
    version = str(version or "").strip()
    if not version:
        raise FUSError("FUS did not return a firmware version")
    return version


def get_latest_version(model: str, region: str, *, timeout_s: int = 15) -> str:
    client = FUSClient(timeout_s=timeout_s)
    response_text = client.make_legacy_request(
        FUSClient.LEGACY_BINARY_INFORM_PATH,
        build_legacy_binaryinform_request(model, region),
    )
    return _parse_binary_version(response_text)


def get_binary_info(client: FUSClient, model: str, region: str) -> BinaryInfo:
    response_text = client.make_legacy_request(
        FUSClient.LEGACY_BINARY_INFORM_PATH,
        build_legacy_binaryinform_request(model, region),
    )
    return _parse_binary_info(response_text)


def get_binary_info_for_version(client: FUSClient, model: str, region: str, firmware_version: str) -> BinaryInfo:
    response_text = client.make_request(
        FUSClient.BINARY_INFORM_PATH,
        build_binaryinform_request(model, region, firmware_version=firmware_version, nonce=client.nonce),
    )
    return _parse_binary_info(response_text)


def _resolve_versioned_info(client: FUSClient, model: str, region: str, firmware_version: str | None) -> BinaryInfo:
    if str(firmware_version or "").strip():
        return get_binary_info_for_version(client, model, region, str(firmware_version))
    latest_info = get_binary_info(client, model, region)
    resolved_version = latest_info.latest_version or latest_info.binary_version
    if not resolved_version:
        raise FUSError("FUS did not return a firmware version")
    return get_binary_info_for_version(client, model, region, resolved_version)


def initialize_download(client: FUSClient, info: BinaryInfo, region: str) -> None:
    client.make_request(
        FUSClient.BINARY_INIT_PATH,
        build_binaryinit_request(
            info.filename,
            client.nonce,
            firmware_version=info.binary_version,
            model_type=info.model_type,
            region=region,
        ),
    )


def get_v4_key(model: str, region: str, *, firmware_version: str | None = None, force_firmware: bool = False) -> bytes:
    client = FUSClient()
    info = _resolve_versioned_info(client, model, region, firmware_version if force_firmware else None)
    binary_version = info.binary_version
    logic_value = info.logic_value
    if not binary_version or not logic_value:
        raise FUSError("FUS did not return the logic value required for v4 decryption")
    return hashlib.md5(get_logic_check(binary_version, logic_value).encode("utf-8")).digest()


def get_v2_key(version: str, model: str, region: str) -> bytes:
    deckey = f"{str(region or '').strip().upper()}:{str(model or '').strip().upper()}:{normalize_version_code(version)}"
    return hashlib.md5(deckey.encode("utf-8")).digest()


def _decrypt_range(
    in_path: Path,
    out_path: Path,
    key: bytes,
    start: int,
    end: int,
) -> None:
    cipher = AES.new(key, AES.MODE_ECB)
    with in_path.open("rb") as inf, out_path.open("r+b") as outf:
        inf.seek(start)
        outf.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            chunk_size = min(1024 * 1024, remaining)
            chunk_size -= chunk_size % 16
            if chunk_size == 0:
                chunk_size = remaining
            data = inf.read(chunk_size)
            if len(data) != chunk_size:
                raise FUSError("unexpected end of encrypted input")
            outf.write(cipher.decrypt(data))
            remaining -= chunk_size


def _finalize_decrypted_file(path: Path) -> None:
    with path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError("decrypted file is empty")
        fh.seek(-16, os.SEEK_END)
        tail = fh.read(16)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)


def decrypt_firmware(
    *,
    version: str | None,
    model: str,
    region: str,
    in_file: str | os.PathLike[str],
    out_file: str | os.PathLike[str],
    enc_ver: int = 4,
    force_firmware: bool = False,
) -> Path:
    in_path = Path(in_file).expanduser()
    out_path = Path(out_file).expanduser()
    if not in_path.is_file():
        raise FileNotFoundError(in_path)
    length = in_path.stat().st_size
    if length % 16 != 0:
        raise FUSError("invalid encrypted input size")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if int(enc_ver) == 4:
        key = get_v4_key(model, region, firmware_version=version, force_firmware=force_firmware)
    else:
        if not str(version or "").strip():
            raise ValueError("firmware version is required for enc2 decrypt")
        key = get_v2_key(str(version), model, region)

    ranges = _build_range_parts(length, part_count=_DECRYPT_THREADS)
    with out_path.open("wb") as fh:
        fh.truncate(length)

    done = 0
    done_lock = threading.Lock()
    started_at = time.monotonic()

    def worker(item: dict[str, int]) -> None:
        nonlocal done
        _decrypt_range(in_path, out_path, key, int(item["start"]), int(item["end"]))
        with done_lock:
            done += int(item["end"]) - int(item["start"]) + 1

    with ThreadPoolExecutor(max_workers=len(ranges) or 1) as executor:
        futures = [executor.submit(worker, item) for item in ranges]
        while True:
            completed = all(future.done() for future in futures)
            with done_lock:
                current_done = done
            _render_progress("Decrypting", current_done, length, started_at, complete=completed and current_done >= length)
            if completed:
                for future in futures:
                    future.result()
                break
            time.sleep(_PROGRESS_REFRESH_S)

    _finalize_decrypted_file(out_path)
    return out_path


def _download_output_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
    auto_decrypt: bool,
) -> Path:
    if out_file:
        path = Path(out_file).expanduser()
    else:
        path = Path(out_dir or ".").expanduser() / filename
    return decrypted_output_path(path) if auto_decrypt else path


def _encrypted_target_path(
    *,
    filename: str,
    out_dir: str | os.PathLike[str] | None,
    out_file: str | os.PathLike[str] | None,
) -> Path:
    if out_file:
        out_path = Path(out_file).expanduser()
        if out_path.suffix.lower() in {".enc2", ".enc4"}:
            return out_path
        return out_path.with_name(f"{out_path.name}.enc4")
    return Path(out_dir or ".").expanduser() / filename


def _finalize_stream_decrypted_file(part_path: Path, final_path: Path) -> Path:
    if not part_path.is_file():
        raise FileNotFoundError(part_path)
    with part_path.open("r+b") as fh:
        if fh.seek(0, os.SEEK_END) <= 0:
            raise FUSError(f"partial file is empty: {part_path}")
        fh.seek(-16, os.SEEK_END)
        tail = fh.read(16)
        final_size = fh.tell() - len(tail) + len(_pkcs7_unpad(tail))
        fh.truncate(final_size)
    if final_path.exists():
        final_path.unlink()
    part_path.replace(final_path)
    return final_path


def _download_ranges_parallel(
    *,
    client: FUSClient,
    remote_path: str,
    out_path: Path,
    total_size: int,
    ranges: list[dict[str, int]],
    decrypt_key: bytes | None = None,
) -> None:
    state_lock = threading.Lock()
    stop_event = threading.Event()
    errors: list[BaseException] = []
    started_at = time.monotonic()
    last_meta_save = 0.0
    samples: deque[tuple[float, int]] = deque()
    meta_path = _resume_state_path(out_path)

    def worker(range_idx: int) -> None:
        segment = ranges[range_idx]
        seg_end = int(segment["end"])
        cipher = AES.new(decrypt_key, AES.MODE_ECB) if decrypt_key is not None else None
        pending = b""
        with out_path.open("r+b", buffering=0) as fh:
            while not stop_event.is_set():
                with state_lock:
                    write_offset = int(segment["offset"])
                request_start = write_offset + len(pending)
                if request_start > seg_end:
                    if pending:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} ended with a partial encrypted block"))
                    return
                response: requests.Response | None = None
                try:
                    response = client.download_file(remote_path, start=request_start, end=seg_end)
                    fh.seek(write_offset)
                    for chunk in response.iter_content(chunk_size=_RANGE_CHUNK_SIZE):
                        if stop_event.is_set():
                            return
                        if not chunk:
                            continue
                        if cipher is None:
                            fh.write(chunk)
                            write_offset += len(chunk)
                        else:
                            pending += chunk
                            block_size = (len(pending) // 16) * 16
                            if block_size:
                                block = pending[:block_size]
                                pending = pending[block_size:]
                                plain = cipher.decrypt(block)
                                fh.write(plain)
                                write_offset += len(plain)
                        with state_lock:
                            segment["offset"] = write_offset
                    if pending:
                        raise FUSError(f"range {range_idx + 1} ended with a partial encrypted block")
                    if write_offset != seg_end + 1:
                        raise FUSError(f"range {range_idx + 1} incomplete: expected {seg_end + 1}, got {write_offset}")
                    return
                except (requests.RequestException, OSError) as exc:
                    attempt = int(segment.get("attempts", 0)) + 1
                    segment["attempts"] = attempt
                    if attempt > _DOWNLOAD_RETRIES:
                        stop_event.set()
                        with state_lock:
                            errors.append(FUSError(f"range {range_idx + 1} failed after retries: {exc}"))
                        return
                    time.sleep(_RETRY_BACKOFF_S * attempt)
                except BaseException as exc:
                    stop_event.set()
                    with state_lock:
                        errors.append(exc)
                    return
                finally:
                    if response is not None:
                        response.close()

    threads = [threading.Thread(target=worker, args=(idx,), daemon=True) for idx in range(len(ranges))]
    for thread in threads:
        thread.start()
        time.sleep(_THREAD_STAGGER_S)

    try:
        while any(thread.is_alive() for thread in threads):
            now = time.monotonic()
            with state_lock:
                done = _resume_done_bytes(ranges)
                err = errors[0] if errors else None
                snapshot = [dict(item) for item in ranges]
            samples.append((now, done))
            while len(samples) >= 2 and now - samples[0][0] > _SPEED_WINDOW_S:
                samples.popleft()
            _render_progress("Downloading", done, total_size, started_at, complete=False)
            if now - last_meta_save >= 0.25:
                _save_range_resume_state(meta_path, total_size, snapshot)
                last_meta_save = now
            if err is not None:
                break
            time.sleep(_PROGRESS_REFRESH_S)
    finally:
        stop_event.set()
        for thread in threads:
            thread.join()

    with state_lock:
        done = _resume_done_bytes(ranges)
        err = errors[0] if errors else None
        snapshot = [dict(item) for item in ranges]
    _save_range_resume_state(meta_path, total_size, snapshot)
    _render_progress("Downloading", done, total_size, started_at, complete=err is None and done >= total_size)
    if err is not None:
        raise err
    if done != total_size:
        raise FUSError(f"incomplete download: expected {total_size} bytes, received {done}")


def download_firmware(
    *,
    model: str,
    region: str,
    firmware_version: str | None = None,
    force_firmware: bool = False,
    out_dir: str | os.PathLike[str] | None = None,
    out_file: str | os.PathLike[str] | None = None,
    resume: bool = False,
    auto_decrypt: bool = False,
) -> DownloadResult:
    model_u = str(model or "").strip().upper()
    region_u = str(region or "").strip().upper()
    if not model_u or not region_u:
        raise ValueError("model and region are required")

    client = FUSClient()
    info = _resolve_versioned_info(client, model_u, region_u, str(firmware_version) if force_firmware else None)
    firmware = info.binary_version or ""
    if not firmware:
        raise FUSError("FUS did not return a firmware version")

    final_path = _download_output_path(
        filename=info.filename,
        out_dir=out_dir,
        out_file=out_file,
        auto_decrypt=auto_decrypt,
    )
    encrypted_path = _encrypted_target_path(filename=info.filename, out_dir=out_dir, out_file=out_file)
    temp_path = _partial_output_path(final_path) if auto_decrypt else encrypted_path
    final_path.parent.mkdir(parents=True, exist_ok=True)

    if final_path.exists() and auto_decrypt:
        raise FUSError(f"{final_path} already exists")
    if encrypted_path.exists() and not auto_decrypt and not resume:
        raise FUSError(f"{encrypted_path} already exists, use --resume or choose another output")

    ranges, meta_path = _prepare_range_resume_state(temp_path, info.size, resume)
    done_before = _resume_done_bytes(ranges)

    initialize_download(client, info, region_u)
    remote_path = f"{info.model_path}{info.filename}"
    _print_info(f"model: {model_u}")
    _print_info(f"region: {region_u}")
    _print_info(f"firmware: {firmware}")
    _print_info(f"filename: {info.filename}")
    _print_info(f"size: {_format_bytes(info.size)}")
    _print_info(f"output: {final_path if auto_decrypt else temp_path}")
    if done_before:
        _print_info(f"resume: {_format_bytes(done_before)}")

    if not auto_decrypt:
        if done_before < info.size:
            _download_ranges_parallel(
                client=client,
                remote_path=remote_path,
                out_path=temp_path,
                total_size=info.size,
                ranges=ranges,
            )
        meta_path.unlink(missing_ok=True)
        return DownloadResult(temp_path, None, firmware, info.filename, info.size)

    decrypt_key = (
        get_v2_key(firmware, model_u, region_u)
        if info.filename.lower().endswith(".enc2")
        else get_v4_key(model_u, region_u, firmware_version=firmware, force_firmware=force_firmware)
    )
    if done_before < info.size:
        _download_ranges_parallel(
            client=client,
            remote_path=remote_path,
            out_path=temp_path,
            total_size=info.size,
            ranges=ranges,
            decrypt_key=decrypt_key,
        )
    meta_path.unlink(missing_ok=True)
    final_stream_path = _finalize_stream_decrypted_file(temp_path, final_path)
    return DownloadResult(encrypted_path, final_stream_path, firmware, info.filename, info.size)
