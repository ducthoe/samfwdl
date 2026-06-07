# Copyright (C) 2026 ducthoe
# SPDX-License-Identifier: GPL-3.0-only

from __future__ import annotations

_AUTH_AES_KEY = bytes.fromhex("422e73733617ae2b198940fd4e32b0a5")
_FUS_USER_AGENT = "SMART 2.0"
_FUS_BASE_URL = "https://neofussvr.sslcs.cdngc.net/"
_FUS_DOWNLOAD_URL = "http://cloud-neofussvr.samsungmobile.com/NF_SmartDownloadBinaryForMass.do"
_AUTH_SIGNATURE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_AUTH_NONCE_COUNT = "00000001"
_AES_BLOCK_SIZE = 16
_FUS_PLACEHOLDER = "." * _AES_BLOCK_SIZE
_PROGRESS_REFRESH_S = 0.1
_RESUME_META_SAVE_INTERVAL_S = 0.25
_RANGE_CHUNK_SIZE = 0x10000
_DOWNLOAD_RETRIES = 15
_DOWNLOAD_RECOVERY_INTERVAL = 3
_RETRY_BACKOFF_S = 0.75
_RATE_LIMIT_COOLDOWN_S = 6.0
_THREAD_STAGGER_S = 0.1
_LATEST_HISTORY_IGNORED_INDEXES = {"90"}
