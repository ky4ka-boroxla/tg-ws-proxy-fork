"""Check against GitHub Releases."""
from __future__ import annotations

import json
import logging
import re
from http.client import HTTPException
from itertools import zip_longest
from typing import Any, Dict
from urllib.request import Request

from proxy.utils import build_github_opener

REPO = "ky4ka-boroxla/tg-ws-proxy-fork"
RELEASES_LATEST_API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE_URL = f"https://github.com/{REPO}/releases/latest"

_SHA256 = re.compile(r"sha256:([0-9a-f]{64})", re.IGNORECASE)
_state: Dict[str, Any] = {
    "checked": False,
    "has_update": False,
    "ahead_of_release": False,
    "latest": None,
    "html_url": RELEASES_PAGE_URL,
    "error": None,
    "assets": [],
}


def _parse_version_tuple(s: str) -> tuple:
    parts = []
    for part in (s or "").strip().lstrip("vV").split("."):
        match = re.match(r"\d+", part)
        parts.append(int(match[0]) if match else 0)
    return tuple(parts)


def _version_gt(a: str, b: str) -> bool:
    for x, y in zip_longest(_parse_version_tuple(a), _parse_version_tuple(b), fillvalue=0):
        if x != y:
            return x > y
    return False


def fetch_latest_release(timeout: float = 12.0) -> dict:
    req = Request(RELEASES_LATEST_API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "tg-ws-proxy-update-check",
    })
    with build_github_opener().open(req, timeout=timeout) as resp:
        return json.load(resp)


def _extract_assets(data: dict) -> list:
    assets = (data or {}).get("assets") or []
    if not isinstance(assets, list):
        raise ValueError("Invalid release assets from GitHub")
    return [
        {"name": a["name"], "url": a["browser_download_url"],
         "digest": a.get("digest") if isinstance(a.get("digest"), str) else ""}
        for a in assets
        if isinstance(a, dict) and isinstance(a.get("name"), str) and a["name"]
        and isinstance(a.get("browser_download_url"), str) and a["browser_download_url"]
    ]


def run_check(current_version: str) -> None:
    """Publish the complete result at once; no persistent cache or error cooldown."""
    global _state
    state = {
        "checked": True, "has_update": False, "ahead_of_release": False,
        "latest": None, "html_url": RELEASES_PAGE_URL, "error": None, "assets": [],
    }
    try:
        data = fetch_latest_release()
        if not isinstance(data, dict) or not isinstance(data.get("tag_name"), str):
            raise ValueError("Invalid release from GitHub")
        latest = data["tag_name"].strip().lstrip("vV")
        if not latest or not latest[0].isdigit():
            raise ValueError("Invalid release version from GitHub")
        state.update(
            latest=latest,
            has_update=_version_gt(latest, current_version),
            ahead_of_release=_version_gt(current_version, latest),
            html_url=data.get("html_url") or RELEASES_PAGE_URL,
            assets=_extract_assets(data),
        )
    except (OSError, ValueError, HTTPException) as exc:
        state["error"] = str(exc) or type(exc).__name__
        logging.getLogger(__name__).warning("Update check failed: %s", exc)
    _state = state


def get_status() -> Dict[str, Any]:
    state = _state
    return {**state, "assets": [dict(a) for a in state["assets"]]}
