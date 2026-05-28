#!/usr/bin/env python3
"""Upload WazuhHound custom node icons to BloodHound CE.

Uses POST /api/v2/custom-nodes with font-awesome icon definitions.
Removes any existing WazuhHound (WZ_*) custom node entries before uploading.

WARNING: removes existing custom node types returned by BloodHound before
uploading custom_types.json. Use carefully on shared instances.
"""

import argparse
import json
import logging
import os
import sys
from typing import Optional, List
from urllib.parse import quote

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def login(base_url, username, secret, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    try:
        resp = requests.post(
            api_url,
            json={"login_method": "secret", "username": username, "secret": secret},
            timeout=timeout,
            verify=verify,
        )
        if not (200 <= resp.status_code < 300):
            logger.error(f"Login failed: HTTP {resp.status_code}")
            return None
        data = resp.json()
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None
    token = data.get("data", {}).get("session_token")
    if data.get("data", {}).get("auth_expired", False) or not token:
        logger.error("Login failed: credentials expired or invalid.")
        return None
    logger.info("Login succeeded.")
    return token


def list_custom_nodes(base_url, token, timeout, verify) -> Optional[List[str]]:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        resp = requests.get(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"GET custom-nodes failed: HTTP {resp.status_code} - {resp.text[:200]}")
            return None
        items = resp.json().get("data", [])
        return [item["kindName"] for item in items if item.get("kindName")]
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


def delete_custom_node(base_url, token, kind, timeout, verify) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes/{quote(kind, safe='')}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(api_url, headers=headers, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def upload_custom_icons(base_url, token, payload, timeout, verify) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/custom-nodes"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "wait=0",
    }
    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"Upload failed: HTTP {resp.status_code} - {resp.text[:300]}")
            return False
        return True
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Upload WazuhHound custom node icons to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or BLOODHOUND_SECRET)")
    parser.add_argument("--file", default="custom_types.json", help="Icon definitions file (default: custom_types.json)")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    url = args.url or os.getenv("BLOODHOUND_URL")
    username = args.username or os.getenv("BLOODHOUND_USERNAME")
    secret = args.secret or os.getenv("BLOODHOUND_SECRET")
    verify = not args.insecure

    if not url or not username or not secret:
        logger.error("Missing credentials. Provide --url/--username/--secret or set env vars.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    if "custom_types" not in payload:
        print(f"[!] {args.file} must contain a top-level 'custom_types' key.")
        sys.exit(1)

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    existing = list_custom_nodes(url, token, timeout=args.timeout, verify=verify)
    if existing is None:
        sys.exit(1)

    wz_existing = [k for k in existing if k.startswith("WZ_")]
    if wz_existing:
        logger.info(f"Removing existing WazuhHound node types: {', '.join(wz_existing)}")
        for kind in wz_existing:
            if not delete_custom_node(url, token, kind, timeout=args.timeout, verify=verify):
                logger.error(f"Failed to delete: {kind}")
                sys.exit(1)

    ok = upload_custom_icons(url, token, payload, timeout=args.timeout, verify=verify)
    if ok:
        kinds = list(payload["custom_types"].keys())
        print(f"[+] Uploaded {len(kinds)} custom node types: {', '.join(kinds)}")
    else:
        print("[!] Upload failed.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
