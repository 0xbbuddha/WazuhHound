#!/usr/bin/env python3
"""Upload WazuhHound schema to BloodHound CE.

Automatically enables the opengraph_extension_management feature flag
if it is not already active before uploading the schema.
"""

import argparse
import json
import logging
import os
import sys
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

FEATURE_FLAG_NAME = "opengraph_extension_management"


def login(base_url, username, secret, timeout, verify) -> Optional[str]:
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
    return token


def get_feature_flags(base_url, token, timeout, verify) -> Optional[list]:
    api_url = f"{base_url.rstrip('/')}/api/v2/features"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        resp = requests.get(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"GET /api/v2/features failed: HTTP {resp.status_code}")
            return None
        return resp.json().get("data", [])
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


def toggle_feature_flag(base_url, token, flag_id, timeout, verify) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/features/{flag_id}/toggle"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        resp = requests.put(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"Toggle flag failed: HTTP {resp.status_code} - {resp.text[:200]}")
            return False
        return True
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def ensure_opengraph_flag_enabled(base_url, token, timeout, verify) -> bool:
    """Enable opengraph_extension_management if not already on. Returns True if ready."""
    flags = get_feature_flags(base_url, token, timeout, verify)
    if flags is None:
        return False

    for flag in flags:
        if flag.get("key") == FEATURE_FLAG_NAME:
            flag_id = flag.get("id")
            enabled = flag.get("enabled", False)
            if enabled:
                logger.info(f"Feature flag '{FEATURE_FLAG_NAME}' already enabled.")
                return True
            print(f"[*] Enabling feature flag '{FEATURE_FLAG_NAME}' (id={flag_id})...")
            if not toggle_feature_flag(base_url, token, flag_id, timeout, verify):
                print(f"[!] Failed to enable feature flag '{FEATURE_FLAG_NAME}'.")
                return False
            print(f"[+] Feature flag '{FEATURE_FLAG_NAME}' enabled.")
            return True

    logger.error(f"Feature flag '{FEATURE_FLAG_NAME}' not found in BloodHound CE.")
    return False


def upload_schema(base_url, token, payload, timeout, verify) -> bool:
    api_url = f"{base_url.rstrip('/')}/api/v2/extensions"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Prefer": "wait=0",
    }
    try:
        resp = requests.put(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            print(f"[!] HTTP {resp.status_code}: {resp.text[:500]}")
            return False
        return True
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Upload WazuhHound schema to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or BLOODHOUND_SECRET)")
    parser.add_argument("--file", default="schema.json", help="Schema file (default: schema.json)")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s")

    url = args.url or os.getenv("BLOODHOUND_URL")
    username = args.username or os.getenv("BLOODHOUND_USERNAME")
    secret = args.secret or os.getenv("BLOODHOUND_SECRET")
    verify = not args.insecure

    if not url or not username or not secret:
        logger.error("Missing credentials. Provide --url/--username/--secret or set env vars.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        payload = json.load(f)

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    if not ensure_opengraph_flag_enabled(url, token, timeout=args.timeout, verify=verify):
        sys.exit(1)

    ok = upload_schema(url, token, payload, timeout=args.timeout, verify=verify)
    if ok:
        print("[+] Schema uploaded successfully.")
    else:
        print("[!] Schema upload failed.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
