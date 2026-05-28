#!/usr/bin/env python3
"""Delete all WazuhHound nodes and edges from BloodHound CE."""

import argparse
import json
import logging
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

WZ_KINDS = ["WZ_Agent", "WZ_AgentGroup", "WZ_Rule", "WZ_Decoder", "WZ_ClusterNode", "WZ_Cluster"]


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
            return None
        data = resp.json()
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None
    token = data.get("data", {}).get("session_token")
    if data.get("data", {}).get("auth_expired", True) or not token:
        logger.error("Login failed.")
        return None
    return token


def run_cypher(base_url, token, query, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/graphs/cypher"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(api_url, headers=headers, json={"query": query}, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Delete all WazuhHound nodes from BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or BLOODHOUND_SECRET)")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    url = args.url or os.getenv("BLOODHOUND_URL")
    username = args.username or os.getenv("BLOODHOUND_USERNAME")
    secret = args.secret or os.getenv("BLOODHOUND_SECRET")
    verify = not args.insecure

    if not url or not username or not secret:
        logger.error("Missing credentials.")
        sys.exit(1)

    if not args.yes:
        confirm = input(f"[?] Delete ALL WazuhHound nodes from {url}? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            sys.exit(0)

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    kinds_str = "|".join(WZ_KINDS)
    query = f"MATCH (n) WHERE any(k IN labels(n) WHERE k IN {json.dumps(WZ_KINDS)}) DETACH DELETE n"
    print(f"[*] Deleting WazuhHound nodes ({kinds_str})...")
    ok = run_cypher(url, token, query, timeout=args.timeout, verify=verify)
    if ok:
        print("[+] Done.")
    else:
        print("[!] Failed.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
