#!/usr/bin/env python3
"""Sync saved Cypher queries to BloodHound CE."""

import argparse
import glob
import json
import logging
import os
import sys
from typing import List, Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


def login(base_url, username, secret, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    body = {"login_method": "secret", "username": username, "secret": secret}
    try:
        resp = requests.post(api_url, json=body, timeout=timeout, verify=verify)
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


def list_saved_queries(base_url, token, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    try:
        resp = requests.get(api_url, headers=headers, params={"scope": "owned"}, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            return None
        return resp.json().get("data", [])
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


def delete_saved_query(base_url, token, query_id, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries/{query_id}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.delete(api_url, headers=headers, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def load_saved_queries(folder):
    payloads = []
    for path in sorted(glob.glob(os.path.join(folder, "*.json"))):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data.get("name") or not data.get("query"):
            raise SystemExit(f"[!] {path} requires 'name' and 'query'")
        payloads.append({"name": data["name"], "query": data["query"]})
    return payloads


def create_saved_query(base_url, token, payload, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/saved-queries"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"}
    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout, verify=verify)
        return 200 <= resp.status_code < 300
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Sync saved Cypher queries to BloodHound CE")
    parser.add_argument("--url", help="BloodHound base URL (or BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or BLOODHOUND_SECRET)")
    parser.add_argument("--folder", default="SavedQueries", help="Queries folder (default: SavedQueries)")
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

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    existing = list_saved_queries(url, token, timeout=args.timeout, verify=verify)
    for item in (existing or []):
        if item.get("id"):
            delete_saved_query(url, token, item["id"], timeout=args.timeout, verify=verify)

    payloads = load_saved_queries(args.folder)
    if not payloads:
        logger.error(f"No saved queries found in: {args.folder}")
        sys.exit(1)

    for payload in payloads:
        if not create_saved_query(url, token, payload, timeout=args.timeout, verify=verify):
            logger.error(f"Failed to create: {payload['name']}")
            sys.exit(1)
        logger.info(f"Uploaded: {payload['name']}")

    print(f"[+] {len(payloads)} queries uploaded.")


if __name__ == "__main__":
    main()
