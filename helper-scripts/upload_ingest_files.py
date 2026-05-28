#!/usr/bin/env python3
"""Upload WazuhHound JSON output files to BloodHound CE for ingest."""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

JOB_STATUS_NAMES = {
    -1: "invalid",
    0: "ready",
    1: "running",
    2: "complete",
    3: "canceled",
    4: "timed out",
    5: "failed",
    6: "ingesting",
    7: "analyzing",
    8: "partially complete",
}
TERMINAL_JOB_STATUSES = {2, 3, 4, 5, 8}
SUCCESS_JOB_STATUSES = {2}


def login(base_url, username, secret, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/login"
    try:
        logger.info(f"Authenticating to BloodHound at {base_url.rstrip('/')}")
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


def start_upload_job(base_url, token, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/start"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "Prefer": "wait=30"}
    try:
        logger.info("Starting BloodHound file upload job")
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"Start job failed: HTTP {resp.status_code} - {resp.text[:200]}")
            return None
        job_id = resp.json().get("data", {}).get("id")
        if not isinstance(job_id, int):
            logger.error("No job id in response.")
            return None
        logger.info(f"Started upload job {job_id}.")
        return job_id
    except Exception as e:
        logger.error(f"Request error: {e}")
        return None


def upload_file(base_url, token, job_id, path, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/plain",
        "Content-Type": "application/json",
        "Prefer": "wait=30",
        "X-File-Upload-Name": path.name,
    }
    try:
        logger.info(f"Uploading {path.name}")
        with path.open("rb") as fh:
            resp = requests.post(api_url, headers=headers, data=fh, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"Upload failed: HTTP {resp.status_code} - {resp.text[:200]}")
            return False
        logger.info(f"Uploaded {path.name}.")
        return True
    except Exception as e:
        logger.error(f"Error: {e}")
        return False


def end_upload_job(base_url, token, job_id, timeout, verify):
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload/{job_id}/end"
    headers = {"Authorization": f"Bearer {token}", "Accept": "text/plain", "Prefer": "wait=30"}
    try:
        resp = requests.post(api_url, headers=headers, timeout=timeout, verify=verify)
        if not (200 <= resp.status_code < 300):
            logger.error(f"End job failed: HTTP {resp.status_code} - {resp.text[:200]}")
            return False
        logger.info("Upload job ended.")
        return True
    except Exception as e:
        logger.error(f"Request error: {e}")
        return False


def poll_job(base_url, token, job_id, timeout, verify, poll_interval, poll_timeout):
    api_url = f"{base_url.rstrip('/')}/api/v2/file-upload"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    deadline = time.monotonic() + poll_timeout if poll_timeout > 0 else None

    print(f"Waiting for ingest job {job_id}...", flush=True)
    while True:
        try:
            resp = requests.get(api_url, headers=headers, params={"id": f"eq:{job_id}", "limit": 1}, timeout=timeout, verify=verify)
            if not (200 <= resp.status_code < 300):
                logger.error(f"Status check failed: HTTP {resp.status_code}")
                return False
            jobs = resp.json().get("data", [])
            job = next((j for j in jobs if isinstance(j, dict) and j.get("id") == job_id), None)
            if not job:
                logger.error(f"Job {job_id} not found in status response.")
                return False
        except Exception as e:
            logger.error(f"Request error: {e}")
            return False

        status = job.get("status")
        status_name = JOB_STATUS_NAMES.get(status, f"unknown ({status})")
        failed = job.get("failed_files", 0)
        total = job.get("total_files", "?")
        print(f"  Job {job_id}: {status_name} (files: {total}, failed: {failed})", flush=True)

        if status in TERMINAL_JOB_STATUSES:
            if status in SUCCESS_JOB_STATUSES and failed == 0:
                print(f"[+] Ingest complete.")
                return True
            print(f"[!] Ingest finished with errors (status: {status_name}).")
            return False

        if deadline and time.monotonic() >= deadline:
            logger.error(f"Timed out waiting for job {job_id}.")
            return False

        time.sleep(poll_interval)


def main():
    parser = argparse.ArgumentParser(
        description="Upload WazuhHound JSON files to BloodHound CE",
        epilog="Example: python3 upload_ingest_files.py --url http://localhost:8080 --username admin --secret xxx ./output/wazuhhound_*.json",
    )
    parser.add_argument("files", nargs="+", help="WazuhHound JSON file(s) to upload")
    parser.add_argument("--url", help="BloodHound base URL (or BLOODHOUND_URL)")
    parser.add_argument("--username", help="Username (or BLOODHOUND_USERNAME)")
    parser.add_argument("--secret", help="Password/secret (or BLOODHOUND_SECRET)")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--poll-timeout", type=int, default=0, help="0 = wait forever")
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

    paths = []
    for raw in args.files:
        p = Path(raw).expanduser()
        if not p.is_file():
            print(f"[!] Not a file: {raw}")
            sys.exit(1)
        if p.suffix.lower() != ".json":
            print(f"[!] Not a JSON file: {raw}")
            sys.exit(1)
        paths.append(p)

    token = login(url, username, secret, timeout=args.timeout, verify=verify)
    if not token:
        sys.exit(1)

    job_id = start_upload_job(url, token, timeout=args.timeout, verify=verify)
    if job_id is None:
        sys.exit(1)

    for path in paths:
        if not upload_file(url, token, job_id, path, timeout=args.timeout, verify=verify):
            logger.error(f"Job {job_id} aborted - file upload failed.")
            sys.exit(1)

    if not end_upload_job(url, token, job_id, timeout=args.timeout, verify=verify):
        sys.exit(1)

    ok = poll_job(url, token, job_id, timeout=args.timeout, verify=verify,
                  poll_interval=args.poll_interval, poll_timeout=args.poll_timeout)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
