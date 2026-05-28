import argparse
import datetime
import json
import logging
import os
import sys
import time
from typing import Optional

import requests
from dotenv import load_dotenv

from .collector import WazuhCollector
from .ingestor import WazuhIngestor
from .names import apply_bloodhound_names, wz_kind


def _env_value(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return None


def _arg_or_env(value: Optional[str], *names: str) -> Optional[str]:
    if value is not None and value != "":
        return value
    return _env_value(*names)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _apply_env_defaults(args) -> None:
    args.wazuh_url = _arg_or_env(args.wazuh_url, "WAZUH_URL")
    args.wazuh_user = _arg_or_env(args.wazuh_user, "WAZUH_USERNAME")
    args.wazuh_password = _arg_or_env(args.wazuh_password, "WAZUH_PASSWORD")
    args.output = _arg_or_env(args.output, "WAZUHHOUND_OUTPUT")
    args.insecure = args.insecure or _env_bool("WAZUHHOUND_INSECURE")
    args.verbose = args.verbose or _env_bool("WAZUHHOUND_VERBOSE")
    args.debug = args.debug or _env_bool("WAZUHHOUND_DEBUG")
    args.skip_enrichment = args.skip_enrichment or _env_bool("WAZUHHOUND_SKIP_ENRICHMENT")
    args.indexer_url = _arg_or_env(args.indexer_url, "WAZUH_INDEXER_URL")
    args.indexer_user = _arg_or_env(args.indexer_user, "WAZUH_INDEXER_USER")
    args.indexer_password = _arg_or_env(args.indexer_password, "WAZUH_INDEXER_PASSWORD")


def _validate_args(args, logger: logging.Logger) -> bool:
    missing = []
    if not args.wazuh_url:
        missing.append("--wazuh-url (or WAZUH_URL)")
    if not args.wazuh_user:
        missing.append("--wazuh-user (or WAZUH_USERNAME)")
    if not args.wazuh_password:
        missing.append("--wazuh-password (or WAZUH_PASSWORD)")
    if not args.output:
        missing.append("--output (or WAZUHHOUND_OUTPUT)")

    if missing:
        logger.error("Missing required configuration:")
        for item in missing:
            logger.error(f"  {item}")
        return False
    return True


def _ensure_output_dir(path: str) -> str:
    output_dir = os.path.abspath(os.path.expanduser(path))
    os.makedirs(output_dir, exist_ok=True)
    if not os.path.isdir(output_dir):
        raise OSError(f"Output path is not a directory: {output_dir}")
    return output_dir


def main() -> int:
    load_dotenv()

    logger = logging.getLogger()
    stream = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    parser = argparse.ArgumentParser(
        description="WazuhHound - BloodHound CE collector for Wazuh",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wazuhhound --wazuh-url https://wazuh.local:55000 --wazuh-user admin --wazuh-password secret --output ./output
  wazuhhound --insecure --output ./output   # reads credentials from .env
        """,
    )
    parser.add_argument("--wazuh-url", type=str, help="Wazuh manager URL (env: WAZUH_URL)")
    parser.add_argument("--wazuh-user", type=str, help="Wazuh API username (env: WAZUH_USERNAME)")
    parser.add_argument("--wazuh-password", type=str, help="Wazuh API password (env: WAZUH_PASSWORD)")
    parser.add_argument("--output", type=str, help="Output directory for JSON files (env: WAZUHHOUND_OUTPUT)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (env: WAZUHHOUND_INSECURE)")
    parser.add_argument("--verbose", action="store_true", help="Enable informational logging (env: WAZUHHOUND_VERBOSE)")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging (may log sensitive data) (env: WAZUHHOUND_DEBUG)",
    )

    parser.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip per-agent enrichment (vulns, ports, packages, network segments) - faster collection (env: WAZUHHOUND_SKIP_ENRICHMENT)",
    )

    indexer_group = parser.add_argument_group("Wazuh Indexer (OpenSearch) - internal users")
    indexer_group.add_argument("--indexer-url", type=str, help="Indexer URL, e.g. https://wazuh:9200 (env: WAZUH_INDEXER_URL, defaults to manager host on port 9200)")
    indexer_group.add_argument("--indexer-user", type=str, help="Indexer admin username (env: WAZUH_INDEXER_USER, defaults to --wazuh-user)")
    indexer_group.add_argument("--indexer-password", type=str, help="Indexer admin password (env: WAZUH_INDEXER_PASSWORD, defaults to --wazuh-password)")

    args = parser.parse_args()
    _apply_env_defaults(args)

    log_level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logger.setLevel(log_level)
    stream.setLevel(log_level)

    if args.debug:
        logger.warning("Debug logging enabled - may include sensitive API response bodies.")

    if not _validate_args(args, logger):
        return 1

    try:
        args.output = _ensure_output_dir(args.output)
    except OSError as exc:
        logger.error(f"Failed to prepare output directory: {exc}")
        return 1

    logger.info("Starting WazuhHound...")

    collector = WazuhCollector(
        url=args.wazuh_url,
        username=args.wazuh_user,
        password=args.wazuh_password,
        verify=not args.insecure,
    )

    env = collector.collect(
        indexer_url=args.indexer_url,
        indexer_user=args.indexer_user,
        indexer_password=args.indexer_password,
        skip_enrichment=args.skip_enrichment,
    )
    if not env:
        print("[!] Collection failed.")
        return 1

    print(f"[+] Collected:")
    print(f"    Agents   : {len(env.agents)}")
    print(f"    Groups   : {len(env.groups)}")
    if env.cluster:
        mode = "standalone" if env.cluster.standalone else "cluster"
        print(f"    Cluster  : {env.cluster.name} ({len(env.cluster.nodes)} node(s), {mode})")
    if env.indexer_cluster:
        print(f"    Indexer  : {env.indexer_cluster.name} ({len(env.indexer_cluster.nodes)} node(s))")
    else:
        print(f"    Indexer  : not found (check 'indexer:read' permission)")
    print(f"    Users    : {len(env.security_users)} (manager API)")
    print(f"    Roles    : {len(env.security_roles)}")
    print(f"    Policies : {len(env.security_policies)}")
    if env.indexer_users:
        print(f"    Idx Users: {len(env.indexer_users)} (indexer internal)")
    else:
        print(f"    Idx Users: 0 (use --indexer-url/--indexer-user/--indexer-password)")
    if env.network_segments:
        print(f"    Segments : {len(env.network_segments)} network segment(s)")
    if not args.skip_enrichment:
        enriched = sum(1 for a in env.agents if a.vuln_total > 0)
        pkgs = sum(a.packages_total for a in env.agents)
        if enriched:
            print(f"    Vulns    : {enriched} agent(s) with vulnerabilities")
        if pkgs:
            print(f"    Packages : {pkgs} total across all agents")

    print("[*] Building OpenGraph...")
    ingestor = WazuhIngestor(env)
    og = ingestor.ingest()

    og_dict = og.export_to_dict()
    og_dict = apply_bloodhound_names(og_dict)

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(args.output, f"wazuhhound_{timestamp}.json")

    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(og_dict, fh, indent=2)

    graph = og_dict.get("graph", og_dict)
    node_count = len(graph.get("nodes", []))
    edge_count = len(graph.get("edges", []))

    print(f"[+] OpenGraph exported:")
    print(f"    Nodes : {node_count}")
    print(f"    Edges : {edge_count}")
    print(f"    File  : {output_file}")
    print()
    print("Upload to BloodHound CE and query with:")
    print(f"  MATCH (n:{wz_kind('Agent')}) RETURN n")
    print(f"  MATCH (n:{wz_kind('Agent')})-[:{wz_kind('MemberOf')}]->(g:{wz_kind('AgentGroup')}) RETURN n, g")
    return 0
