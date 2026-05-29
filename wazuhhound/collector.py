import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import requests
import urllib3

from .models import (
    WazuhAgent,
    WazuhCluster,
    WazuhClusterNode,
    WazuhEnvironment,
    WazuhGroup,
    WazuhIndexerCluster,
    WazuhIndexerNode,
    WazuhIndexerRole,
    WazuhIndexerUser,
    WazuhNetworkSegment,
    WazuhRoleMapping,
    WazuhSecurityPolicy,
    WazuhSecurityRole,
    WazuhSecurityUser,
    compute_risk_score,
    ip_to_cidr,
)

DEFAULT_PAGE_SIZE = 500
DEFAULT_WORKERS = 10


class WazuhCollector:
    """Collects data from the Wazuh REST API and returns a WazuhEnvironment."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify: bool = True,
        timeout: int = 30,
    ):
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.token: Optional[str] = None
        self.logger = logging.getLogger(__name__)

        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> bool:
        url = f"{self.base_url}/security/user/authenticate"
        try:
            self.logger.debug(f"POST {url}")
            resp = requests.post(
                url,
                auth=(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify,
            )
            self.logger.debug(f"Status: {resp.status_code}")
            if not (200 <= resp.status_code < 300):
                self.logger.error(f"Authentication failed: HTTP {resp.status_code}")
                if resp.text:
                    self.logger.debug(f"Body: {resp.text}")
                return False
            data = resp.json()
            auth_data = data.get("data", {})
            if auth_data.get("auth_expired", False):
                self.logger.error("Authentication token expired.")
                return False
            self.token = auth_data.get("token")
            if not self.token:
                self.logger.error("Authentication succeeded but no token in response.")
                return False
            self.logger.info("Wazuh authentication successful.")
            return True
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Authentication request error: {e}")
            return False

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Generic paginated GET
    # ------------------------------------------------------------------

    def _get_all(self, path: str, key: str, extra_params: Optional[dict] = None) -> List[dict]:
        results = []
        offset = 0
        while True:
            url = f"{self.base_url}{path}"
            params: dict = {"limit": DEFAULT_PAGE_SIZE, "offset": offset}
            if extra_params:
                params.update(extra_params)
            try:
                self.logger.debug(f"GET {url} offset={offset}")
                resp = requests.get(
                    url,
                    headers=self._headers(),
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify,
                )
                if not (200 <= resp.status_code < 300):
                    self.logger.warning(f"GET {path} failed: HTTP {resp.status_code} - {resp.text[:200]}")
                    break
                data = resp.json()
                items = data.get("data", {}).get("affected_items", [])
                results.extend(items)
                total = data.get("data", {}).get("total_affected_items", len(results))
                offset += len(items)
                if offset >= total or not items:
                    break
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                self.logger.error(f"Error fetching {path}: {e}")
                break
        self.logger.info(f"Fetched {len(results)} {key}")
        return results

    def _get_one(self, path: str) -> Optional[dict]:
        url = f"{self.base_url}{path}"
        try:
            self.logger.debug(f"GET {url}")
            resp = requests.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(f"GET {path} failed: HTTP {resp.status_code} - {resp.text[:200]}")
                return None
            return resp.json()
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            self.logger.error(f"Error fetching {path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Group membership (agent_id -> [group_names])
    # ------------------------------------------------------------------

    def _get_group_memberships(self, group_names: List[str]) -> Dict[str, List[str]]:
        """For each group, fetch member agent IDs and build a reverse mapping."""
        memberships: Dict[str, List[str]] = {}
        for name in group_names:
            raw = self._get_all(f"/groups/{name}/agents", f"agents in group {name!r}")
            for item in raw:
                agent_id = str(item.get("id", ""))
                if agent_id:
                    memberships.setdefault(agent_id, []).append(name)
        return memberships

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def get_agents(self, group_memberships: Optional[Dict[str, List[str]]] = None) -> List[WazuhAgent]:
        raw = self._get_all("/agents", "agents")
        agents = []
        for item in raw:
            os_info = item.get("os") or {}

            # group field: try both singular and plural; fallback to membership dict
            groups_raw = item.get("group") or item.get("groups") or []
            if isinstance(groups_raw, str):
                groups_raw = [groups_raw]
            groups = list(groups_raw)

            agent_id = str(item.get("id", ""))

            # If the API didn't return group data, use membership dict from /groups/{name}/agents
            if not groups and group_memberships and agent_id:
                groups = group_memberships.get(agent_id, [])

            # manager field: try multiple field names
            manager = (
                item.get("manager")
                or item.get("managerName")
                or item.get("manager_name")
            )
            node_name = item.get("node_name") or item.get("nodeName")

            agents.append(
                WazuhAgent(
                    id=agent_id,
                    name=item.get("name", ""),
                    ip=item.get("ip"),
                    register_ip=item.get("registerIP"),
                    os_name=os_info.get("name"),
                    os_version=os_info.get("version"),
                    os_platform=os_info.get("platform"),
                    os_arch=os_info.get("arch"),
                    version=item.get("version"),
                    status=item.get("status"),
                    manager=manager,
                    node_name=node_name,
                    groups=groups,
                    last_keepalive=item.get("lastKeepAlive"),
                    date_add=item.get("dateAdd"),
                    merged_sum=item.get("mergedSum"),
                    config_sum=item.get("configSum"),
                )
            )
        return agents

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def get_groups(self) -> List[WazuhGroup]:
        raw = self._get_all("/groups", "groups")
        groups = []
        for item in raw:
            groups.append(
                WazuhGroup(
                    name=item.get("name", ""),
                    agent_count=item.get("count", 0),
                    config_sum=item.get("configSum"),
                    merged_sum=item.get("mergedSum"),
                )
            )
        return groups

    # ------------------------------------------------------------------
    # Cluster / Manager
    # ------------------------------------------------------------------

    def _is_cluster_enabled(self) -> bool:
        data = self._get_one("/cluster/status")
        if not data:
            return False
        return data.get("data", {}).get("enabled") == "yes"

    def get_cluster(self) -> Optional[WazuhCluster]:
        if not self._is_cluster_enabled():
            self.logger.info("Cluster mode disabled - collecting standalone manager info.")
            return self._get_standalone_cluster()

        raw = self._get_all("/cluster/nodes", "cluster nodes")
        if not raw:
            return self._get_standalone_cluster()

        nodes = []
        for item in raw:
            nodes.append(
                WazuhClusterNode(
                    name=item.get("name", ""),
                    type=item.get("type", "worker"),
                    ip=item.get("ip"),
                    version=item.get("version"),
                    status=item.get("status"),
                )
            )

        cluster_info = self._get_one("/cluster/local/info")
        cluster_name = "wazuh-cluster"
        if cluster_info:
            cluster_name = (
                cluster_info.get("data", {})
                .get("affected_items", [{}])[0]
                .get("cluster", cluster_name)
            )

        return WazuhCluster(name=cluster_name, nodes=nodes, standalone=False)

    def _get_standalone_cluster(self) -> WazuhCluster:
        """Return a single-node WazuhCluster for standalone (non-clustered) deployments."""
        data = self._get_one("/manager/info")
        manager_name = "wazuh-manager"
        manager_version = ""
        manager_ip = ""

        if data:
            items = data.get("data", {}).get("affected_items", [{}])
            if items:
                manager_name = items[0].get("name") or manager_name
                manager_version = items[0].get("version") or ""

        node = WazuhClusterNode(
            name=manager_name,
            type="standalone",
            ip=manager_ip,
            version=manager_version,
            status="active",
        )
        return WazuhCluster(name=manager_name, nodes=[node], standalone=True)

    # ------------------------------------------------------------------
    # Indexer
    # ------------------------------------------------------------------

    def get_indexer_cluster(
        self,
        indexer_url: Optional[str] = None,
        indexer_user: Optional[str] = None,
        indexer_password: Optional[str] = None,
    ) -> Optional[WazuhIndexerCluster]:
        # If direct indexer access is configured, prefer it over the Wazuh Manager proxy
        if indexer_url:
            result = self._get_indexer_cluster_direct(indexer_url, indexer_user, indexer_password)
            if result:
                return result
            self.logger.warning("Direct OpenSearch API failed; falling back to Wazuh Manager proxy.")

        # Try the Wazuh Manager API proxy (/indexer/nodes)
        raw = []
        for path in ["/indexer/nodes", "/wazuh-indexer/nodes"]:
            raw = self._get_all(path, "indexer nodes")
            if raw:
                break

        if not raw:
            self.logger.warning(
                "Indexer nodes not available. "
                "Use --indexer-url https://<host>:9200 --indexer-user admin --indexer-password <pw> "
                "for direct OpenSearch access, or ensure the Wazuh API user has 'indexer:read' permission."
            )
            return None

        nodes = []
        for item in raw:
            roles = item.get("roles") or []
            if isinstance(roles, str):
                roles = [r.strip() for r in roles.split(",") if r.strip()]
            nodes.append(
                WazuhIndexerNode(
                    name=item.get("name", ""),
                    roles=roles,
                    ip=item.get("ip") or item.get("host") or item.get("transport_address"),
                    version=item.get("version"),
                    status=item.get("status"),
                )
            )

        cluster_info = self._get_one("/indexer/clusters")
        cluster_name = "wazuh-indexer"
        if cluster_info:
            items = cluster_info.get("data", {}).get("affected_items", [{}])
            cluster_name = items[0].get("name", cluster_name) if items else cluster_name

        self.logger.info(f"Indexer cluster '{cluster_name}' with {len(nodes)} node(s).")
        return WazuhIndexerCluster(name=cluster_name, nodes=nodes)

    def _get_indexer_cluster_direct(
        self,
        indexer_url: str,
        indexer_user: Optional[str],
        indexer_password: Optional[str],
    ) -> Optional[WazuhIndexerCluster]:
        """Query the OpenSearch REST API directly for cluster and node info."""
        base = indexer_url.rstrip("/")
        auth = (indexer_user or self.username, indexer_password or self.password)

        try:
            # GET / - cluster identity
            resp = requests.get(
                f"{base}/",
                auth=auth,
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(
                    f"OpenSearch root endpoint failed: HTTP {resp.status_code}. "
                    "Check --indexer-url, --indexer-user, --indexer-password."
                )
                return None
            root = resp.json()
            cluster_name = root.get("cluster_name") or root.get("name") or "wazuh-indexer"

            # GET /_nodes - node list
            resp2 = requests.get(
                f"{base}/_nodes",
                auth=auth,
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp2.status_code < 300):
                self.logger.warning(f"OpenSearch /_nodes failed: HTTP {resp2.status_code}")
                return None

            nodes_data = resp2.json().get("nodes", {})
            nodes = []
            for node_id, info in nodes_data.items():
                roles = info.get("roles") or []
                if isinstance(roles, str):
                    roles = [r.strip() for r in roles.split(",") if r.strip()]
                transport = info.get("transport_address") or ""
                ip = transport.split(":")[0] if ":" in transport else transport
                nodes.append(
                    WazuhIndexerNode(
                        name=info.get("name", node_id),
                        roles=roles,
                        ip=ip or None,
                        version=info.get("version"),
                        status="green",
                    )
                )

            self.logger.info(f"Indexer cluster '{cluster_name}' with {len(nodes)} node(s) (direct).")
            return WazuhIndexerCluster(name=cluster_name, nodes=nodes)

        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.warning(f"Direct OpenSearch query failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Security (RBAC)
    # ------------------------------------------------------------------

    def get_security_users(self) -> List[WazuhSecurityUser]:
        raw = self._get_all("/security/users", "security users")

        # If the general endpoint returned nothing or very few users, also probe
        # the reserved user ID range (1-99) explicitly. Built-in Wazuh users
        # (wazuh, wazuh-wui, admin, …) live in that range and are often hidden
        # from the general listing when the calling account lacks full
        # security:read permissions.
        seen_ids = {item.get("id") for item in raw}
        reserved_ids = ",".join(str(i) for i in range(1, 100))
        reserved_raw = self._get_all(f"/security/users?user_ids={reserved_ids}", "reserved security users")
        for item in reserved_raw:
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                raw.append(item)

        if not raw:
            self.logger.warning(
                "No security users returned. Ensure your Wazuh user has "
                "'security:read' permission with resource 'user:id:*'. "
                "The built-in 'wazuh' admin user has this permission by default."
            )

        users = []
        for item in raw:
            role_ids = item.get("roles") or []
            if isinstance(role_ids, list):
                role_ids = [int(r) if not isinstance(r, int) else r for r in role_ids]
            users.append(
                WazuhSecurityUser(
                    id=item.get("id", 0),
                    username=item.get("username", ""),
                    allow_run_as=bool(item.get("allow_run_as", False)),
                    roles=role_ids,
                )
            )
        self.logger.info(f"Total security users collected: {len(users)}")
        return users

    def get_security_roles(self) -> List[WazuhSecurityRole]:
        raw = self._get_all("/security/roles", "security roles")

        seen_ids = {item.get("id") for item in raw}
        reserved_ids = ",".join(str(i) for i in range(1, 100))
        for item in self._get_all(f"/security/roles?role_ids={reserved_ids}", "reserved security roles"):
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                raw.append(item)

        roles = []
        for item in raw:
            policy_ids = item.get("policies") or []
            if isinstance(policy_ids, list):
                policy_ids = [int(p) if not isinstance(p, int) else p for p in policy_ids]
            roles.append(
                WazuhSecurityRole(
                    id=item.get("id", 0),
                    name=item.get("name", ""),
                    policies=policy_ids,
                )
            )
        self.logger.info(f"Total security roles collected: {len(roles)}")
        return roles

    def get_security_policies(self) -> List[WazuhSecurityPolicy]:
        raw = self._get_all("/security/policies", "security policies")

        seen_ids = {item.get("id") for item in raw}
        reserved_ids = ",".join(str(i) for i in range(1, 100))
        for item in self._get_all(f"/security/policies?policy_ids={reserved_ids}", "reserved security policies"):
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                raw.append(item)

        policies = []
        for item in raw:
            p = item.get("policy") or {}
            if not isinstance(p, dict):
                p = {}
            actions = p.get("actions") or []
            resources = p.get("resources") or []
            effect = p.get("effect") or ""
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            policies.append(
                WazuhSecurityPolicy(
                    id=item.get("id", 0),
                    name=item.get("name", ""),
                    actions=actions,
                    resources=resources,
                    effect=effect,
                )
            )
        self.logger.info(f"Total security policies collected: {len(policies)}")
        return policies

    # ------------------------------------------------------------------
    # Indexer internal users (OpenSearch Security API, port 9200)
    # ------------------------------------------------------------------

    def get_indexer_users(self, indexer_url: Optional[str] = None, indexer_user: Optional[str] = None, indexer_password: Optional[str] = None) -> List[WazuhIndexerUser]:
        """
        Fetch Wazuh Indexer internal users from the OpenSearch Security API.
        These users have direct access to raw log data in the indexer and are
        separate from the Wazuh Manager API users.

        Requires the indexer URL (default: manager host on port 9200) and
        admin credentials for the OpenSearch security API.
        """
        if not indexer_url:
            # Derive indexer URL from manager URL by swapping port to 9200
            try:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(self.base_url)
                indexer_url = urlunparse(parsed._replace(netloc=f"{parsed.hostname}:9200"))
            except Exception:
                self.logger.warning("Could not derive indexer URL from manager URL.")
                return []

        auth_user = indexer_user or self.username
        auth_pass = indexer_password or self.password

        url = f"{indexer_url.rstrip('/')}/_plugins/_security/api/internalusers"
        try:
            self.logger.debug(f"GET {url}")
            resp = requests.get(
                url,
                auth=(auth_user, auth_pass),
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(
                    f"Indexer security API failed: HTTP {resp.status_code}. "
                    "Ensure the indexer admin credentials are correct and the "
                    "OpenSearch security plugin is enabled."
                )
                return []

            data = resp.json()
            users = []
            for username, info in data.items():
                if not isinstance(info, dict):
                    continue
                backend_roles = info.get("backend_roles") or []
                if isinstance(backend_roles, str):
                    backend_roles = [backend_roles]
                users.append(
                    WazuhIndexerUser(
                        username=username,
                        backend_roles=backend_roles,
                        reserved=bool(info.get("reserved", False)),
                        hidden=bool(info.get("hidden", False)),
                        description=info.get("description") or "",
                    )
                )
            self.logger.info(f"Fetched {len(users)} indexer internal users.")
            return users

        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.warning(f"Failed to fetch indexer internal users: {e}")
            return []

    def get_indexer_roles(
        self,
        indexer_url: str,
        indexer_user: Optional[str],
        indexer_password: Optional[str],
    ) -> List[WazuhIndexerRole]:
        """Fetch OpenSearch roles and role mappings, resolve user assignments."""
        base = indexer_url.rstrip("/")
        auth = (indexer_user or self.username, indexer_password or self.password)

        roles: List[WazuhIndexerRole] = []
        try:
            resp = requests.get(
                f"{base}/_plugins/_security/api/roles",
                auth=auth,
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(f"OpenSearch roles API failed: HTTP {resp.status_code}")
                return []

            for name, info in resp.json().items():
                if not isinstance(info, dict):
                    continue
                if info.get("hidden"):
                    continue
                cluster_perms = info.get("cluster_permissions") or []
                index_perms = info.get("index_permissions") or []
                patterns: List[str] = []
                actions: List[str] = []
                for ip in index_perms:
                    if not isinstance(ip, dict):
                        continue
                    patterns.extend(ip.get("index_patterns") or [])
                    actions.extend(ip.get("allowed_actions") or [])
                roles.append(WazuhIndexerRole(
                    name=name,
                    cluster_permissions=cluster_perms,
                    index_patterns=list(set(patterns)),
                    allowed_actions=list(set(actions)),
                    reserved=bool(info.get("reserved", False)),
                    hidden=bool(info.get("hidden", False)),
                    description=info.get("description") or "",
                ))
        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.warning(f"Failed to fetch indexer roles: {e}")

        self.logger.info(f"Fetched {len(roles)} indexer roles.")
        return roles

    def resolve_indexer_role_mappings(
        self,
        indexer_url: str,
        indexer_user: Optional[str],
        indexer_password: Optional[str],
        users: List[WazuhIndexerUser],
    ) -> None:
        """Resolve which OpenSearch roles each user holds via rolesmapping and mutate users in-place."""
        base = indexer_url.rstrip("/")
        auth = (indexer_user or self.username, indexer_password or self.password)
        try:
            resp = requests.get(
                f"{base}/_plugins/_security/api/rolesmapping",
                auth=auth,
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(f"OpenSearch rolesmapping API failed: HTTP {resp.status_code}")
                return

            mappings = resp.json()
            for role_name, mapping in mappings.items():
                if not isinstance(mapping, dict):
                    continue
                mapped_users = set(mapping.get("users") or [])
                mapped_backend_roles = set(mapping.get("backend_roles") or [])
                for user in users:
                    if user.username in mapped_users:
                        if role_name not in user.roles:
                            user.roles.append(role_name)
                    elif mapped_backend_roles.intersection(set(user.backend_roles)):
                        if role_name not in user.roles:
                            user.roles.append(role_name)
        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.warning(f"Failed to fetch indexer role mappings: {e}")

    # ------------------------------------------------------------------
    # Security configuration (RBAC mode)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_rule_usernames(rule: dict) -> List[str]:
        """Recursively extract all username values from a Wazuh role mapping rule."""
        if not isinstance(rule, dict):
            return []
        usernames: List[str] = []
        for op in ("FIND", "MATCH"):
            condition = rule.get(op)
            if isinstance(condition, dict):
                for field in ("username", "user_name"):
                    val = condition.get(field)
                    if val and isinstance(val, str):
                        usernames.append(val)
        for op in ("AND", "OR"):
            sub = rule.get(op)
            if isinstance(sub, list):
                for sub_rule in sub:
                    usernames.extend(WazuhCollector._extract_rule_usernames(sub_rule))
        return usernames

    def get_security_rules(self) -> List[WazuhRoleMapping]:
        """GET /security/rules - role mapping rules (auto-assign roles based on user attributes)."""
        raw = self._get_all("/security/rules", "security rules")

        seen_ids = {item.get("id") for item in raw}
        reserved_ids = ",".join(str(i) for i in range(1, 100))
        for item in self._get_all(f"/security/rules?rule_ids={reserved_ids}", "reserved security rules"):
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                raw.append(item)

        mappings = []
        for item in raw:
            role_ids = item.get("roles") or []
            if isinstance(role_ids, list):
                role_ids = [int(r) if not isinstance(r, int) else r for r in role_ids]
            mappings.append(WazuhRoleMapping(
                id=item.get("id", 0),
                name=item.get("name", ""),
                rule=item.get("rule") or {},
                role_ids=role_ids,
            ))
        self.logger.info(f"Total role mapping rules collected: {len(mappings)}")
        return mappings

    def get_security_config(self) -> dict:
        """GET /security/config - returns rbac_mode and auth_token_exp_timeout."""
        data = self._get_one("/security/config")
        if not data:
            return {}
        items = data.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    # ------------------------------------------------------------------
    # Syscollector - network addresses (per agent)
    # ------------------------------------------------------------------

    def get_agent_network_data(self, agent_ids: List[str]) -> Dict[str, List[dict]]:
        """Return {agent_id: [netaddr_items]} for all agents (parallel)."""
        def fetch(agent_id: str):
            return agent_id, self._get_all(f"/syscollector/{agent_id}/netaddr", f"netaddr agent {agent_id}")
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as ex:
            return dict(ex.map(fetch, agent_ids))

    def build_network_segments(
        self, network_data: Dict[str, List[dict]]
    ) -> List[WazuhNetworkSegment]:
        """Derive WazuhNetworkSegment objects from syscollector netaddr data."""
        segments: Dict[str, WazuhNetworkSegment] = {}
        for agent_id, addrs in network_data.items():
            for addr in addrs:
                if addr.get("proto", addr.get("type", "")) not in ("ipv4", "IPv4", ""):
                    continue
                ip = addr.get("address") or addr.get("ip") or ""
                mask = addr.get("netmask") or ""
                if not ip or not mask:
                    continue
                cidr = ip_to_cidr(ip, mask)
                if not cidr:
                    continue
                if cidr not in segments:
                    segments[cidr] = WazuhNetworkSegment(cidr=cidr)
                if agent_id not in segments[cidr].agent_ids:
                    segments[cidr].agent_ids.append(agent_id)
        return list(segments.values())

    # ------------------------------------------------------------------
    # Syscollector - listening ports (per agent)
    # ------------------------------------------------------------------

    def get_agent_ports(self, agent_ids: List[str]) -> Dict[str, str]:
        """Return {agent_id: "port/process, ..."} for listening ports (parallel)."""
        def fetch(agent_id: str):
            items = self._get_all(
                f"/syscollector/{agent_id}/ports",
                f"ports agent {agent_id}",
                extra_params={"state": "listening"},
            )
            if not items:
                return agent_id, ""
            ports = []
            for p in items:
                local = p.get("local") or {}
                port = local.get("port") or p.get("local_port") or ""
                proc = p.get("process") or ""
                if port:
                    ports.append(f"{port}/{proc}" if proc else str(port))
            return agent_id, ", ".join(sorted(set(ports)))
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as ex:
            return dict(ex.map(fetch, agent_ids))

    # ------------------------------------------------------------------
    # Vulnerabilities - OpenSearch index (Wazuh 4.8+)
    # ------------------------------------------------------------------

    def get_agent_vulnerabilities_from_indexer(
        self,
        indexer_url: str,
        indexer_user: Optional[str],
        indexer_password: Optional[str],
    ) -> Dict[str, dict]:
        """Aggregate vulnerability counts per agent from wazuh-states-vulnerabilities-* index."""
        base = indexer_url.rstrip("/")
        auth = (indexer_user or self.username, indexer_password or self.password)
        query = {
            "size": 0,
            "aggs": {
                "by_agent": {
                    "terms": {"field": "agent.id", "size": 50000},
                    "aggs": {
                        "by_severity": {
                            "terms": {"field": "vulnerability.severity", "size": 10}
                        }
                    },
                }
            },
        }
        try:
            resp = requests.post(
                f"{base}/wazuh-states-vulnerabilities-*/_search",
                auth=auth,
                json=query,
                timeout=self.timeout,
                verify=self.verify,
            )
            if not (200 <= resp.status_code < 300):
                self.logger.warning(
                    f"Vulnerability index query failed: HTTP {resp.status_code}. "
                    "Trying legacy /vulnerability API."
                )
                return {}
            result: Dict[str, dict] = {}
            for bucket in resp.json().get("aggregations", {}).get("by_agent", {}).get("buckets", []):
                agent_id = str(bucket["key"])
                counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": bucket["doc_count"]}
                for sev in bucket.get("by_severity", {}).get("buckets", []):
                    k = sev["key"].lower()
                    if k in counts:
                        counts[k] = sev["doc_count"]
                result[agent_id] = counts
            self.logger.info(f"Vulnerability data: {len(result)} agents from indexer.")
            return result
        except (requests.exceptions.RequestException, ValueError) as e:
            self.logger.warning(f"Vulnerability indexer query error: {e}")
            return {}

    def get_agent_vulnerabilities_legacy(self, agent_ids: List[str]) -> Dict[str, dict]:
        """Fallback: GET /vulnerability/{agent_id} for Wazuh <= 4.7 (parallel)."""
        def fetch(agent_id: str):
            items = self._get_all(f"/vulnerability/{agent_id}", f"vulns agent {agent_id}")
            if not items:
                return agent_id, {}
            counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(items)}
            for v in items:
                sev = (v.get("severity") or "").lower()
                if sev in counts:
                    counts[sev] += 1
            return agent_id, counts
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as ex:
            return {aid: counts for aid, counts in ex.map(fetch, agent_ids) if counts}

    def get_agent_package_counts(self, agent_ids: List[str]) -> Dict[str, int]:
        """Return {agent_id: total_packages} using a single lightweight request per agent (parallel)."""
        def fetch(agent_id: str):
            url = f"{self.base_url}/syscollector/{agent_id}/packages"
            try:
                resp = requests.get(
                    url,
                    headers=self._headers(),
                    params={"limit": 1, "offset": 0},
                    timeout=self.timeout,
                    verify=self.verify,
                )
                if 200 <= resp.status_code < 300:
                    total = resp.json().get("data", {}).get("total_affected_items", 0)
                    return agent_id, int(total)
            except (requests.exceptions.RequestException, ValueError):
                pass
            return agent_id, 0
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as ex:
            return dict(ex.map(fetch, agent_ids))

    def _enrich_agents(
        self,
        agents: List[WazuhAgent],
        vuln_data: Dict[str, dict],
        port_data: Dict[str, str],
        package_counts: Dict[str, int],
    ) -> None:
        """Mutate agents in-place with vulnerability counts, risk score, open ports, package count."""
        for agent in agents:
            v = vuln_data.get(agent.id, {})
            agent.vuln_critical = v.get("critical", 0)
            agent.vuln_high = v.get("high", 0)
            agent.vuln_medium = v.get("medium", 0)
            agent.vuln_total = v.get("total", 0)
            agent.risk_score = compute_risk_score(
                agent.vuln_critical,
                agent.vuln_high,
                agent.vuln_medium,
                agent.status,
                agent.os_platform,
                agent.os_version,
            )
            agent.open_ports = port_data.get(agent.id, "")
            agent.packages_total = package_counts.get(agent.id, 0)

    # ------------------------------------------------------------------
    # Full collection
    # ------------------------------------------------------------------

    def collect(
        self,
        indexer_url: Optional[str] = None,
        indexer_user: Optional[str] = None,
        indexer_password: Optional[str] = None,
        skip_enrichment: bool = False,
    ) -> Optional[WazuhEnvironment]:
        if not self.token and not self.authenticate():
            return None

        self.logger.info("Collecting groups...")
        groups = self.get_groups()

        # Fetch group memberships explicitly - more reliable than the group field in /agents
        self.logger.info("Collecting group memberships...")
        group_memberships = self._get_group_memberships([g.name for g in groups])
        total_memberships = sum(len(v) for v in group_memberships.values())
        self.logger.info(f"Group memberships: {total_memberships} agent-group pairs across {len(group_memberships)} agents")

        self.logger.info("Collecting agents...")
        agents = self.get_agents(group_memberships=group_memberships)

        self.logger.info("Collecting cluster/manager info...")
        cluster = self.get_cluster()

        self.logger.info("Collecting indexer nodes...")
        indexer_cluster = self.get_indexer_cluster(
            indexer_url=indexer_url,
            indexer_user=indexer_user,
            indexer_password=indexer_password,
        )

        self.logger.info("Collecting security users/roles/policies/rules...")
        security_users = self.get_security_users()
        security_roles = self.get_security_roles()
        security_policies = self.get_security_policies()
        role_mappings = self.get_security_rules()

        # Fetch users referenced in role mapping rules but missing from the user list
        known_usernames = {u.username for u in security_users}
        rule_usernames: set = set()
        for mapping in role_mappings:
            rule_usernames.update(self._extract_rule_usernames(mapping.rule))
        for username in rule_usernames - known_usernames:
            self.logger.info(f"Fetching user '{username}' referenced in role mapping rule...")
            raw = self._get_all("/security/users", f"user {username}", extra_params={"search": username})
            known_ids = {u.id for u in security_users}
            for item in raw:
                if item.get("username") == username and item.get("id") not in known_ids:
                    role_ids = item.get("roles") or []
                    if isinstance(role_ids, list):
                        role_ids = [int(r) if not isinstance(r, int) else r for r in role_ids]
                    security_users.append(WazuhSecurityUser(
                        id=item.get("id", 0),
                        username=item.get("username", ""),
                        allow_run_as=bool(item.get("allow_run_as", False)),
                        roles=role_ids,
                    ))
                    self.logger.info(f"Added user '{username}' from role mapping rule.")

        self.logger.info("Collecting indexer internal users...")
        indexer_users = self.get_indexer_users(
            indexer_url=indexer_url,
            indexer_user=indexer_user,
            indexer_password=indexer_password,
        )

        indexer_roles: List[WazuhIndexerRole] = []
        if indexer_url and indexer_users:
            self.logger.info("Collecting indexer roles and role mappings...")
            indexer_roles = self.get_indexer_roles(indexer_url, indexer_user, indexer_password)
            self.resolve_indexer_role_mappings(indexer_url, indexer_user, indexer_password, indexer_users)

        # RBAC configuration
        self.logger.info("Collecting security configuration (RBAC mode)...")
        sec_config = self.get_security_config()
        if sec_config and cluster:
            cluster.rbac_mode = sec_config.get("rbac_mode") or ""
            cluster.auth_token_exp_timeout = int(sec_config.get("auth_token_exp_timeout") or 900)
            if cluster.rbac_mode == "black":
                self.logger.warning(
                    "RBAC mode is 'black' (default-allow): users without explicit policies "
                    "can access ALL resources not explicitly denied - high-risk configuration."
                )

        # Syscollector enrichment (skippable with --skip-enrichment)
        agent_ids = [a.id for a in agents]
        network_segments: List[WazuhNetworkSegment] = []
        if skip_enrichment:
            self.logger.info("Skipping agent enrichment (--skip-enrichment).")
        else:
            self.logger.info("Collecting syscollector network data (per agent)...")
            network_data = self.get_agent_network_data(agent_ids)
            network_segments = self.build_network_segments(network_data)
            self.logger.info(f"Discovered {len(network_segments)} network segment(s).")

            self.logger.info("Collecting syscollector listening ports (per agent)...")
            port_data = self.get_agent_ports(agent_ids)

            self.logger.info("Collecting syscollector package counts (per agent)...")
            package_counts = self.get_agent_package_counts(agent_ids)

            # Vulnerabilities
            vuln_data: Dict[str, dict] = {}
            if indexer_url:
                self.logger.info("Collecting vulnerability data from indexer...")
                vuln_data = self.get_agent_vulnerabilities_from_indexer(
                    indexer_url, indexer_user, indexer_password
                )
            if not vuln_data:
                self.logger.info("Trying legacy vulnerability API (Wazuh <= 4.7)...")
                vuln_data = self.get_agent_vulnerabilities_legacy(agent_ids)

            self._enrich_agents(agents, vuln_data, port_data, package_counts)

        env = WazuhEnvironment(
            cluster=cluster,
            standalone_manager=None,
            agents=agents,
            groups=groups,
            indexer_cluster=indexer_cluster,
            security_users=security_users,
            security_roles=security_roles,
            security_policies=security_policies,
            role_mappings=role_mappings,
            indexer_users=indexer_users,
            indexer_roles=indexer_roles,
            network_segments=network_segments,
        )
        self.logger.info(f"Collection complete: {env}")
        return env
