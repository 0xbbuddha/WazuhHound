import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WazuhAgent:
    id: str
    name: str
    ip: Optional[str] = None
    register_ip: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_platform: Optional[str] = None
    os_arch: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    manager: Optional[str] = None
    node_name: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    last_keepalive: Optional[str] = None
    date_add: Optional[str] = None
    merged_sum: Optional[str] = None
    config_sum: Optional[str] = None
    # Enrichment: vulnerabilities
    vuln_critical: int = 0
    vuln_high: int = 0
    vuln_medium: int = 0
    vuln_total: int = 0
    # Enrichment: risk score (0-10)
    risk_score: float = 0.0
    # Enrichment: listening ports summary "22/sshd, 80/nginx"
    open_ports: str = ""
    # Enrichment: installed package count
    packages_total: int = 0

    def object_id(self) -> str:
        return f"wazuh-agent-{self.id}"

    def __repr__(self):
        return f"WazuhAgent(id={self.id!r}, name={self.name!r}, status={self.status!r})"


@dataclass
class WazuhNetworkSegment:
    cidr: str
    agent_ids: List[str] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-segment-{self.cidr.replace('/', '-')}"

    def __repr__(self):
        return f"WazuhNetworkSegment(cidr={self.cidr!r}, agents={len(self.agent_ids)})"


@dataclass
class WazuhGroup:
    name: str
    agent_count: int = 0
    config_sum: Optional[str] = None
    merged_sum: Optional[str] = None

    def object_id(self) -> str:
        return f"wazuh-group-{self.name}"

    def __repr__(self):
        return f"WazuhGroup(name={self.name!r}, agents={self.agent_count})"


@dataclass
class WazuhClusterNode:
    name: str
    type: str
    ip: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None

    def object_id(self) -> str:
        return f"wazuh-node-{self.name}"

    def __repr__(self):
        return f"WazuhClusterNode(name={self.name!r}, type={self.type!r}, status={self.status!r})"


@dataclass
class WazuhCluster:
    name: str
    nodes: List[WazuhClusterNode] = field(default_factory=list)
    standalone: bool = False
    # RBAC configuration
    rbac_mode: str = ""           # "white" (default-deny) or "black" (default-allow!)
    auth_token_exp_timeout: int = 900

    def object_id(self) -> str:
        return f"wazuh-cluster-{self.name}"

    def __repr__(self):
        return f"WazuhCluster(name={self.name!r}, nodes={len(self.nodes)}, standalone={self.standalone}, rbac={self.rbac_mode!r})"


@dataclass
class WazuhIndexerNode:
    name: str
    roles: List[str] = field(default_factory=list)
    ip: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None

    def object_id(self) -> str:
        return f"wazuh-indexer-{self.name}"

    def __repr__(self):
        return f"WazuhIndexerNode(name={self.name!r}, roles={self.roles}, status={self.status!r})"


@dataclass
class WazuhIndexerCluster:
    name: str
    nodes: List[WazuhIndexerNode] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-indexer-cluster-{self.name}"

    def __repr__(self):
        return f"WazuhIndexerCluster(name={self.name!r}, nodes={len(self.nodes)})"


@dataclass
class WazuhSecurityUser:
    id: int
    username: str
    allow_run_as: bool = False
    roles: List[int] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-user-{self.id}"

    def __repr__(self):
        return f"WazuhSecurityUser(id={self.id}, username={self.username!r})"


@dataclass
class WazuhIndexerRole:
    name: str
    cluster_permissions: List[str] = field(default_factory=list)
    index_patterns: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=list)
    reserved: bool = False
    hidden: bool = False
    description: str = ""

    def object_id(self) -> str:
        return f"wazuh-indexer-role-{self.name}"

    def __repr__(self):
        return f"WazuhIndexerRole(name={self.name!r}, reserved={self.reserved})"


@dataclass
class WazuhIndexerUser:
    username: str
    backend_roles: List[str] = field(default_factory=list)
    reserved: bool = False
    hidden: bool = False
    description: str = ""
    roles: List[str] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-indexer-user-{self.username}"

    def __repr__(self):
        return f"WazuhIndexerUser(username={self.username!r}, reserved={self.reserved})"


@dataclass
class WazuhSecurityRole:
    id: int
    name: str
    policies: List[int] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-role-{self.id}"

    def __repr__(self):
        return f"WazuhSecurityRole(id={self.id}, name={self.name!r})"


@dataclass
class WazuhSecurityPolicy:
    id: int
    name: str
    actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    effect: str = ""

    def object_id(self) -> str:
        return f"wazuh-policy-{self.id}"

    def __repr__(self):
        return f"WazuhSecurityPolicy(id={self.id}, name={self.name!r}, effect={self.effect!r})"


@dataclass
class WazuhRoleMapping:
    id: int
    name: str
    rule: dict
    role_ids: List[int] = field(default_factory=list)

    def object_id(self) -> str:
        return f"wazuh-rolemapping-{self.id}"

    def __repr__(self):
        return f"WazuhRoleMapping(id={self.id}, name={self.name!r})"


@dataclass
class WazuhEnvironment:
    cluster: Optional[WazuhCluster] = None
    standalone_manager: Optional[str] = None
    indexer_cluster: Optional[WazuhIndexerCluster] = None
    agents: List[WazuhAgent] = field(default_factory=list)
    groups: List[WazuhGroup] = field(default_factory=list)
    security_users: List[WazuhSecurityUser] = field(default_factory=list)
    security_roles: List[WazuhSecurityRole] = field(default_factory=list)
    security_policies: List[WazuhSecurityPolicy] = field(default_factory=list)
    role_mappings: List["WazuhRoleMapping"] = field(default_factory=list)
    indexer_users: List["WazuhIndexerUser"] = field(default_factory=list)
    indexer_roles: List["WazuhIndexerRole"] = field(default_factory=list)
    network_segments: List[WazuhNetworkSegment] = field(default_factory=list)

    def __repr__(self):
        return (
            f"WazuhEnvironment(agents={len(self.agents)}, groups={len(self.groups)}, "
            f"users={len(self.security_users)}, roles={len(self.security_roles)}, "
            f"policies={len(self.security_policies)}, role_mappings={len(self.role_mappings)}, "
            f"indexer_users={len(self.indexer_users)}, "
            f"segments={len(self.network_segments)}, "
            f"indexer_nodes={len(self.indexer_cluster.nodes) if self.indexer_cluster else 0})"
        )


# -----------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------

def ip_to_cidr(address: str, netmask: str) -> Optional[str]:
    """Convert an IP + netmask to CIDR notation, skipping loopback/link-local."""
    try:
        net = ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
        if net.is_loopback or net.is_link_local:
            return None
        return str(net)
    except (ValueError, TypeError):
        return None


def compute_risk_score(
    vuln_critical: int,
    vuln_high: int,
    vuln_medium: int,
    status: Optional[str],
    os_platform: Optional[str],
    os_version: Optional[str],
) -> float:
    """Compute a 0-10 risk score from available agent data."""
    score = 0.0
    if vuln_critical > 0:
        score += min(4.0, 1.5 + vuln_critical * 0.3)
    if vuln_high > 0:
        score += min(2.5, 0.8 + vuln_high * 0.15)
    if vuln_medium > 0:
        score += min(1.0, vuln_medium * 0.05)
    if status == "disconnected":
        score += 1.0  # unknown current state
    elif status == "never_connected":
        score += 0.5
    # Very rough OS EOL heuristic
    if os_platform and os_version:
        plat = os_platform.lower()
        ver = os_version.lower()
        if "windows" in plat and any(x in ver for x in ("xp", "2003", "2008", "vista", "7 ")):
            score += 2.0
        elif "ubuntu" in plat and any(x in ver for x in ("14.", "16.", "18.")):
            score += 0.5
        elif "centos" in plat and "6" in ver:
            score += 1.0
    return min(10.0, round(score, 1))
