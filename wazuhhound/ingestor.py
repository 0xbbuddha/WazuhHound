import logging
from typing import Optional

from bhopengraph.Edge import Edge as OGEdge
from bhopengraph.Node import Node as OGNode
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Properties import Properties as OGProps

from .models import WazuhEnvironment, WazuhIndexerRole, WazuhIndexerUser, WazuhNetworkSegment, WazuhRoleMapping
from .names import wz_kind

BASE = wz_kind("Base")


class WazuhIngestor:
    """Transforms a WazuhEnvironment into a BloodHound CE OpenGraph."""

    def __init__(self, env: WazuhEnvironment):
        self.env = env
        self.og = OpenGraph()
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def ingest(self) -> OpenGraph:
        self._ingest_cluster()
        self._ingest_indexer()
        self._ingest_groups()
        self._ingest_agents()
        self._ingest_network_segments()
        self._ingest_security()
        self._ingest_indexer_roles()
        self._ingest_indexer_users()
        self._ingest_role_mappings()
        self._ingest_policy_impact()
        return self.og

    # ------------------------------------------------------------------
    # Cluster / standalone manager
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Network segments
    # ------------------------------------------------------------------

    # Max agents per segment for SharedSegment edge generation (avoids N^2 explosion on large flat nets)
    _SHARED_SEGMENT_MAX = 50

    def _ingest_network_segments(self) -> None:
        agent_by_id = {a.id: a for a in self.env.agents}
        for seg in self.env.network_segments:
            self.og.add_node(
                OGNode(
                    id=seg.object_id(),
                    kinds=[wz_kind("NetworkSegment"), BASE],
                    properties=OGProps(
                        name=seg.cidr,
                        agent_count=len(seg.agent_ids),
                    ),
                )
            )
            present = [aid for aid in seg.agent_ids if aid in agent_by_id]
            for agent_id in present:
                self.og.add_edge(
                    OGEdge(
                        start_node=agent_by_id[agent_id].object_id(),
                        end_node=seg.object_id(),
                        kind=wz_kind("InSegment"),
                        properties=OGProps(),
                    )
                )
                self.logger.debug(f"Agent {agent_id} -[InSegment]-> {seg.cidr}")

            # SharedSegment: lateral movement edges between all agent pairs on same subnet
            if 2 <= len(present) <= self._SHARED_SEGMENT_MAX:
                for i, a1 in enumerate(present):
                    for a2 in present[i + 1:]:
                        self.og.add_edge(OGEdge(
                            start_node=agent_by_id[a1].object_id(),
                            end_node=agent_by_id[a2].object_id(),
                            kind=wz_kind("SharedSegment"),
                            properties=OGProps(cidr=seg.cidr),
                        ))
                        self.og.add_edge(OGEdge(
                            start_node=agent_by_id[a2].object_id(),
                            end_node=agent_by_id[a1].object_id(),
                            kind=wz_kind("SharedSegment"),
                            properties=OGProps(cidr=seg.cidr),
                        ))
                self.logger.debug(f"SharedSegment: {len(present)} agents on {seg.cidr} -> {len(present)*(len(present)-1)} lateral edges")

    # ------------------------------------------------------------------
    # Cluster / standalone manager
    # ------------------------------------------------------------------

    def _ingest_cluster(self) -> None:
        cluster = self.env.cluster
        if not cluster:
            return

        self.og.add_node(
            OGNode(
                id=cluster.object_id(),
                kinds=[wz_kind("Cluster"), BASE],
                properties=OGProps(
                    name=cluster.name,
                    mode="standalone" if cluster.standalone else "cluster",
                    rbac_mode=cluster.rbac_mode or "white",
                    auth_token_exp_timeout=cluster.auth_token_exp_timeout,
                    high_value=True,
                ),
            )
        )

        for node in cluster.nodes:
            self.og.add_node(
                OGNode(
                    id=node.object_id(),
                    kinds=[wz_kind("ClusterNode"), BASE],
                    properties=OGProps(
                        name=node.name,
                        type=node.type,
                        ip=node.ip or "",
                        version=node.version or "",
                        status=node.status or "",
                    ),
                )
            )
            self.og.add_edge(
                OGEdge(
                    start_node=node.object_id(),
                    end_node=cluster.object_id(),
                    kind=wz_kind("PartOf"),
                    properties=OGProps(),
                )
            )
            self.logger.debug(f"ClusterNode {node.name} -[PartOf]-> {cluster.name}")

    def _cluster_id(self) -> Optional[str]:
        return self.env.cluster.object_id() if self.env.cluster else None

    def _manager_node_id(self, agent_manager: Optional[str], agent_node: Optional[str]) -> Optional[str]:
        """Resolve the cluster node ID an agent reports to."""
        cluster = self.env.cluster
        if not cluster or not cluster.nodes:
            return None

        name = agent_node or agent_manager
        if name:
            for n in cluster.nodes:
                if n.name == name:
                    return n.object_id()
            # Name didn't match any known node - fall through to default
            # rather than generating a non-existent node ID

        # Default: master node, or first available node
        masters = [n for n in cluster.nodes if n.type == "master"]
        fallback = masters[0] if masters else cluster.nodes[0]
        return fallback.object_id()

    # ------------------------------------------------------------------
    # Indexer
    # ------------------------------------------------------------------

    def _ingest_indexer(self) -> None:
        if not self.env.indexer_cluster:
            return

        ic = self.env.indexer_cluster
        self.og.add_node(
            OGNode(
                id=ic.object_id(),
                kinds=[wz_kind("IndexerCluster"), BASE],
                properties=OGProps(name=ic.name, high_value=True),
            )
        )

        for node in ic.nodes:
            roles_str = ", ".join(node.roles) if node.roles else ""
            self.og.add_node(
                OGNode(
                    id=node.object_id(),
                    kinds=[wz_kind("IndexerNode"), BASE],
                    properties=OGProps(
                        name=node.name,
                        roles=roles_str,
                        ip=node.ip or "",
                        version=node.version or "",
                        status=node.status or "",
                    ),
                )
            )
            self.og.add_edge(
                OGEdge(
                    start_node=node.object_id(),
                    end_node=ic.object_id(),
                    kind=wz_kind("PartOf"),
                    properties=OGProps(),
                )
            )
            self.logger.debug(f"IndexerNode {node.name} -[PartOf]-> {ic.name}")

        # Link the manager cluster to the indexer cluster
        cluster_id = self._cluster_id()
        if cluster_id:
            self.og.add_edge(
                OGEdge(
                    start_node=cluster_id,
                    end_node=ic.object_id(),
                    kind=wz_kind("Monitors"),
                    properties=OGProps(),
                )
            )
            self.logger.debug(f"Cluster -[Monitors]-> IndexerCluster {ic.name}")

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def _ingest_groups(self) -> None:
        seen_names = {g.name for g in self.env.groups}

        # Ensure nodes exist for groups referenced by agents but missing from /groups
        for agent in self.env.agents:
            for g in agent.groups:
                if g not in seen_names:
                    seen_names.add(g)
                    from .models import WazuhGroup
                    self.env.groups.append(WazuhGroup(name=g))

        cluster_id = self._cluster_id()

        for group in self.env.groups:
            self.og.add_node(
                OGNode(
                    id=group.object_id(),
                    kinds=[wz_kind("AgentGroup"), BASE],
                    properties=OGProps(
                        name=group.name,
                        agent_count=group.agent_count,
                        config_sum=group.config_sum or "",
                        merged_sum=group.merged_sum or "",
                    ),
                )
            )

            # Every agent group is managed by the Wazuh cluster
            if cluster_id:
                self.og.add_edge(
                    OGEdge(
                        start_node=group.object_id(),
                        end_node=cluster_id,
                        kind=wz_kind("ManagedBy"),
                        properties=OGProps(),
                    )
                )
                self.logger.debug(f"AgentGroup {group.name} -[ManagedBy]-> cluster")

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def _ingest_agents(self) -> None:
        for agent in self.env.agents:
            is_manager = agent.id == "000"
            self.og.add_node(
                OGNode(
                    id=agent.object_id(),
                    kinds=[wz_kind("Agent"), BASE],
                    properties=OGProps(
                        name=agent.name,
                        agentid=agent.id,
                        ip=agent.ip or "",
                        register_ip=agent.register_ip or "",
                        os_name=agent.os_name or "",
                        os_version=agent.os_version or "",
                        os_platform=agent.os_platform or "",
                        os_arch=agent.os_arch or "",
                        version=agent.version or "",
                        status=agent.status or "",
                        last_keepalive=agent.last_keepalive or "",
                        date_add=agent.date_add or "",
                        vuln_critical=agent.vuln_critical,
                        vuln_high=agent.vuln_high,
                        vuln_medium=agent.vuln_medium,
                        vuln_total=agent.vuln_total,
                        risk_score=agent.risk_score,
                        open_ports=agent.open_ports,
                        packages_total=agent.packages_total,
                        high_value=is_manager,
                        is_manager=is_manager,
                    ),
                )
            )
            if is_manager:
                self.logger.debug(f"Agent 000 ({agent.name}) is the Wazuh manager itself - tagged high_value")

            for group_name in agent.groups:
                group_id = f"wazuh-group-{group_name}"
                self.og.add_edge(
                    OGEdge(
                        start_node=agent.object_id(),
                        end_node=group_id,
                        kind=wz_kind("MemberOf"),
                        properties=OGProps(),
                    )
                )
                self.logger.debug(f"Agent {agent.name} -[MemberOf]-> {group_name}")

            manager_id = self._manager_node_id(agent.manager, agent.node_name)
            if manager_id:
                self.og.add_edge(
                    OGEdge(
                        start_node=agent.object_id(),
                        end_node=manager_id,
                        kind=wz_kind("ConnectedTo"),
                        properties=OGProps(),
                    )
                )
                self.logger.debug(f"Agent {agent.name} -[ConnectedTo]-> {manager_id}")

    # ------------------------------------------------------------------
    # Role mapping rules (/security/rules)
    # ------------------------------------------------------------------

    def _ingest_role_mappings(self) -> None:
        if not self.env.role_mappings:
            return

        role_by_id = {r.id: r for r in self.env.security_roles}
        user_by_username = {u.username: u for u in self.env.security_users}
        # Wazuh role mapping rules can also reference indexer (OpenSearch/Dashboard) users
        indexer_user_by_username = {u.username: u for u in self.env.indexer_users}

        for mapping in self.env.role_mappings:
            import json as _json
            rule_str = _json.dumps(mapping.rule, separators=(",", ":")) if mapping.rule else "{}"
            self.og.add_node(OGNode(
                id=mapping.object_id(),
                kinds=[wz_kind("RoleMapping"), BASE],
                properties=OGProps(
                    name=mapping.name,
                    mappingid=mapping.id,
                    rule=rule_str,
                ),
            ))
            self.logger.debug(f"RoleMapping {mapping.name}")

            # WZ_RoleMapping -[WZ_AutoAssigns]-> WZ_Role
            for role_id in mapping.role_ids:
                if role_id in role_by_id:
                    self.og.add_edge(OGEdge(
                        start_node=mapping.object_id(),
                        end_node=role_by_id[role_id].object_id(),
                        kind=wz_kind("AutoAssigns"),
                        properties=OGProps(),
                    ))
                    self.logger.debug(f"RoleMapping {mapping.name} -[AutoAssigns]-> {role_by_id[role_id].name}")

            # Try to resolve username-based rules against both Manager API users and Indexer users
            matched_users = self._evaluate_mapping_rule(mapping.rule, user_by_username)
            matched_users += self._evaluate_mapping_rule(mapping.rule, indexer_user_by_username)
            for user_obj_id in list(set(matched_users)):
                self.og.add_edge(OGEdge(
                    start_node=user_obj_id,
                    end_node=mapping.object_id(),
                    kind=wz_kind("AppliesTo"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"User -[AppliesTo]-> RoleMapping {mapping.name}")

    @staticmethod
    def _evaluate_mapping_rule(rule: dict, user_by_username: dict) -> list:
        """Resolve simple FIND/MATCH username rules to user object IDs."""
        if not isinstance(rule, dict):
            return []
        matched = []
        for op in ("FIND", "MATCH"):
            condition = rule.get(op)
            if isinstance(condition, dict):
                # Wazuh uses both "username" and "user_name" depending on version
                username = condition.get("username") or condition.get("user_name")
                if username and username in user_by_username:
                    matched.append(user_by_username[username].object_id())
        # AND/OR: recurse one level
        for op in ("AND", "OR"):
            sub = rule.get(op)
            if isinstance(sub, list):
                for sub_rule in sub:
                    matched.extend(WazuhIngestor._evaluate_mapping_rule(sub_rule, user_by_username))
        return list(set(matched))

    # ------------------------------------------------------------------
    # Policy impact edges (compromise paths)
    # ------------------------------------------------------------------

    # Actions that allow controlling agents (write/exec)
    _AGENT_CONTROL_ACTIONS = frozenset({
        "agent:restart", "agent:upgrade", "agent:delete", "agent:create",
        "agent:reconnect", "agent:modify_group", "agent:*", "*:*",
    })
    # Actions that allow managing users/roles/policies (privilege escalation)
    _SECURITY_MANAGE_ACTIONS = frozenset({
        "security:create", "security:edit", "security:delete",
        "security:update", "security:*", "*:*",
    })
    # Inject events into analysisd (log poisoning / detection bypass)
    _EVENT_INJECT_ACTIONS = frozenset({
        "event:ingest", "event:*", "*:*",
    })
    # Execute active-response commands on agents (RCE via AR)
    _ACTIVE_RESPONSE_ACTIONS = frozenset({
        "active-response:command", "active-response:*", "*:*",
    })
    # Write files on the manager: upload AR scripts or ossec.conf = RCE path
    _WRITE_CONFIG_ACTIONS = frozenset({
        "manager:upload", "manager:files", "manager:*",
        "configuration:update", "configuration:*", "*:*",
    })

    @staticmethod
    def _action_matches(action: str, target_set: frozenset) -> bool:
        """True if action matches any entry in target_set, respecting namespace wildcards."""
        if action in target_set or action == "*:*":
            return True
        # "agent:*" matches any "agent:xxx"
        if action.endswith(":*"):
            prefix = action[:-1]
            for t in target_set:
                if t.startswith(prefix):
                    return True
        return False

    @classmethod
    def _matches_any(cls, actions: list, target: frozenset) -> bool:
        return any(cls._action_matches(a, target) for a in actions)

    def _ingest_policy_impact(self) -> None:
        """Derive impact edges from allow policies - the compromise path layer."""
        cluster_id = self._cluster_id()
        agent_by_id = {a.id: a for a in self.env.agents}
        group_by_name = {g.name: g for g in self.env.groups}

        # allow_run_as users get WZ_CanImpersonate -> cluster
        if cluster_id:
            for user in self.env.security_users:
                if user.allow_run_as:
                    self.og.add_edge(OGEdge(
                        start_node=user.object_id(),
                        end_node=cluster_id,
                        kind=wz_kind("CanImpersonate"),
                        properties=OGProps(),
                    ))
                    self.logger.debug(f"User {user.username} -[CanImpersonate]-> cluster (allow_run_as)")

        for policy in self.env.security_policies:
            if policy.effect != "allow":
                continue

            can_control = self._matches_any(policy.actions, self._AGENT_CONTROL_ACTIONS)
            can_manage_sec = self._matches_any(policy.actions, self._SECURITY_MANAGE_ACTIONS)
            can_inject = self._matches_any(policy.actions, self._EVENT_INJECT_ACTIONS)
            can_ar = self._matches_any(policy.actions, self._ACTIVE_RESPONSE_ACTIONS)
            can_write_cfg = self._matches_any(policy.actions, self._WRITE_CONFIG_ACTIONS)

            if can_control:
                targets = self._resolve_resource_targets(
                    policy.resources, agent_by_id, group_by_name, cluster_id
                )
                for target_id in targets:
                    self.og.add_edge(OGEdge(
                        start_node=policy.object_id(),
                        end_node=target_id,
                        kind=wz_kind("CanControlAgent"),
                        properties=OGProps(),
                    ))
                    self.logger.debug(f"Policy {policy.name} -[CanControlAgent]-> {target_id}")

            if can_manage_sec and cluster_id:
                self.og.add_edge(OGEdge(
                    start_node=policy.object_id(),
                    end_node=cluster_id,
                    kind=wz_kind("CanManageSecurity"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"Policy {policy.name} -[CanManageSecurity]-> cluster")

            if can_inject and cluster_id:
                self.og.add_edge(OGEdge(
                    start_node=policy.object_id(),
                    end_node=cluster_id,
                    kind=wz_kind("CanInjectEvents"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"Policy {policy.name} -[CanInjectEvents]-> cluster")

            if can_ar:
                targets = self._resolve_resource_targets(
                    policy.resources, agent_by_id, group_by_name, cluster_id
                )
                for target_id in targets:
                    self.og.add_edge(OGEdge(
                        start_node=policy.object_id(),
                        end_node=target_id,
                        kind=wz_kind("CanExecuteAR"),
                        properties=OGProps(),
                    ))
                    self.logger.debug(f"Policy {policy.name} -[CanExecuteAR]-> {target_id}")
                    # AR on agent 000 = the manager itself - also add edge to cluster (RCE on manager)
                    if target_id == "wazuh-agent-000" and cluster_id:
                        self.og.add_edge(OGEdge(
                            start_node=policy.object_id(),
                            end_node=cluster_id,
                            kind=wz_kind("CanExecuteAR"),
                            properties=OGProps(note="via agent:id:000 (manager self-agent)"),
                        ))
                        self.logger.debug(f"Policy {policy.name} -[CanExecuteAR]-> cluster (agent 000 = manager)")

            if can_write_cfg and cluster_id:
                self.og.add_edge(OGEdge(
                    start_node=policy.object_id(),
                    end_node=cluster_id,
                    kind=wz_kind("CanWriteConfig"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"Policy {policy.name} -[CanWriteConfig]-> cluster")

    def _resolve_resource_targets(
        self,
        resources: list,
        agent_by_id: dict,
        group_by_name: dict,
        cluster_id,
    ) -> list:
        """Map Wazuh resource strings to node IDs for impact edges."""
        targets = []
        for res in resources:
            if not isinstance(res, str):
                continue
            # agent:id:* or *:*:* -> all agents represented by cluster node
            if res in ("agent:id:*", "*:*:*", "*:*", "*") or res.endswith(":*:*"):
                if cluster_id:
                    targets.append(cluster_id)
            # agent:id:001 -> specific agent
            elif res.startswith("agent:id:"):
                agent_id = res.split(":", 2)[2]
                if agent_id in agent_by_id:
                    targets.append(agent_by_id[agent_id].object_id())
            # group:id:linux -> specific group
            elif res.startswith("group:id:"):
                group_id = res.split(":", 2)[2]
                if group_id in group_by_name:
                    targets.append(group_by_name[group_id].object_id())
                elif group_id == "*" and cluster_id:
                    targets.append(cluster_id)
        return list(set(targets))

    # ------------------------------------------------------------------
    # Indexer roles (OpenSearch Security)
    # ------------------------------------------------------------------

    _INDEXER_WRITE_ACTIONS = frozenset({
        "indices:data/write/index",
        "indices:data/write/bulk*",
        "indices:data/write/delete*",
        "indices:data/write/update*",
        "write", "crud", "*",
    })
    _INDEXER_READ_ACTIONS = frozenset({
        "indices:data/read/search",
        "indices:data/read*",
        "read", "search", "*",
    })
    _INDEXER_ADMIN_ROLES = frozenset({
        "all_access", "security_manager",
    })

    def _ingest_indexer_roles(self) -> None:
        if not self.env.indexer_roles:
            return

        ic_id = self.env.indexer_cluster.object_id() if self.env.indexer_cluster else None

        for role in self.env.indexer_roles:
            if role.hidden:
                continue
            self.og.add_node(
                OGNode(
                    id=role.object_id(),
                    kinds=[wz_kind("IndexerRole"), BASE],
                    properties=OGProps(
                        name=role.name,
                        cluster_permissions=", ".join(role.cluster_permissions),
                        index_patterns=", ".join(role.index_patterns),
                        allowed_actions=", ".join(role.allowed_actions),
                        reserved=role.reserved,
                        description=role.description,
                    ),
                )
            )
            self.logger.debug(f"IndexerRole {role.name}")

            if not ic_id:
                continue

            all_actions = set(role.allowed_actions) | set(role.cluster_permissions)
            is_admin = role.name in self._INDEXER_ADMIN_ROLES or "*" in all_actions or "cluster:admin" in all_actions

            can_read = is_admin or bool(all_actions & self._INDEXER_READ_ACTIONS)
            can_write = is_admin or bool(all_actions & self._INDEXER_WRITE_ACTIONS)

            if can_write:
                self.og.add_edge(OGEdge(
                    start_node=role.object_id(),
                    end_node=ic_id,
                    kind=wz_kind("CanWriteIndex"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"IndexerRole {role.name} -[CanWriteIndex]-> indexer")
            elif can_read:
                self.og.add_edge(OGEdge(
                    start_node=role.object_id(),
                    end_node=ic_id,
                    kind=wz_kind("CanReadIndex"),
                    properties=OGProps(),
                ))
                self.logger.debug(f"IndexerRole {role.name} -[CanReadIndex]-> indexer")

    # ------------------------------------------------------------------
    # Indexer internal users (OpenSearch Security)
    # ------------------------------------------------------------------

    def _ingest_indexer_users(self) -> None:
        if not self.env.indexer_users:
            return

        ic_id = self.env.indexer_cluster.object_id() if self.env.indexer_cluster else None

        for user in self.env.indexer_users:
            if user.hidden:
                continue
            self.og.add_node(
                OGNode(
                    id=user.object_id(),
                    kinds=[wz_kind("IndexerUser"), BASE],
                    properties=OGProps(
                        name=user.username,
                        backend_roles=", ".join(user.backend_roles),
                        reserved=user.reserved,
                        description=user.description,
                    ),
                )
            )

            # Connect to indexer cluster
            if ic_id:
                self.og.add_edge(
                    OGEdge(
                        start_node=user.object_id(),
                        end_node=ic_id,
                        kind=wz_kind("AccessesIndexer"),
                        properties=OGProps(),
                    )
                )
                self.logger.debug(f"IndexerUser {user.username} -[AccessesIndexer]-> indexer cluster")

            # Connect to resolved OpenSearch roles
            role_ids = {r.object_id() for r in self.env.indexer_roles}
            for role_name in user.roles:
                role_id = f"wazuh-indexer-role-{role_name}"
                if role_id in role_ids:
                    self.og.add_edge(
                        OGEdge(
                            start_node=user.object_id(),
                            end_node=role_id,
                            kind=wz_kind("MappedToRole"),
                            properties=OGProps(),
                        )
                    )
                    self.logger.debug(f"IndexerUser {user.username} -[MappedToRole]-> {role_name}")

    # ------------------------------------------------------------------
    # Security (RBAC)
    # ------------------------------------------------------------------

    def _ingest_security(self) -> None:
        if not (self.env.security_users or self.env.security_roles or self.env.security_policies):
            return

        policy_by_id = {p.id: p for p in self.env.security_policies}
        role_by_id = {r.id: r for r in self.env.security_roles}

        # Policies
        for policy in self.env.security_policies:
            self.og.add_node(
                OGNode(
                    id=policy.object_id(),
                    kinds=[wz_kind("Policy"), BASE],
                    properties=OGProps(
                        name=policy.name,
                        actions=", ".join(policy.actions),
                        resources=", ".join(policy.resources),
                        effect=policy.effect,
                    ),
                )
            )

        # Roles → Policies
        for role in self.env.security_roles:
            self.og.add_node(
                OGNode(
                    id=role.object_id(),
                    kinds=[wz_kind("Role"), BASE],
                    properties=OGProps(
                        name=role.name,
                        roleid=role.id,
                    ),
                )
            )
            for policy_id in role.policies:
                if policy_id in policy_by_id:
                    self.og.add_edge(
                        OGEdge(
                            start_node=role.object_id(),
                            end_node=policy_by_id[policy_id].object_id(),
                            kind=wz_kind("HasPolicy"),
                            properties=OGProps(),
                        )
                    )
                    self.logger.debug(f"Role {role.name} -[HasPolicy]-> {policy_by_id[policy_id].name}")

        # Users → Roles
        for user in self.env.security_users:
            self.og.add_node(
                OGNode(
                    id=user.object_id(),
                    kinds=[wz_kind("User"), BASE],
                    properties=OGProps(
                        name=user.username,
                        userid=user.id,
                        allow_run_as=user.allow_run_as,
                    ),
                )
            )
            for role_id in user.roles:
                if role_id in role_by_id:
                    self.og.add_edge(
                        OGEdge(
                            start_node=user.object_id(),
                            end_node=role_by_id[role_id].object_id(),
                            kind=wz_kind("HasRole"),
                            properties=OGProps(),
                        )
                    )
                    self.logger.debug(f"User {user.username} -[HasRole]-> {role_by_id[role_id].name}")
