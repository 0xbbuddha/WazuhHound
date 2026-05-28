# WazuhHound

WazuhHound is a BloodHound CE OpenGraph collector for Wazuh. It maps agents, groups, manager cluster nodes, indexer nodes, RBAC security users/roles/policies, OpenSearch internal users/roles, and network segments from the Wazuh REST API into a BloodHound-compatible graph - exposing privilege escalation paths, agent control paths, and full infrastructure topology.

```cypher
MATCH (start), (end)
WHERE (start:WZ_User OR start:WZ_IndexerUser)
  AND (end:WZ_Cluster OR end:WZ_IndexerCluster)
  AND start <> end
MATCH p = allShortestPaths((start)-[:WZ_HasRole|WZ_HasPolicy|WZ_CanManageSecurity|WZ_CanControlAgent|WZ_CanImpersonate|WZ_CanInjectEvents|WZ_CanExecuteAR|WZ_MappedToRole|WZ_AccessesIndexer|WZ_CanReadIndex|WZ_CanWriteIndex*1..10]->(end))
RETURN p
```

---

## Features

- Collects agents, groups, manager cluster nodes, and indexer nodes via the Wazuh REST API.
- Collects RBAC security users, roles, and policies with full permission path modeling.
- Collects OpenSearch internal users and roles via the indexer Security API.
- Derives attack path edges from policy content: `WZ_CanControlAgent`, `WZ_CanManageSecurity`, `WZ_CanInjectEvents`, `WZ_CanExecuteAR`, `WZ_CanImpersonate`, `WZ_CanWriteConfig`.
- Detects agent 000 (Wazuh manager self-agent) and tags it `high_value=True` - active-response on agent 000 is RCE on the manager server itself.
- Enriches agents with vulnerability counts (critical/high/medium), risk score (0-10), listening ports, and installed package count via syscollector.
- Derives network segments (IP subnets) from per-agent syscollector netaddr data; identifies multi-homed pivot points and generates `WZ_SharedSegment` lateral movement edges between agents on the same subnet.
- Reads RBAC mode (`white`/`black`) and auth token expiry from Wazuh security config.
- Parallel agent enrichment with `ThreadPoolExecutor` - scales to large deployments.
- Works in both standalone and clustered Wazuh deployments.
- Ships 45 pre-built Cypher saved queries including `shortestPath` / `allShortestPaths` attack path queries.

---

## Coverage

WazuhHound defines **12 node kinds** and **19 relationship kinds**.

| Area | Node kinds |
| --- | --- |
| Manager | `WZ_Cluster`, `WZ_ClusterNode` |
| Agents | `WZ_Agent`, `WZ_AgentGroup` |
| Network | `WZ_NetworkSegment` |
| Indexer | `WZ_IndexerCluster`, `WZ_IndexerNode`, `WZ_IndexerRole` |
| Security (RBAC) | `WZ_User`, `WZ_Role`, `WZ_Policy` |
| Security (Indexer) | `WZ_IndexerUser` |

| Area | Relationship kinds |
| --- | --- |
| Agent topology | `WZ_MemberOf`, `WZ_ConnectedTo`, `WZ_InSegment`, `WZ_SharedSegment` |
| Infrastructure | `WZ_PartOf`, `WZ_ManagedBy`, `WZ_Monitors` |
| RBAC | `WZ_HasRole`, `WZ_HasPolicy` |
| Indexer access | `WZ_AccessesIndexer`, `WZ_MappedToRole`, `WZ_CanReadIndex`, `WZ_CanWriteIndex` |
| Attack paths | `WZ_CanControlAgent`, `WZ_CanManageSecurity`, `WZ_CanImpersonate`, `WZ_CanInjectEvents`, `WZ_CanExecuteAR`, `WZ_CanWriteConfig` |

---

## Prerequisites

- Python 3.10+
- A running [Wazuh](https://wazuh.com/) deployment (v4.x)
- A running [BloodHound CE](https://github.com/SpecterOps/BloodHound) instance

---

## Installation

```bash
git clone https://github.com/your-org/WazuhHound.git
cd WazuhHound

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run via the root launcher:

```bash
python3 WazuhHound.py --help
```

Or install locally to use the `wazuhhound` console entry point:

```bash
pip install -e .
wazuhhound --help
```

---

## Usage

```
wazuhhound [-h]
           [--wazuh-url WAZUH_URL]
           [--wazuh-user WAZUH_USER]
           [--wazuh-password WAZUH_PASSWORD]
           [--output OUTPUT]
           [--insecure] [--verbose] [--debug]
           [--skip-enrichment]
           [--indexer-url INDEXER_URL]
           [--indexer-user INDEXER_USER]
           [--indexer-password INDEXER_PASSWORD]
```

| Flag | Env var | Description |
| --- | --- | --- |
| `--wazuh-url` | `WAZUH_URL` | Wazuh manager URL (default port 55000) |
| `--wazuh-user` | `WAZUH_USERNAME` | Wazuh API username |
| `--wazuh-password` | `WAZUH_PASSWORD` | Wazuh API password |
| `--output` | `WAZUHHOUND_OUTPUT` | Output directory for JSON files |
| `--insecure` | `WAZUHHOUND_INSECURE` | Disable TLS verification |
| `--verbose` | `WAZUHHOUND_VERBOSE` | Enable informational logging |
| `--debug` | `WAZUHHOUND_DEBUG` | Enable debug logging (may log sensitive data) |
| `--skip-enrichment` | `WAZUHHOUND_SKIP_ENRICHMENT` | Skip per-agent enrichment (vulns, ports, packages, network segments) for faster collection |
| `--indexer-url` | `WAZUH_INDEXER_URL` | Indexer URL, e.g. `https://wazuh:9200` |
| `--indexer-user` | `WAZUH_INDEXER_USER` | Indexer admin username (defaults to `--wazuh-user`) |
| `--indexer-password` | `WAZUH_INDEXER_PASSWORD` | Indexer admin password (defaults to `--wazuh-password`) |

### Basic collection

```bash
wazuhhound \
  --wazuh-url https://wazuh-manager:55000 \
  --wazuh-user admin \
  --wazuh-password secret \
  --output ./output \
  --insecure
```

### Full collection with indexer

```bash
wazuhhound \
  --wazuh-url https://wazuh-manager:55000 \
  --wazuh-user admin \
  --wazuh-password secret \
  --indexer-url https://wazuh-manager:9200 \
  --indexer-user admin \
  --indexer-password secret \
  --output ./output \
  --insecure
```

### Fast RBAC-only collection (skip agent enrichment)

```bash
wazuhhound \
  --wazuh-url https://wazuh-manager:55000 \
  --wazuh-user admin \
  --wazuh-password secret \
  --output ./output \
  --skip-enrichment \
  --insecure
```

---

## BloodHound Setup

### 1. Upload the OpenGraph Schema

```bash
python3 helper-scripts/upload_schema.py \
  --url http://localhost:8080 \
  --username admin \
  --secret "$BLOODHOUND_SECRET"
```

The schema uses namespace `WZ`, registers 12 node kinds and 17 relationship kinds, and automatically enables the `opengraph_extension_management` feature flag.

### 2. Upload Custom Icons

```bash
python3 helper-scripts/upload_custom_icons.py \
  --url http://localhost:8080 \
  --username admin \
  --secret "$BLOODHOUND_SECRET"
```

| Node | Icon | Color |
| --- | --- | --- |
| `WZ_Agent` | laptop | `#3B82F6` |
| `WZ_AgentGroup` | users | `#F97316` |
| `WZ_ClusterNode` | server | `#8B5CF6` |
| `WZ_Cluster` | network-wired | `#1D4ED8` |
| `WZ_IndexerNode` | database | `#0EA5E9` |
| `WZ_IndexerCluster` | circle-nodes | `#0369A1` |
| `WZ_IndexerRole` | key | `#9D174D` |
| `WZ_NetworkSegment` | network-wired | `#0F766E` |
| `WZ_User` | user | `#7C3AED` |
| `WZ_Role` | id-badge | `#D97706` |
| `WZ_Policy` | scroll | `#0D9488` |
| `WZ_IndexerUser` | user-secret | `#BE185D` |

> [!WARNING]
> The helper removes existing `WZ_*` custom node types before uploading. Use it carefully on shared BloodHound instances.

### 3. Upload Saved Queries

```bash
python3 helper-scripts/upload_saved_queries.py \
  --url http://localhost:8080 \
  --username admin \
  --secret "$BLOODHOUND_SECRET"
```

> [!WARNING]
> This helper deletes the authenticated user's existing saved queries before uploading the WazuhHound query set.

### 4. Upload Collector Output

```bash
python3 helper-scripts/upload_ingest_files.py \
  --url http://localhost:8080 \
  --username admin \
  --secret "$BLOODHOUND_SECRET" \
  --verbose \
  ./output/wazuhhound_*.json
```

You can also drag-and-drop the generated JSON directly into the BloodHound CE web interface via **File Ingest**.

---

## Permissions Required

### Wazuh Manager API

| Resource | Permission |
| --- | --- |
| `agent:id:*` | `agent:read` |
| `group:id:*` | `group:read` |
| `cluster:*` | `cluster:read` |
| `*:*:*` | `indexer:read` |
| `*:*:*` | `security:read` |

The built-in `wazuh` and `wazuh-wui` users cover most of these. For `security:read` you may need a user with that policy explicitly assigned.

### Wazuh Indexer (OpenSearch)

Indexer internal user/role collection and vulnerability aggregation require the `admin` OpenSearch user (or equivalent) with access to `/_plugins/_security/api/` and `wazuh-states-vulnerabilities-*`.

---

## Example Queries

**Attack path - shortest path from any user to the Wazuh cluster:**

```cypher
MATCH (u:WZ_User), (c:WZ_Cluster)
WHERE u <> c
MATCH p = shortestPath((u)-[:WZ_HasRole|WZ_HasPolicy|WZ_CanManageSecurity|WZ_CanImpersonate|WZ_CanInjectEvents|WZ_CanExecuteAR*1..10]->(c))
RETURN p ORDER BY length(p)
```

**Attack path - all shortest paths to crown jewels:**

```cypher
MATCH (start), (end)
WHERE (start:WZ_User OR start:WZ_IndexerUser)
  AND (end:WZ_Cluster OR end:WZ_IndexerCluster)
  AND start <> end
MATCH p = allShortestPaths((start)-[:WZ_HasRole|WZ_HasPolicy|WZ_CanManageSecurity|WZ_CanControlAgent|WZ_CanImpersonate|WZ_CanInjectEvents|WZ_CanExecuteAR|WZ_MappedToRole|WZ_AccessesIndexer|WZ_CanReadIndex|WZ_CanWriteIndex*1..10]->(end))
RETURN p
```

**Attack path - privilege escalation via RBAC:**

```cypher
MATCH p=(u:WZ_User)-[:WZ_HasRole]->(:WZ_Role)-[:WZ_HasPolicy]->(:WZ_Policy)-[:WZ_CanManageSecurity]->(:WZ_Cluster)
RETURN p ORDER BY u.name
```

**Attack path - RCE on agents via active response:**

```cypher
MATCH p=()-[:WZ_CanExecuteAR]->(:WZ_Agent)
RETURN p
```

**Attack path - RCE on the manager itself (active response on agent 000):**

```cypher
MATCH p=()-[:WZ_CanExecuteAR]->(:WZ_Agent {is_manager: true})
RETURN p
```

**Attack path - manager config write (upload malicious AR script):**

```cypher
MATCH p=()-[:WZ_CanWriteConfig]->(:WZ_Cluster)
RETURN p
```

**Network - lateral movement between agents on the same subnet:**

```cypher
MATCH p=(a:WZ_Agent)-[:WZ_SharedSegment]->(b:WZ_Agent)
RETURN p ORDER BY a.name
```

**Attack path - event injection / log poisoning:**

```cypher
MATCH p=()-[:WZ_CanInjectEvents]->(:WZ_Cluster)
RETURN p
```

**Infrastructure - full path from agent to indexer:**

```cypher
MATCH p=(a:WZ_Agent)-[:WZ_ConnectedTo]->(n:WZ_ClusterNode)-[:WZ_PartOf]->(c:WZ_Cluster)-[:WZ_Monitors]->(ic:WZ_IndexerCluster)
RETURN p
```

**Network - multi-homed agents (pivot points):**

```cypher
MATCH (a:WZ_Agent)-[:WZ_InSegment]->(s:WZ_NetworkSegment)
WITH a, count(s) AS seg_count
WHERE seg_count > 1
RETURN a.name, seg_count ORDER BY seg_count DESC
```

**Agents - high risk (risk_score >= 7):**

```cypher
MATCH (a:WZ_Agent)
WHERE a.risk_score >= 7
RETURN a ORDER BY a.risk_score DESC
```

**Security - users with allow_run_as:**

```cypher
MATCH (u:WZ_User) WHERE u.allow_run_as = true RETURN u
```

---

## Traversable Edges

All 17 relationship kinds are marked `is_traversable: true` in `schema.json`, enabling BloodHound CE pathfinding through the full graph:

```
WZ_MemberOf         WZ_ConnectedTo      WZ_InSegment        WZ_SharedSegment
WZ_PartOf           WZ_ManagedBy        WZ_Monitors
WZ_HasRole          WZ_HasPolicy
WZ_AccessesIndexer  WZ_MappedToRole     WZ_CanReadIndex     WZ_CanWriteIndex
WZ_CanControlAgent  WZ_CanManageSecurity
WZ_CanImpersonate   WZ_CanInjectEvents  WZ_CanExecuteAR     WZ_CanWriteConfig
```

---

## Saved Queries

48 pre-built queries shipped in `SavedQueries/`.

| Category | Query | Purpose |
| --- | --- | --- |
| **Agents** | Agents - List | All agents |
| | Agents - Disconnected | Agents with `status = disconnected` |
| | Agents - Without Group | Agents not in any group |
| | Agents - Group Membership | Agent → group relationships |
| | Agents - Connected To Node | Agent → cluster node relationships |
| **Groups** | Groups - Empty | Groups with no agents |
| **Cluster** | Cluster - Overview | Manager cluster nodes |
| **Indexer** | Indexer - Overview | Indexer cluster and nodes |
| | Indexer - Master Nodes | Nodes with master role |
| | Indexer - Roles Overview | All OpenSearch roles |
| | Indexer - Admin Roles | Roles with full access |
| | Indexer - User Role Mapping | Indexer user → role assignments |
| | Indexer - User Full Path | Full path from indexer user to cluster |
| **Network** | Network - All Relationships | Full agent/cluster/indexer graph |
| | Network - Full Infrastructure | All infrastructure edges |
| | Network - Agent Full Path | Agent → Group → Cluster path |
| | Network - Infrastructure to Indexer | Cluster → Indexer link |
| | Network - Agent to Indexer | Full path from agent to indexer |
| | Network - Segments | Network segments and their agents |
| | Network - Pivot Points | Multi-homed agents on 2+ subnets |
| **Security** | Security - Users and Roles | User → role assignments |
| | Security - Full Permission Path | User → Role → Policy full path |
| | Security - Admin Users | Users in built-in admin roles |
| | Security - Allow Run As | Users with `allow_run_as = true` |
| | Security - Policies Allow Effect | All allow-effect policies |
| | Security - Indexer Internal Users | OpenSearch internal users |
| **Attack** | Attack - Full Chain | User → Role → Policy → impact |
| | Attack - Full Compromise Path | User to cluster control |
| | Attack - All Paths | All impact edges |
| | Attack - Privilege Escalation | Paths to `WZ_CanManageSecurity` |
| | Attack - Agent Control Paths | Paths to `WZ_CanControlAgent` |
| | Attack - Event Injection | Paths to `WZ_CanInjectEvents` |
| | Attack - Active Response Abuse | Paths to `WZ_CanExecuteAR` |
| | Attack - Impersonation | Users with `WZ_CanImpersonate` |
| | Attack - Indexer Read Access | Paths to `WZ_CanReadIndex` |
| | Attack - Indexer Write Access | Paths to `WZ_CanWriteIndex` |
| | Attack - RBAC Black Mode | Clusters with default-allow RBAC |
| | Attack - Critical CVE Agents | Agents with critical vulnerabilities |
| | Attack - High Risk Agents | Agents with risk_score >= 7 |
| | Attack - Path to Vulnerable Agent | User → agent with critical CVEs |
| | Attack - AR on Manager (Agent 000) | Active response paths targeting the manager self-agent |
| | Attack - Write Config (Manager RCE) | Policies with manager upload/config write = RCE path |
| **Network (lateral)** | Network - Lateral Movement | All `WZ_SharedSegment` edges between co-located agents |
| **Path** | Path - Inbound to Cluster | Shortest path from any user to cluster |
| | Path - Inbound to Indexer | Shortest path from any indexer user to indexer |
| | Path - All Shortest Paths to Crown Jewels | All shortest paths to high-value targets |
| | Path - Outbound from User | All targets reachable from a user |
| | Path - Users with Cluster Access | List of users who can reach the cluster |

---

## Environment Variables

```bash
# Wazuh Manager API
WAZUH_URL=https://wazuh-manager:55000
WAZUH_USERNAME=admin
WAZUH_PASSWORD=secret

# Wazuh Indexer (OpenSearch)
WAZUH_INDEXER_URL=https://wazuh-manager:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=secret

# Collector options
WAZUHHOUND_OUTPUT=./output
WAZUHHOUND_INSECURE=false
WAZUHHOUND_VERBOSE=false
WAZUHHOUND_DEBUG=false
WAZUHHOUND_SKIP_ENRICHMENT=false

# BloodHound CE (helper scripts)
BLOODHOUND_URL=http://localhost:8080
BLOODHOUND_USERNAME=admin
BLOODHOUND_SECRET=your_secret_here
```

Copy `example.env` to `.env` and fill in your values.

---

## Helper Scripts

| Script | Purpose |
| --- | --- |
| `helper-scripts/upload_schema.py` | Upload the OpenGraph extension schema (auto-enables feature flag) |
| `helper-scripts/upload_ingest_files.py` | Upload WazuhHound JSON files to BloodHound CE |
| `helper-scripts/upload_custom_icons.py` | Upload custom node icons and colors |
| `helper-scripts/upload_saved_queries.py` | Sync saved Cypher queries from `SavedQueries/` |
| `helper-scripts/clear_database.py` | Delete all `WZ_*` nodes from BloodHound CE |

> [!WARNING]
> `helper-scripts/clear_database.py` is destructive. Use it only against BloodHound instances where deleting WazuhHound data is intended.

---

## Limitations

- Agent properties reflect the last known state at collection time.
- Indexer node collection requires the `--indexer-url` flag or `WAZUH_INDEXER_URL`. Without it, indexer users, roles, and vulnerability data from OpenSearch are not collected.
- Vulnerability data requires either `--indexer-url` (Wazuh 4.8+, `wazuh-states-vulnerabilities-*` index) or the legacy `/vulnerability/{agent_id}` API (Wazuh ≤ 4.7).
- Security user/role/policy collection requires the `security:read` permission.
- Agent enrichment (vulns, ports, packages, network segments) makes one API call per agent per data type - use `--skip-enrichment` for large deployments when enrichment is not needed.
- `WZ_SharedSegment` edges are only generated for segments with 2-50 agents. Segments with more than 50 agents are skipped to avoid edge explosion on large flat networks.
- `WZ_CanWriteConfig` requires that the Wazuh policy explicitly lists `manager:upload`, `manager:*`, or `configuration:update` actions. Policies granted via `*:*` wildcards are also matched.
