"""BloodHound kind naming helpers for the WazuhHound extension."""

NAMESPACE = "WZ"
BASE_KIND = f"{NAMESPACE}_Base"

TRAVERSABLE_EDGE_KINDS = frozenset(
    {
        "WZ_MemberOf",
        "WZ_ConnectedTo",
        "WZ_PartOf",
"WZ_ManagedBy",
        "WZ_Monitors",
        "WZ_HasRole",
        "WZ_HasPolicy",
        "WZ_AccessesIndexer",
        "WZ_MappedToRole",
        "WZ_CanControlAgent",
        "WZ_CanManageSecurity",
        "WZ_CanReadIndex",
        "WZ_CanWriteIndex",
        "WZ_InSegment",
        "WZ_CanImpersonate",
        "WZ_CanInjectEvents",
        "WZ_CanExecuteAR",
        "WZ_CanWriteConfig",
        "WZ_SharedSegment",
        "WZ_AutoAssigns",
        "WZ_AppliesTo",
    }
)


def wz_kind(kind: str) -> str:
    """Return the BloodHound extension-prefixed form for a WazuhHound kind."""
    if not isinstance(kind, str) or not kind:
        return kind
    if kind.startswith(f"{NAMESPACE}_"):
        return kind
    return f"{NAMESPACE}_{kind}"


def is_traversable_edge(kind: str) -> bool:
    return wz_kind(kind) in {wz_kind(k) for k in TRAVERSABLE_EDGE_KINDS}


def apply_bloodhound_names(opengraph: dict) -> dict:
    """Prefix WazuhHound node and relationship kinds in an OpenGraph export."""
    graph = opengraph.get("graph") if isinstance(opengraph.get("graph"), dict) else opengraph

    metadata = opengraph.get("metadata")
    if isinstance(metadata, dict) and metadata.get("source_kind"):
        metadata["source_kind"] = wz_kind(metadata["source_kind"])

    for node in graph.get("nodes", []) or []:
        if not isinstance(node, dict):
            continue
        kinds = node.get("kinds")
        if isinstance(kinds, list):
            node["kinds"] = [wz_kind(k) for k in kinds]

    for edge in graph.get("edges", []) or []:
        if isinstance(edge, dict) and edge.get("kind"):
            edge["kind"] = wz_kind(edge["kind"])

    return opengraph
