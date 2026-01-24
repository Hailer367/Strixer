"""
Advanced Knowledge Graph Actions - RAG-powered Security Intelligence Tools.

This module provides tools for building and querying a semantic knowledge graph
that serves as the intelligence backbone for security operations. It enables
multi-hop reasoning, attack path discovery, and intelligent context retrieval.

KEY CAPABILITIES:
- Multi-hop graph traversal for deep context
- Attack path discovery between entities
- Automatic entity extraction and linking
- Pattern detection for vulnerability correlation
- Graph analytics and visualization export
- Cross-scope knowledge sharing
"""

import os
from typing import Any, Dict, List, Optional
from strix.tools.registry import register_tool
from strix.tools.knowledge_graph.graph_engine import (
    GraphEngine,
    NodeType,
    RelationType,
)


def _get_strixdb_actions():
    """Lazy import to avoid circular dependencies."""
    from strix.tools.strixdb import strixdb_actions
    return strixdb_actions


def _get_engine(target_scope: Optional[str] = None) -> GraphEngine:
    """Get or create a graph engine for the scope."""
    strixdb = _get_strixdb_actions()
    return GraphEngine.load_from_strixdb(strixdb, target_scope)


def _save_engine(engine: GraphEngine) -> bool:
    """Save the engine to StrixDB."""
    strixdb = _get_strixdb_actions()
    return engine.save_to_strixdb(strixdb)


@register_tool(sandbox_execution=False)
def link_entities(
    source_id: str,
    target_id: str,
    relation: str,
    properties: Optional[Dict[str, Any]] = None,
    target_scope: Optional[str] = None,
    confidence: float = 1.0,
    bidirectional: bool = False,
    evidence: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Link two entities in the Semantic Knowledge Graph with enhanced metadata.
    
    Use this to build relational intelligence between discovered assets.
    Common relations: POINTS_TO, HAS_SUBDOMAIN, RUNS_SERVICE, VULNERABLE_TO,
    EXPLOITED_BY, PROTECTED_BY, BYPASSED_WITH, CONTAINS, LEADS_TO.
    
    Example: link_entities("example.com", "1.2.3.4", "RESOLVES_TO")
    """
    engine = _get_engine(target_scope)
    
    # Ensure nodes exist with proper types
    if source_id not in engine.nodes:
        engine.add_node(source_id, NodeType.CUSTOM.value, source="link_operation")
    if target_id not in engine.nodes:
        engine.add_node(target_id, NodeType.CUSTOM.value, source="link_operation")
    
    engine.add_edge(
        source_id,
        target_id,
        relation,
        properties=properties,
        confidence=confidence,
        bidirectional=bidirectional,
        evidence=evidence or [],
    )
    
    if _save_engine(engine):
        return {
            "success": True,
            "message": f"Linked {source_id} to {target_id} via {relation}",
            "scope": target_scope or "Global",
            "edge": {
                "source": source_id,
                "target": target_id,
                "relation": relation,
                "confidence": confidence,
            },
        }
    return {"success": False, "message": "Failed to save graph update"}


@register_tool(sandbox_execution=False)
def get_entity_context(
    entity_id: str,
    target_scope: Optional[str] = None,
    depth: int = 2,
    include_risk: bool = True,
    include_patterns: bool = True,
    max_nodes: int = 50,
) -> Dict[str, Any]:
    """
    Advanced RAG context retrieval with multi-hop traversal.
    
    Retrieves comprehensive intelligence about an entity including:
    - All connected entities up to specified depth
    - Risk analysis and scoring
    - Attack pattern detection
    - Intelligence summary
    
    Use this BEFORE performing security operations to understand the target context.
    """
    engine = _get_engine(target_scope)
    
    context = engine.get_context(
        entity_id,
        depth=depth,
        include_risk=include_risk,
        include_patterns=include_patterns,
        max_nodes=max_nodes,
    )
    
    return {
        "success": True if "error" not in context else False,
        "entity": entity_id,
        "scope": target_scope or "Global",
        "context": context,
    }


@register_tool(sandbox_execution=False)
def add_entity(
    entity_id: str,
    entity_type: str,
    properties: Optional[Dict[str, Any]] = None,
    is_global: bool = False,
    target_scope: Optional[str] = None,
    confidence: float = 1.0,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Add an entity to the Knowledge Graph with specific type and properties.
    
    Supported types: IP, Domain, Subdomain, CVE, Service, Port, Technology,
    Endpoint, Parameter, Vulnerability, Credential, User, Bucket, API_Key,
    Secret, Certificate, WAF, CDN, Cloud_Resource, Network_Segment, Finding,
    Payload, Session, Custom.
    
    Example: add_entity("admin.example.com", "Subdomain", {"discovered_via": "subfinder"})
    """
    engine = _get_engine(target_scope)
    
    node = engine.add_node(
        entity_id,
        entity_type,
        properties=properties,
        is_global=is_global,
        confidence=confidence,
        tags=tags,
    )
    
    if _save_engine(engine):
        return {
            "success": True,
            "message": f"Added entity {entity_id} ({entity_type})",
            "scope": target_scope or "Global",
            "entity": {
                "id": entity_id,
                "type": entity_type,
                "risk_score": node.risk_score,
                "is_global": is_global,
            },
        }
    return {"success": False, "message": "Failed to save entity to graph"}


@register_tool(sandbox_execution=False)
def auto_link_findings(
    text: str,
    target_scope: Optional[str] = None,
    is_global: bool = False,
    source: str = "auto_extraction",
) -> Dict[str, Any]:
    """
    Automatically extract and link entities from text (scan output, reports, etc.).
    
    Extracts: IPs, domains, CVEs, CWEs, URLs, emails, API keys, S3 buckets,
    JWTs, private keys, hashes, and more.
    
    Use this to quickly build your knowledge base from tool output.
    """
    engine = _get_engine(target_scope)
    
    extracted = engine.auto_extract_entities(
        text,
        is_global=is_global,
        source=source,
    )
    
    total_extracted = sum(len(v) for v in extracted.values())
    
    if total_extracted > 0:
        if _save_engine(engine):
            return {
                "success": True,
                "message": f"Extracted and saved {total_extracted} entities.",
                "entities_by_type": extracted,
                "total_entities": total_extracted,
                "scope": target_scope or "Global",
            }
    
    return {
        "success": True,
        "message": "No new entities extracted.",
        "entities_by_type": {},
        "total_entities": 0,
    }


@register_tool(sandbox_execution=False)
def find_attack_paths(
    source_entity: str,
    target_type: str,
    target_scope: Optional[str] = None,
    max_depth: int = 5,
) -> Dict[str, Any]:
    """
    Find potential attack paths from a source entity to entities of a target type.
    
    Use this to discover exploitation chains and lateral movement opportunities.
    
    Example: find_attack_paths("external_ip", "Credential", max_depth=4)
    """
    engine = _get_engine(target_scope)
    
    paths = engine.find_attack_paths(source_entity, target_type, max_depth)
    
    formatted_paths = []
    for path in paths:
        path_info = []
        for i, node_id in enumerate(path):
            node = engine.nodes.get(node_id)
            path_info.append({
                "id": node_id,
                "type": node.type if node else "Unknown",
                "step": i + 1,
            })
        formatted_paths.append(path_info)
    
    return {
        "success": True,
        "source": source_entity,
        "target_type": target_type,
        "paths_found": len(paths),
        "attack_paths": formatted_paths,
        "max_depth_searched": max_depth,
    }


@register_tool(sandbox_execution=False)
def get_related_entities(
    entity_id: str,
    target_scope: Optional[str] = None,
    relation_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get all entities directly related to a specific entity.
    
    Optionally filter by relation type (VULNERABLE_TO, HAS_SUBDOMAIN, etc.)
    or entity type (CVE, Service, etc.).
    """
    engine = _get_engine(target_scope)
    
    related = engine.get_related_entities(
        entity_id,
        relation_filter=relation_filter,
        type_filter=type_filter,
    )
    
    return {
        "success": True,
        "entity": entity_id,
        "related_count": len(related),
        "related_entities": related,
        "filters_applied": {
            "relation": relation_filter,
            "type": type_filter,
        },
    }


@register_tool(sandbox_execution=False)
def infer_relationships(
    target_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Automatically infer relationships between entities based on patterns.
    
    Detects: subdomain hierarchies, CVE-technology correlations,
    and other logical connections.
    """
    engine = _get_engine(target_scope)
    
    inferred = engine.infer_relationships()
    
    if inferred and _save_engine(engine):
        return {
            "success": True,
            "message": f"Inferred {len(inferred)} new relationships.",
            "inferred_count": len(inferred),
            "relationships": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "confidence": e.confidence,
                }
                for e in inferred[:20]  # Limit output
            ],
        }
    
    return {
        "success": True,
        "message": "No new relationships inferred.",
        "inferred_count": 0,
    }


@register_tool(sandbox_execution=False)
def get_graph_statistics(
    target_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Get comprehensive statistics about the knowledge graph.
    
    Returns node counts by type, edge counts by relation, query stats, etc.
    """
    engine = _get_engine(target_scope)
    stats = engine.get_graph_statistics()
    
    return {
        "success": True,
        "scope": target_scope or "Global",
        "statistics": stats,
    }


@register_tool(sandbox_execution=False)
def export_graph_visualization(
    target_scope: Optional[str] = None,
    format: str = "cytoscape",
) -> Dict[str, Any]:
    """
    Export the knowledge graph for visualization.
    
    Formats:
    - cytoscape: Cytoscape.js JSON format (for web visualization)
    - neo4j: Neo4j Cypher statements (for graph database import)
    """
    engine = _get_engine(target_scope)
    
    if format == "cytoscape":
        data = engine.export_to_cytoscape()
        return {
            "success": True,
            "format": "cytoscape",
            "data": data,
            "node_count": len(data["nodes"]),
            "edge_count": len(data["edges"]),
        }
    elif format == "neo4j":
        cypher = engine.export_to_neo4j_cypher()
        return {
            "success": True,
            "format": "neo4j",
            "cypher_statements": cypher,
            "statement_count": cypher.count(";") + 1 if cypher else 0,
        }
    else:
        return {
            "success": False,
            "error": f"Unknown format: {format}. Supported: cytoscape, neo4j",
        }


@register_tool(sandbox_execution=False)
def merge_graphs(
    source_scope: str,
    target_scope: str,
) -> Dict[str, Any]:
    """
    Merge knowledge from one scope into another.
    
    Useful for combining intelligence from multiple engagements
    or importing global knowledge into a project.
    """
    source_engine = _get_engine(source_scope)
    target_engine = _get_engine(target_scope)
    
    original_nodes = len(target_engine.nodes)
    original_edges = len(target_engine.edges)
    
    target_engine.merge_graph(source_engine)
    
    if _save_engine(target_engine):
        return {
            "success": True,
            "message": f"Merged {source_scope} into {target_scope}",
            "nodes_added": len(target_engine.nodes) - original_nodes,
            "edges_added": len(target_engine.edges) - original_edges,
            "total_nodes": len(target_engine.nodes),
            "total_edges": len(target_engine.edges),
        }
    
    return {"success": False, "message": "Failed to save merged graph"}


@register_tool(sandbox_execution=False)
def query_by_type(
    entity_type: str,
    target_scope: Optional[str] = None,
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Query all entities of a specific type in the graph.
    
    Useful for enumeration: "Show me all CVEs" or "List all discovered endpoints"
    """
    engine = _get_engine(target_scope)
    
    node_ids = list(engine._nodes_by_type.get(entity_type, set()))[:limit]
    
    entities = []
    for node_id in node_ids:
        node = engine.nodes.get(node_id)
        if node:
            entities.append({
                "id": node_id,
                "type": node.type,
                "risk_score": node.risk_score,
                "properties": node.properties,
                "tags": node.tags,
            })
    
    return {
        "success": True,
        "entity_type": entity_type,
        "count": len(entities),
        "entities": entities,
        "limit_applied": limit,
    }


@register_tool(sandbox_execution=False)
def get_high_risk_entities(
    target_scope: Optional[str] = None,
    min_risk_score: float = 0.7,
    limit: int = 20,
) -> Dict[str, Any]:
    """
    Get all high-risk entities in the graph.
    
    Risk scores are calculated based on entity type and confidence.
    Use this to prioritize testing efforts.
    """
    engine = _get_engine(target_scope)
    
    high_risk = []
    for node_id, node in engine.nodes.items():
        if node.risk_score >= min_risk_score:
            high_risk.append({
                "id": node_id,
                "type": node.type,
                "risk_score": node.risk_score,
                "properties": node.properties,
            })
    
    # Sort by risk score descending
    high_risk.sort(key=lambda x: -x["risk_score"])
    
    return {
        "success": True,
        "min_risk_threshold": min_risk_score,
        "count": len(high_risk),
        "high_risk_entities": high_risk[:limit],
    }


@register_tool(sandbox_execution=False)
def add_vulnerability_context(
    cve_id: str,
    affected_product: str,
    severity: str,
    description: str = "",
    cvss_score: Optional[float] = None,
    exploit_available: bool = False,
    target_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Add detailed vulnerability context to the graph.
    
    Links the CVE to affected technologies and calculates risk propagation.
    """
    engine = _get_engine(target_scope)
    
    # Add CVE node with detailed properties
    properties = {
        "affected_product": affected_product,
        "severity": severity,
        "description": description,
        "exploit_available": exploit_available,
    }
    if cvss_score:
        properties["cvss_score"] = cvss_score
    
    engine.add_node(
        cve_id,
        NodeType.CVE.value,
        properties=properties,
        is_global=True,  # CVEs are always global
        confidence=1.0,
    )
    
    # Try to link to existing technologies
    technologies = list(engine._nodes_by_type.get(NodeType.TECHNOLOGY.value, set()))
    linked_count = 0
    
    for tech_id in technologies:
        if (affected_product.lower() in tech_id.lower() or 
            tech_id.lower() in affected_product.lower()):
            engine.add_edge(
                tech_id,
                cve_id,
                RelationType.VULNERABLE_TO.value,
                confidence=0.8,
            )
            linked_count += 1
    
    if _save_engine(engine):
        return {
            "success": True,
            "message": f"Added vulnerability context for {cve_id}",
            "cve_id": cve_id,
            "technologies_linked": linked_count,
        }
    
    return {"success": False, "message": "Failed to save vulnerability context"}


@register_tool(sandbox_execution=False)
def record_waf_bypass(
    waf_type: str,
    original_payload: str,
    bypass_payload: str,
    target_url: str,
    bypass_technique: str,
    target_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Record a successful WAF bypass in the knowledge graph.
    
    This creates a knowledge trail that can be reused in future engagements.
    """
    engine = _get_engine(target_scope)
    
    # Create WAF node
    waf_id = f"WAF_{waf_type}"
    engine.add_node(
        waf_id,
        NodeType.WAF.value,
        properties={"vendor": waf_type},
    )
    
    # Create payload node
    import hashlib
    payload_hash = hashlib.md5(bypass_payload.encode()).hexdigest()[:8]
    payload_id = f"Payload_{bypass_technique}_{payload_hash}"
    
    engine.add_node(
        payload_id,
        NodeType.PAYLOAD.value,
        properties={
            "original": original_payload,
            "bypass": bypass_payload,
            "technique": bypass_technique,
            "target_url": target_url,
        },
        is_global=True,  # Share bypass knowledge globally
    )
    
    # Link: WAF --BYPASSED_WITH--> Payload
    engine.add_edge(
        waf_id,
        payload_id,
        RelationType.BYPASSED_WITH.value,
        properties={"target_url": target_url},
        evidence=[f"Successfully bypassed at {target_url}"],
    )
    
    if _save_engine(engine):
        return {
            "success": True,
            "message": f"Recorded WAF bypass: {waf_type} via {bypass_technique}",
            "waf_id": waf_id,
            "payload_id": payload_id,
            "is_global": True,
        }
    
    return {"success": False, "message": "Failed to record WAF bypass"}


@register_tool(sandbox_execution=False)
def get_waf_bypass_history(
    waf_type: Optional[str] = None,
    target_scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Retrieve known WAF bypass techniques from the knowledge graph.
    
    Use this before attempting WAF evasion to leverage past successful bypasses.
    """
    # Check both global and scoped knowledge
    engines = []
    
    if target_scope:
        engines.append(_get_engine(target_scope))
    engines.append(_get_engine(None))  # Global
    
    bypasses = []
    seen_payloads = set()
    
    for engine in engines:
        # Find all WAF bypass relationships
        for edge in engine._edges_by_relation.get(RelationType.BYPASSED_WITH.value, []):
            if edge.target in seen_payloads:
                continue
            
            waf_node = engine.nodes.get(edge.source)
            payload_node = engine.nodes.get(edge.target)
            
            if not waf_node or not payload_node:
                continue
            
            if waf_type and waf_node.properties.get("vendor", "").lower() != waf_type.lower():
                continue
            
            seen_payloads.add(edge.target)
            bypasses.append({
                "waf_type": waf_node.properties.get("vendor", "Unknown"),
                "technique": payload_node.properties.get("technique", "Unknown"),
                "original_payload": payload_node.properties.get("original", ""),
                "bypass_payload": payload_node.properties.get("bypass", ""),
                "confidence": edge.confidence,
            })
    
    return {
        "success": True,
        "waf_filter": waf_type,
        "bypasses_found": len(bypasses),
        "bypasses": bypasses,
    }
