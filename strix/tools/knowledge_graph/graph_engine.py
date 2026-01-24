"""
Advanced Semantic Knowledge Graph Engine for RAG-powered Security Intelligence.

This module provides a sophisticated graph-based knowledge representation system
with multi-hop traversal, semantic similarity, pattern detection, and intelligent
context retrieval for security operations.

KEY FEATURES:
- Multi-hop graph traversal with configurable depth
- Semantic similarity scoring for entity relationships
- Attack path discovery and visualization
- Intelligent context aggregation for RAG
- Pattern detection for attack surface mapping
- Cross-scope knowledge sharing (global CVEs, local assets)
- Graph analytics for vulnerability correlation
"""

import json
import os
import re
import hashlib
import math
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set, Tuple, Callable
from datetime import datetime
from collections import defaultdict
from enum import Enum


class NodeType(Enum):
    """Standardized node types for the knowledge graph."""
    IP = "IP"
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    CVE = "CVE"
    SERVICE = "Service"
    PORT = "Port"
    TECHNOLOGY = "Technology"
    ENDPOINT = "Endpoint"
    PARAMETER = "Parameter"
    VULNERABILITY = "Vulnerability"
    CREDENTIAL = "Credential"
    USER = "User"
    BUCKET = "Bucket"
    API_KEY = "API_Key"
    SECRET = "Secret"
    CERTIFICATE = "Certificate"
    WAF = "WAF"
    CDN = "CDN"
    CLOUD_RESOURCE = "Cloud_Resource"
    NETWORK_SEGMENT = "Network_Segment"
    FINDING = "Finding"
    PAYLOAD = "Payload"
    SESSION = "Session"
    CUSTOM = "Custom"


class RelationType(Enum):
    """Standardized relationship types."""
    POINTS_TO = "POINTS_TO"
    RESOLVES_TO = "RESOLVES_TO"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RUNS_SERVICE = "RUNS_SERVICE"
    HAS_PORT = "HAS_PORT"
    USES_TECHNOLOGY = "USES_TECHNOLOGY"
    VULNERABLE_TO = "VULNERABLE_TO"
    EXPLOITED_BY = "EXPLOITED_BY"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    ACCESSES = "ACCESSES"
    CONTAINS = "CONTAINS"
    BELONGS_TO = "BELONGS_TO"
    PROTECTED_BY = "PROTECTED_BY"
    BYPASSED_WITH = "BYPASSED_WITH"
    DISCOVERED_VIA = "DISCOVERED_VIA"
    RELATED_TO = "RELATED_TO"
    LEADS_TO = "LEADS_TO"
    DEPENDS_ON = "DEPENDS_ON"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    SAME_AS = "SAME_AS"


@dataclass
class Node:
    """Enhanced node with semantic metadata and scoring."""
    id: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 1.0  # Confidence score (0-1)
    source: str = "manual"  # How was this node discovered
    tags: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # Calculated risk score
    access_count: int = 0  # How many times this node was queried
    last_accessed: Optional[str] = None
    
    def __post_init__(self):
        if not self.tags:
            self.tags = []


@dataclass
class Edge:
    """Enhanced edge with temporal and confidence metadata."""
    source: str
    target: str
    relation: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 1.0  # Confidence in this relationship
    weight: float = 1.0  # Weight for pathfinding
    bidirectional: bool = False  # Is this relationship bidirectional?
    evidence: List[str] = field(default_factory=list)  # Evidence supporting this edge
    
    def __post_init__(self):
        if not self.evidence:
            self.evidence = []


@dataclass
class TraversalResult:
    """Result of a graph traversal operation."""
    paths: List[List[str]]
    nodes: Dict[str, Node]
    edges: List[Edge]
    depth_reached: int
    total_nodes_visited: int
    risk_aggregation: float


@dataclass
class PatternMatch:
    """A detected pattern in the graph."""
    pattern_type: str
    matched_nodes: List[str]
    matched_edges: List[Tuple[str, str, str]]
    confidence: float
    description: str
    recommendations: List[str]


class GraphEngine:
    """
    Advanced Semantic Knowledge Graph Engine.
    
    Provides sophisticated graph operations for security intelligence:
    - Multi-hop traversal with depth control
    - Semantic similarity and pattern detection
    - Attack path discovery
    - Intelligent RAG context generation
    """
    
    # Entity extraction patterns
    EXTRACTION_PATTERNS = {
        "ip_v4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ip_v6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        "cve": r'CVE-\d{4}-\d{4,}',
        "cwe": r'CWE-\d+',
        "port": r'\b(?:port\s*)?(\d{1,5})(?:/(?:tcp|udp))?\b',
        "url": r'https?://[^\s<>"\']+',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "hash_md5": r'\b[a-fA-F0-9]{32}\b',
        "hash_sha1": r'\b[a-fA-F0-9]{40}\b',
        "hash_sha256": r'\b[a-fA-F0-9]{64}\b',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "s3_bucket": r's3://[a-z0-9][-a-z0-9.]{1,61}[a-z0-9]',
        "jwt": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "api_key_generic": r'(?:api[_-]?key|apikey|api_secret|secret_key)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
        "private_key": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "internal_ip": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "mac_address": r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',
        "version": r'\b[vV]?(\d+\.)+\d+(?:-[a-zA-Z0-9]+)?\b',
    }
    
    # Risk scoring weights by node type
    RISK_WEIGHTS = {
        NodeType.CVE.value: 0.9,
        NodeType.VULNERABILITY.value: 0.85,
        NodeType.CREDENTIAL.value: 0.95,
        NodeType.SECRET.value: 0.95,
        NodeType.API_KEY.value: 0.9,
        NodeType.ENDPOINT.value: 0.3,
        NodeType.SERVICE.value: 0.4,
        NodeType.TECHNOLOGY.value: 0.2,
        NodeType.IP.value: 0.1,
        NodeType.DOMAIN.value: 0.1,
    }
    
    # Attack pattern templates
    ATTACK_PATTERNS = {
        "credential_leak": {
            "path": [NodeType.ENDPOINT.value, NodeType.CREDENTIAL.value],
            "description": "Potential credential exposure via endpoint"
        },
        "vulnerable_service": {
            "path": [NodeType.SERVICE.value, NodeType.CVE.value],
            "description": "Service with known vulnerability"
        },
        "waf_bypass": {
            "path": [NodeType.WAF.value, NodeType.PAYLOAD.value, NodeType.VULNERABILITY.value],
            "description": "WAF bypass leading to vulnerability"
        },
        "lateral_movement": {
            "path": [NodeType.IP.value, NodeType.SERVICE.value, NodeType.CREDENTIAL.value, NodeType.IP.value],
            "description": "Potential lateral movement path"
        },
        "cloud_misconfiguration": {
            "path": [NodeType.CLOUD_RESOURCE.value, NodeType.SECRET.value],
            "description": "Cloud resource exposing secrets"
        },
    }
    
    # Common exclusion patterns for extraction
    EXTRACTION_EXCLUSIONS = {
        "domain": {
            "google.com", "duckduckgo.com", "bing.com", "yahoo.com",
            "github.com", "githubusercontent.com", "example.com",
            "localhost", "test.com", "schema.org", "w3.org"
        }
    }
    
    def __init__(self, target_scope: Optional[str] = None):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.target_scope = target_scope
        self.global_nodes: Set[str] = set()
        
        # Indexing structures for fast lookup
        self._edges_by_source: Dict[str, List[Edge]] = defaultdict(list)
        self._edges_by_target: Dict[str, List[Edge]] = defaultdict(list)
        self._edges_by_relation: Dict[str, List[Edge]] = defaultdict(list)
        self._nodes_by_type: Dict[str, Set[str]] = defaultdict(set)
        
        # Caching
        self._context_cache: Dict[str, Tuple[datetime, Dict]] = {}
        self._cache_ttl_seconds = 300  # 5 minutes
        
        # Statistics
        self._stats = {
            "total_queries": 0,
            "cache_hits": 0,
            "traversals": 0,
            "entities_extracted": 0,
        }
    
    def _rebuild_indices(self) -> None:
        """Rebuild all indices from current data."""
        self._edges_by_source.clear()
        self._edges_by_target.clear()
        self._edges_by_relation.clear()
        self._nodes_by_type.clear()
        
        for edge in self.edges:
            self._edges_by_source[edge.source].append(edge)
            self._edges_by_target[edge.target].append(edge)
            self._edges_by_relation[edge.relation].append(edge)
        
        for node_id, node in self.nodes.items():
            self._nodes_by_type[node.type].add(node_id)
    
    def add_node(
        self,
        node_id: str,
        node_type: str,
        properties: Optional[Dict[str, Any]] = None,
        is_global: bool = False,
        confidence: float = 1.0,
        source: str = "manual",
        tags: Optional[List[str]] = None,
    ) -> Node:
        """Add or update a node with enhanced metadata."""
        now = datetime.now().isoformat()
        
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.updated_at = now
            if properties:
                node.properties.update(properties)
            if tags:
                node.tags = list(set(node.tags + tags))
            # Update confidence if new source is more reliable
            if confidence > node.confidence:
                node.confidence = confidence
                node.source = source
        else:
            node = Node(
                id=node_id,
                type=node_type,
                properties=properties or {},
                confidence=confidence,
                source=source,
                tags=tags or [],
                created_at=now,
                updated_at=now,
            )
            self.nodes[node_id] = node
            self._nodes_by_type[node_type].add(node_id)
        
        # Calculate risk score based on type
        node.risk_score = self.RISK_WEIGHTS.get(node_type, 0.1) * confidence
        
        if is_global:
            self.global_nodes.add(node_id)
        
        # Invalidate cache for related contexts
        self._invalidate_related_cache(node_id)
        
        return node
    
    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        weight: float = 1.0,
        bidirectional: bool = False,
        evidence: Optional[List[str]] = None,
    ) -> Edge:
        """Add an edge with enhanced metadata."""
        # Auto-create nodes if they don't exist
        if source not in self.nodes:
            self.add_node(source, NodeType.CUSTOM.value, source="auto_edge")
        if target not in self.nodes:
            self.add_node(target, NodeType.CUSTOM.value, source="auto_edge")
        
        # Check for existing edge
        existing = self._find_edge(source, target, relation)
        if existing:
            # Update existing edge
            if properties:
                existing.properties.update(properties)
            if evidence:
                existing.evidence.extend(evidence)
            existing.confidence = max(existing.confidence, confidence)
            return existing
        
        edge = Edge(
            source=source,
            target=target,
            relation=relation,
            properties=properties or {},
            confidence=confidence,
            weight=weight,
            bidirectional=bidirectional,
            evidence=evidence or [],
        )
        
        self.edges.append(edge)
        self._edges_by_source[source].append(edge)
        self._edges_by_target[target].append(edge)
        self._edges_by_relation[relation].append(edge)
        
        # Invalidate cache
        self._invalidate_related_cache(source)
        self._invalidate_related_cache(target)
        
        return edge
    
    def _find_edge(self, source: str, target: str, relation: str) -> Optional[Edge]:
        """Find an existing edge."""
        for edge in self._edges_by_source.get(source, []):
            if edge.target == target and edge.relation == relation:
                return edge
        return None
    
    def _invalidate_related_cache(self, node_id: str) -> None:
        """Invalidate cache entries related to a node."""
        keys_to_remove = [k for k in self._context_cache if node_id in k]
        for key in keys_to_remove:
            del self._context_cache[key]
    
    def get_context(
        self,
        node_id: str,
        depth: int = 2,
        include_risk: bool = True,
        include_patterns: bool = True,
        max_nodes: int = 50,
    ) -> Dict[str, Any]:
        """
        Advanced context retrieval for RAG with multi-hop traversal.
        
        This is the primary method for getting intelligence about an entity
        before performing security operations.
        """
        self._stats["total_queries"] += 1
        
        # Check cache
        cache_key = f"{node_id}_{depth}_{include_risk}_{include_patterns}"
        if cache_key in self._context_cache:
            cached_time, cached_result = self._context_cache[cache_key]
            if (datetime.now() - cached_time).total_seconds() < self._cache_ttl_seconds:
                self._stats["cache_hits"] += 1
                return cached_result
        
        if node_id not in self.nodes:
            return {"error": "Node not found", "node_id": node_id}
        
        # Update access tracking
        node = self.nodes[node_id]
        node.access_count += 1
        node.last_accessed = datetime.now().isoformat()
        
        # Perform multi-hop traversal
        traversal = self._multi_hop_traversal(node_id, depth, max_nodes)
        
        # Build context
        context = {
            "node": asdict(node),
            "scope": self.target_scope or "Global",
            "traversal": {
                "depth_reached": traversal.depth_reached,
                "total_nodes": traversal.total_nodes_visited,
                "paths_found": len(traversal.paths),
            },
            "relationships": self._format_relationships(traversal),
            "connected_entities": {
                node_type: [asdict(traversal.nodes[nid]) for nid in nids if nid in traversal.nodes]
                for node_type, nids in self._group_nodes_by_type(traversal.nodes).items()
            },
        }
        
        if include_risk:
            context["risk_analysis"] = self._analyze_risk(node_id, traversal)
        
        if include_patterns:
            patterns = self._detect_patterns(node_id, traversal)
            if patterns:
                context["detected_patterns"] = [
                    {
                        "type": p.pattern_type,
                        "confidence": p.confidence,
                        "description": p.description,
                        "recommendations": p.recommendations,
                    }
                    for p in patterns
                ]
        
        # Add intelligence summary
        context["intelligence_summary"] = self._generate_intelligence_summary(node_id, traversal)
        
        # Cache result
        self._context_cache[cache_key] = (datetime.now(), context)
        
        return context
    
    def _multi_hop_traversal(
        self,
        start_node: str,
        max_depth: int,
        max_nodes: int,
    ) -> TraversalResult:
        """Perform multi-hop graph traversal with BFS."""
        self._stats["traversals"] += 1
        
        visited: Set[str] = set()
        paths: List[List[str]] = []
        collected_nodes: Dict[str, Node] = {}
        collected_edges: List[Edge] = []
        
        # BFS queue: (current_node, current_path, current_depth)
        queue: List[Tuple[str, List[str], int]] = [(start_node, [start_node], 0)]
        
        while queue and len(visited) < max_nodes:
            current, path, depth = queue.pop(0)
            
            if current in visited:
                continue
            
            visited.add(current)
            
            if current in self.nodes:
                collected_nodes[current] = self.nodes[current]
            
            if depth >= max_depth:
                paths.append(path)
                continue
            
            # Get outgoing edges
            outgoing = self._edges_by_source.get(current, [])
            incoming = self._edges_by_target.get(current, [])
            
            has_children = False
            for edge in outgoing:
                if edge.target not in visited:
                    collected_edges.append(edge)
                    queue.append((edge.target, path + [edge.target], depth + 1))
                    has_children = True
            
            # Also traverse incoming edges (reverse relationships)
            for edge in incoming:
                if edge.source not in visited:
                    collected_edges.append(edge)
                    queue.append((edge.source, path + [edge.source], depth + 1))
                    has_children = True
            
            if not has_children:
                paths.append(path)
        
        # Calculate risk aggregation
        risk_sum = sum(
            collected_nodes[nid].risk_score
            for nid in collected_nodes
            if nid != start_node
        )
        
        return TraversalResult(
            paths=paths,
            nodes=collected_nodes,
            edges=collected_edges,
            depth_reached=max_depth,
            total_nodes_visited=len(visited),
            risk_aggregation=risk_sum,
        )
    
    def _format_relationships(self, traversal: TraversalResult) -> List[Dict[str, Any]]:
        """Format relationships for context output."""
        relationships = []
        seen = set()
        
        for edge in traversal.edges:
            key = (edge.source, edge.target, edge.relation)
            if key in seen:
                continue
            seen.add(key)
            
            source_node = traversal.nodes.get(edge.source)
            target_node = traversal.nodes.get(edge.target)
            
            relationships.append({
                "source": {
                    "id": edge.source,
                    "type": source_node.type if source_node else "Unknown",
                },
                "relation": edge.relation,
                "target": {
                    "id": edge.target,
                    "type": target_node.type if target_node else "Unknown",
                },
                "confidence": edge.confidence,
                "properties": edge.properties,
            })
        
        return relationships
    
    def _group_nodes_by_type(self, nodes: Dict[str, Node]) -> Dict[str, List[str]]:
        """Group node IDs by their type."""
        grouped: Dict[str, List[str]] = defaultdict(list)
        for node_id, node in nodes.items():
            grouped[node.type].append(node_id)
        return dict(grouped)
    
    def _analyze_risk(self, root_node: str, traversal: TraversalResult) -> Dict[str, Any]:
        """Analyze risk based on connected entities."""
        risk_analysis = {
            "overall_risk_score": 0.0,
            "risk_factors": [],
            "high_risk_entities": [],
            "vulnerability_connections": [],
        }
        
        total_risk = 0.0
        
        for node_id, node in traversal.nodes.items():
            if node_id == root_node:
                continue
            
            total_risk += node.risk_score
            
            if node.risk_score > 0.7:
                risk_analysis["high_risk_entities"].append({
                    "id": node_id,
                    "type": node.type,
                    "risk_score": node.risk_score,
                })
            
            if node.type in [NodeType.CVE.value, NodeType.VULNERABILITY.value]:
                risk_analysis["vulnerability_connections"].append({
                    "id": node_id,
                    "type": node.type,
                    "properties": node.properties,
                })
        
        # Normalize risk score
        if traversal.total_nodes_visited > 1:
            risk_analysis["overall_risk_score"] = min(1.0, total_risk / (traversal.total_nodes_visited - 1))
        
        # Identify risk factors
        if risk_analysis["vulnerability_connections"]:
            risk_analysis["risk_factors"].append("Connected to known vulnerabilities")
        if len(risk_analysis["high_risk_entities"]) > 3:
            risk_analysis["risk_factors"].append("Multiple high-risk connections")
        
        return risk_analysis
    
    def _detect_patterns(self, root_node: str, traversal: TraversalResult) -> List[PatternMatch]:
        """Detect attack patterns in the graph."""
        patterns: List[PatternMatch] = []
        
        for pattern_name, pattern_def in self.ATTACK_PATTERNS.items():
            expected_path = pattern_def["path"]
            matches = self._find_pattern_matches(root_node, expected_path, traversal)
            
            for match in matches:
                patterns.append(PatternMatch(
                    pattern_type=pattern_name,
                    matched_nodes=match["nodes"],
                    matched_edges=match["edges"],
                    confidence=match["confidence"],
                    description=pattern_def["description"],
                    recommendations=self._get_pattern_recommendations(pattern_name),
                ))
        
        return patterns
    
    def _find_pattern_matches(
        self,
        root: str,
        expected_types: List[str],
        traversal: TraversalResult,
    ) -> List[Dict[str, Any]]:
        """Find paths matching a pattern of node types."""
        matches = []
        
        for path in traversal.paths:
            if len(path) < len(expected_types):
                continue
            
            # Sliding window match
            for i in range(len(path) - len(expected_types) + 1):
                window = path[i:i + len(expected_types)]
                types_match = True
                confidence = 1.0
                
                for j, node_id in enumerate(window):
                    if node_id not in traversal.nodes:
                        types_match = False
                        break
                    if traversal.nodes[node_id].type != expected_types[j]:
                        types_match = False
                        break
                    confidence *= traversal.nodes[node_id].confidence
                
                if types_match:
                    edges = []
                    for k in range(len(window) - 1):
                        edge = self._find_edge(window[k], window[k + 1], None)
                        if edge:
                            edges.append((edge.source, edge.target, edge.relation))
                    
                    matches.append({
                        "nodes": window,
                        "edges": edges,
                        "confidence": confidence,
                    })
        
        return matches
    
    def _get_pattern_recommendations(self, pattern_name: str) -> List[str]:
        """Get security recommendations for a pattern."""
        recommendations = {
            "credential_leak": [
                "Review endpoint for authentication bypass",
                "Check for exposed credentials in response",
                "Test for IDOR vulnerabilities",
            ],
            "vulnerable_service": [
                "Verify CVE applicability to service version",
                "Check for public exploits",
                "Test with relevant PoC",
            ],
            "waf_bypass": [
                "Document successful bypass technique",
                "Test additional payload variations",
                "Report WAF misconfiguration",
            ],
            "lateral_movement": [
                "Map additional network access",
                "Test credential reuse",
                "Document lateral movement path",
            ],
            "cloud_misconfiguration": [
                "Enumerate exposed secrets",
                "Check IAM policies",
                "Test for privilege escalation",
            ],
        }
        return recommendations.get(pattern_name, ["Investigate further"])
    
    def _generate_intelligence_summary(
        self,
        root_node: str,
        traversal: TraversalResult,
    ) -> str:
        """Generate a human-readable intelligence summary."""
        node = self.nodes.get(root_node)
        if not node:
            return "No intelligence available"
        
        lines = [f"Intelligence Summary for {root_node} ({node.type})"]
        lines.append(f"- Connected to {traversal.total_nodes_visited - 1} other entities")
        
        # Count by type
        type_counts = defaultdict(int)
        for nid, n in traversal.nodes.items():
            if nid != root_node:
                type_counts[n.type] += 1
        
        if type_counts:
            lines.append("- Connected entity types:")
            for t, c in sorted(type_counts.items(), key=lambda x: -x[1])[:5]:
                lines.append(f"  - {t}: {c}")
        
        # Risk summary
        high_risk = [n for n in traversal.nodes.values() if n.risk_score > 0.7]
        if high_risk:
            lines.append(f"- High-risk connections: {len(high_risk)}")
        
        return "\n".join(lines)
    
    def find_attack_paths(
        self,
        source: str,
        target_type: str,
        max_depth: int = 5,
    ) -> List[List[str]]:
        """Find all paths from source to nodes of target type."""
        paths = []
        target_nodes = self._nodes_by_type.get(target_type, set())
        
        if not target_nodes:
            return []
        
        # BFS to find paths
        queue: List[Tuple[str, List[str]]] = [(source, [source])]
        visited: Set[Tuple[str, ...]] = set()
        
        while queue:
            current, path = queue.pop(0)
            
            if len(path) > max_depth:
                continue
            
            path_tuple = tuple(path)
            if path_tuple in visited:
                continue
            visited.add(path_tuple)
            
            if current in target_nodes and len(path) > 1:
                paths.append(path)
                continue
            
            for edge in self._edges_by_source.get(current, []):
                if edge.target not in path:
                    queue.append((edge.target, path + [edge.target]))
        
        return paths
    
    def get_related_entities(
        self,
        node_id: str,
        relation_filter: Optional[str] = None,
        type_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get entities related to a node with optional filters."""
        related = []
        
        for edge in self._edges_by_source.get(node_id, []):
            if relation_filter and edge.relation != relation_filter:
                continue
            target = self.nodes.get(edge.target)
            if target:
                if type_filter and target.type != type_filter:
                    continue
                related.append({
                    "entity": asdict(target),
                    "relation": edge.relation,
                    "direction": "outgoing",
                })
        
        for edge in self._edges_by_target.get(node_id, []):
            if relation_filter and edge.relation != relation_filter:
                continue
            source = self.nodes.get(edge.source)
            if source:
                if type_filter and source.type != type_filter:
                    continue
                related.append({
                    "entity": asdict(source),
                    "relation": edge.relation,
                    "direction": "incoming",
                })
        
        return related
    
    def auto_extract_entities(
        self,
        text: str,
        is_global: bool = False,
        source: str = "auto_extraction",
        confidence: float = 0.8,
    ) -> Dict[str, List[str]]:
        """
        Advanced entity extraction from text with pattern matching.
        
        Returns a dictionary of extracted entities grouped by type.
        """
        extracted: Dict[str, List[str]] = defaultdict(list)
        
        for entity_type, pattern in self.EXTRACTION_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            
            for match in matches:
                # Handle tuple matches from groups
                entity = match if isinstance(match, str) else match[0] if match else None
                if not entity:
                    continue
                
                # Apply exclusions
                exclusions = self.EXTRACTION_EXCLUSIONS.get(entity_type, set())
                if entity.lower() in exclusions:
                    continue
                
                # Map pattern type to node type
                node_type = self._map_pattern_to_node_type(entity_type)
                
                # Add to graph
                self.add_node(
                    entity,
                    node_type,
                    properties={"extraction_source": entity_type},
                    is_global=is_global or entity_type == "cve",
                    confidence=confidence,
                    source=source,
                )
                
                extracted[node_type].append(entity)
        
        self._stats["entities_extracted"] += sum(len(v) for v in extracted.values())
        
        return dict(extracted)
    
    def _map_pattern_to_node_type(self, pattern_type: str) -> str:
        """Map extraction pattern type to node type."""
        mapping = {
            "ip_v4": NodeType.IP.value,
            "ip_v6": NodeType.IP.value,
            "internal_ip": NodeType.IP.value,
            "domain": NodeType.DOMAIN.value,
            "cve": NodeType.CVE.value,
            "cwe": NodeType.VULNERABILITY.value,
            "port": NodeType.PORT.value,
            "url": NodeType.ENDPOINT.value,
            "email": NodeType.USER.value,
            "hash_md5": NodeType.FINDING.value,
            "hash_sha1": NodeType.FINDING.value,
            "hash_sha256": NodeType.FINDING.value,
            "aws_key": NodeType.API_KEY.value,
            "s3_bucket": NodeType.BUCKET.value,
            "jwt": NodeType.SECRET.value,
            "api_key_generic": NodeType.API_KEY.value,
            "private_key": NodeType.SECRET.value,
            "mac_address": NodeType.FINDING.value,
            "version": NodeType.TECHNOLOGY.value,
        }
        return mapping.get(pattern_type, NodeType.CUSTOM.value)
    
    def infer_relationships(self) -> List[Edge]:
        """
        Automatically infer relationships between entities based on patterns.
        
        This uses heuristics to connect related entities.
        """
        inferred_edges = []
        
        # Domain-IP inference (domains on same IP likely related)
        domains = self._nodes_by_type.get(NodeType.DOMAIN.value, set())
        ips = self._nodes_by_type.get(NodeType.IP.value, set())
        
        # Subdomain inference
        for domain in domains:
            for other_domain in domains:
                if domain != other_domain:
                    if other_domain.endswith(f".{domain}"):
                        edge = self.add_edge(
                            domain,
                            other_domain,
                            RelationType.HAS_SUBDOMAIN.value,
                            confidence=0.95,
                            source="inference",
                        )
                        inferred_edges.append(edge)
        
        # CVE-Service relationship inference
        cves = self._nodes_by_type.get(NodeType.CVE.value, set())
        services = self._nodes_by_type.get(NodeType.SERVICE.value, set())
        technologies = self._nodes_by_type.get(NodeType.TECHNOLOGY.value, set())
        
        for cve in cves:
            cve_node = self.nodes.get(cve)
            if cve_node and cve_node.properties.get("affected_product"):
                product = cve_node.properties["affected_product"].lower()
                for tech in technologies:
                    if tech.lower() in product or product in tech.lower():
                        edge = self.add_edge(
                            tech,
                            cve,
                            RelationType.VULNERABLE_TO.value,
                            confidence=0.7,
                            source="inference",
                        )
                        inferred_edges.append(edge)
        
        return inferred_edges
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the graph."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "global_nodes": len(self.global_nodes),
            "nodes_by_type": {
                t: len(nodes) for t, nodes in self._nodes_by_type.items()
            },
            "edges_by_relation": {
                r: len(edges) for r, edges in self._edges_by_relation.items()
            },
            "query_stats": self._stats,
            "target_scope": self.target_scope,
        }
    
    def merge_graph(self, other: "GraphEngine") -> None:
        """Merge another graph into this one."""
        for node_id, node in other.nodes.items():
            self.add_node(
                node_id,
                node.type,
                node.properties,
                is_global=node_id in other.global_nodes,
                confidence=node.confidence,
                source=node.source,
                tags=node.tags,
            )
        
        for edge in other.edges:
            self.add_edge(
                edge.source,
                edge.target,
                edge.relation,
                edge.properties,
                edge.confidence,
                edge.weight,
                edge.bidirectional,
                edge.evidence,
            )
    
    def export_to_cytoscape(self) -> Dict[str, Any]:
        """Export graph to Cytoscape.js format for visualization."""
        elements = {
            "nodes": [],
            "edges": [],
        }
        
        for node_id, node in self.nodes.items():
            elements["nodes"].append({
                "data": {
                    "id": node_id,
                    "label": node_id,
                    "type": node.type,
                    "risk_score": node.risk_score,
                    **node.properties,
                },
            })
        
        for i, edge in enumerate(self.edges):
            elements["edges"].append({
                "data": {
                    "id": f"edge_{i}",
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.relation,
                    "confidence": edge.confidence,
                },
            })
        
        return elements
    
    def export_to_neo4j_cypher(self) -> str:
        """Export graph as Neo4j Cypher statements."""
        statements = []
        
        for node_id, node in self.nodes.items():
            props = {
                "id": node_id,
                "type": node.type,
                "risk_score": node.risk_score,
                **node.properties,
            }
            props_str = ", ".join(f"{k}: {json.dumps(v)}" for k, v in props.items())
            statements.append(f"CREATE (:{node.type} {{{props_str}}})")
        
        for edge in self.edges:
            statements.append(
                f"MATCH (a), (b) WHERE a.id = '{edge.source}' AND b.id = '{edge.target}' "
                f"CREATE (a)-[:{edge.relation} {{confidence: {edge.confidence}}}]->(b)"
            )
        
        return ";\n".join(statements)
    
    def serialize(self) -> str:
        """Serialize the graph to JSON."""
        return json.dumps({
            "target_scope": self.target_scope,
            "nodes": {k: asdict(v) for k, v in self.nodes.items()},
            "edges": [asdict(e) for e in self.edges],
            "global_nodes": list(self.global_nodes),
            "stats": self._stats,
        }, indent=2)
    
    @classmethod
    def deserialize(cls, data_str: str) -> "GraphEngine":
        """Deserialize a graph from JSON."""
        data = json.loads(data_str)
        engine = cls(target_scope=data.get("target_scope"))
        
        for nid, n_data in data.get("nodes", {}).items():
            # Handle backward compatibility
            node = Node(
                id=n_data["id"],
                type=n_data["type"],
                properties=n_data.get("properties", {}),
                created_at=n_data.get("created_at", datetime.now().isoformat()),
                updated_at=n_data.get("updated_at", datetime.now().isoformat()),
                confidence=n_data.get("confidence", 1.0),
                source=n_data.get("source", "deserialized"),
                tags=n_data.get("tags", []),
                risk_score=n_data.get("risk_score", 0.0),
                access_count=n_data.get("access_count", 0),
                last_accessed=n_data.get("last_accessed"),
            )
            engine.nodes[nid] = node
        
        for e_data in data.get("edges", []):
            edge = Edge(
                source=e_data["source"],
                target=e_data["target"],
                relation=e_data["relation"],
                properties=e_data.get("properties", {}),
                created_at=e_data.get("created_at", datetime.now().isoformat()),
                confidence=e_data.get("confidence", 1.0),
                weight=e_data.get("weight", 1.0),
                bidirectional=e_data.get("bidirectional", False),
                evidence=e_data.get("evidence", []),
            )
            engine.edges.append(edge)
        
        engine.global_nodes = set(data.get("global_nodes", []))
        engine._stats = data.get("stats", engine._stats)
        
        # Rebuild indices
        engine._rebuild_indices()
        
        return engine
    
    def save_to_strixdb(self, strixdb_actions: Any) -> bool:
        """Persist the graph to StrixDB."""
        filename = (
            "knowledge_graph.json"
            if not self.target_scope
            else f"targets/{self.target_scope}/knowledge_graph.json"
        )
        try:
            strixdb_actions.create(
                category="metadata",
                title=f"Knowledge Graph (Scope: {self.target_scope or 'Global'})",
                content=self.serialize(),
                filename=filename
            )
            return True
        except Exception as e:
            print(f"Failed to save Knowledge Graph: {e}")
            return False
    
    @classmethod
    def load_from_strixdb(
        cls,
        strixdb_actions: Any,
        target_scope: Optional[str] = None,
    ) -> "GraphEngine":
        """Load the graph from StrixDB."""
        filename = (
            "knowledge_graph.json"
            if not target_scope
            else f"targets/{target_scope}/knowledge_graph.json"
        )
        
        try:
            name = filename.replace(".json", "")
            res = strixdb_actions.strixdb_get(
                agent_state=None,
                category="metadata",
                name=name,
            )
            
            if res.get("success") and res.get("item"):
                return cls.deserialize(res["item"]["content"])
        except Exception:
            pass
        
        return cls(target_scope=target_scope)
