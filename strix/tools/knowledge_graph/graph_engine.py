import json
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Set
from datetime import datetime

@dataclass
class Node:
    id: str
    type: str  # e.g., IP, Domain, CVE, Service, TechStack
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Edge:
    source: str
    target: str
    relation: str  # e.g., IS_SUBDOMAIN_OF, RUNS_SERVICE, VULNERABLE_TO
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

class GraphEngine:
    """
    Core engine for the Semantic Knowledge Graph.
    Handles persistence, scoping, and relational queries.
    """
    def __init__(self, target_scope: Optional[str] = None):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        # target_scope is the project identifier (e.g., repository name or target domain)
        self.target_scope = target_scope
        self.global_nodes: Set[str] = set() # IDs of nodes that are globally shared

    def add_node(self, node_id: str, node_type: str, properties: Dict[str, Any] = None, is_global: bool = False) -> Node:
        if node_id in self.nodes:
            self.nodes[node_id].updated_at = datetime.now().isoformat()
            if properties:
                self.nodes[node_id].properties.update(properties)
        else:
            self.nodes[node_id] = Node(id=node_id, type=node_type, properties=properties or {})
        
        if is_global:
            self.global_nodes.add(node_id)
        return self.nodes[node_id]

    def add_edge(self, source: str, target: str, relation: str, properties: Dict[str, Any] = None) -> Edge:
        edge = Edge(source=source, target=target, relation=relation, properties=properties or {})
        self.edges.append(edge)
        return edge

    def get_context(self, node_id: str, depth: int = 1) -> Dict[str, Any]:
        """Retrieves the neighborhood of a node for RAG context."""
        if node_id not in self.nodes:
            return {"error": "Node not found"}

        context = {
            "node": asdict(self.nodes[node_id]),
            "relationships": []
        }

        # Simple 1-hop retrieval for now
        for edge in self.edges:
            if edge.source == node_id:
                target_node = self.nodes.get(edge.target)
                if target_node:
                    context["relationships"].append({
                        "relation": edge.relation,
                        "node": asdict(target_node)
                    })
            elif edge.target == node_id:
                source_node = self.nodes.get(edge.source)
                if source_node:
                    context["relationships"].append({
                        "relation": f"REVERSED_{edge.relation}",
                        "node": asdict(source_node)
                    })

        return context

    def serialize(self) -> str:
        return json.dumps({
            "target_scope": self.target_scope,
            "nodes": {k: asdict(v) for k, v in self.nodes.items()},
            "edges": [asdict(e) for e in self.edges],
            "global_nodes": list(self.global_nodes)
        }, indent=2)

    @classmethod
    def deserialize(cls, data_str: str) -> "GraphEngine":
        data = json.loads(data_str)
        engine = cls(target_scope=data.get("target_scope"))
        for nid, n_data in data.get("nodes", {}).items():
            engine.nodes[nid] = Node(**n_data)
        for e_data in data.get("edges", []):
            engine.edges.append(Edge(**e_data))
        engine.global_nodes = set(data.get("global_nodes", []))
        return engine

    def save_to_strixdb(self, strixdb_actions: Any) -> bool:
        """Persists the graph to the StrixDB repository via the provided actions tool."""
        filename = "knowledge_graph.json" if not self.target_scope else f"targets/{self.target_scope}/knowledge_graph.json"
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
    def load_from_strixdb(cls, strixdb_actions: Any, target_scope: Optional[str] = None) -> "GraphEngine":
        """Loads the graph from StrixDB."""
        filename = "knowledge_graph.json" if not target_scope else f"targets/{target_scope}/knowledge_graph.json"
        
        try:
            # We use the raw category/name interface of strixdb
            # name in strixdb ignores extension, so we use 'knowledge_graph' or 'targets/scope/knowledge_graph'
            # But strixdb handles paths via categories. 
            # We'll use 'metadata' as category.
            name = filename.replace(".json", "")
            res = strixdb_actions.strixdb_get(agent_state=None, category="metadata", name=name)
            
            if res.get("success") and res.get("item"):
                return cls.deserialize(res["item"]["content"])
        except Exception as e:
            # Fallback to empty graph if not found or error
            pass
        
        return cls(target_scope=target_scope)
    def auto_extract_entities(self, text: str, is_global: bool = False) -> List[str]:
        """Automatically extracts and links entities from a text block."""
        import re
        
        extracted_ids = []
        
        # Simple regex for IPs and Domains
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        
        ips = re.findall(ip_pattern, text)
        domains = re.findall(domain_pattern, text)
        cves = re.findall(cve_pattern, text)
        
        for ip in ips:
            self.add_node(ip, "IP", is_global=is_global)
            extracted_ids.append(ip)
            
        for dom in domains:
            if dom.lower() not in ("google.com", "duckduckgo.com"): # Filter common search engines
                self.add_node(dom, "Domain", is_global=is_global)
                extracted_ids.append(dom)
                
        for cve in cves:
            self.add_node(cve, "CVE", is_global=True) # CVEs are always global knowledge
            extracted_ids.append(cve)
            
        return extracted_ids
