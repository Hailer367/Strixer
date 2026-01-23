import os
from typing import Any, Dict, Optional
from strix.tools.registry import register_tool
from strix.tools.knowledge_graph.graph_engine import GraphEngine

def _get_strixdb_actions():
    from strix.tools.strixdb import strixdb_actions
    return strixdb_actions

@register_tool(sandbox_execution=False)
def link_entities(
    source_id: str,
    target_id: str,
    relation: str,
    properties: Optional[Dict[str, Any]] = None,
    target_scope: Optional[str] = None
) -> Dict[str, Any]:
    """
    Links two entities in the Semantic Knowledge Graph.
    Example: link_entities("example.com", "1.2.3.4", "POINTS_TO")
    """
    strixdb = _get_strixdb_actions()
    engine = GraphEngine.load_from_strixdb(strixdb, target_scope)
    
    # Ensure nodes exist
    # For now, we auto-create nodes if they don't exist
    engine.add_node(source_id, "Entity") 
    engine.add_node(target_id, "Entity")
    
    engine.add_edge(source_id, target_id, relation, properties)
    
    if engine.save_to_strixdb(strixdb):
        return {
            "success": True,
            "message": f"Linked {source_id} to {target_id} via {relation}",
            "scope": target_scope or "Global"
        }
    return {"success": False, "message": "Failed to save graph update"}

@register_tool(sandbox_execution=False)
def get_entity_context(
    entity_id: str,
    target_scope: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieves the contextual neighborhood of an entity from the graph.
    Useful for RAG before performing actions on a target.
    """
    strixdb = _get_strixdb_actions()
    engine = GraphEngine.load_from_strixdb(strixdb, target_scope)
    
    context = engine.get_context(entity_id)
    return {
        "success": True,
        "entity": entity_id,
        "scope": target_scope or "Global",
        "context": context
    }

@register_tool(sandbox_execution=False)
def add_entity(
    entity_id: str,
    entity_type: str,
    properties: Optional[Dict[str, Any]] = None,
    is_global: bool = False,
    target_scope: Optional[str] = None
) -> Dict[str, Any]:
    """
    Explicitly adds an entity to the Knowledge Graph with specific properties.
    """
    strixdb = _get_strixdb_actions()
    engine = GraphEngine.load_from_strixdb(strixdb, target_scope)
    
    engine.add_node(entity_id, entity_type, properties, is_global=is_global)
    
    if engine.save_to_strixdb(strixdb):
        return {
            "success": True,
            "message": f"Added entity {entity_id} ({entity_type})",
            "scope": target_scope or "Global"
        }
    return {"success": False, "message": "Failed to save entity to graph"}
@register_tool(sandbox_execution=False)
def auto_link_findings(
    text: str,
    target_scope: Optional[str] = None,
    is_global: bool = False
) -> Dict[str, Any]:
    """
    Scans a text block (e.g., scan report) and automatically adds discovered 
    entities (IPs, Domains, CVEs) to the Knowledge Graph.
    """
    strixdb = _get_strixdb_actions()
    engine = GraphEngine.load_from_strixdb(strixdb, target_scope)
    
    extracted = engine.auto_extract_entities(text, is_global=is_global)
    
    if extracted:
        if engine.save_to_strixdb(strixdb):
            return {
                "success": True,
                "message": f"Automatically extracted and saved {len(extracted)} entities.",
                "entities": extracted
            }
    return {"success": True, "message": "No new entities extracted.", "entities": []}
