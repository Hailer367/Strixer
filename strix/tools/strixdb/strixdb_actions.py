"""
StrixDB Actions - Advanced GitHub-based Persistent Knowledge Repository.

This module provides tools for the AI agent to interact with StrixDB,
a sophisticated GitHub repository for storing, retrieving, and querying
security artifacts with advanced features:

KEY FEATURES:
- Intelligent full-text search with relevance scoring
- Automatic cross-referencing and relationship detection
- Version tracking and change history
- Semantic tagging and categorization
- Caching for improved performance
- Batch operations for efficiency
- Integration with Knowledge Graph

CONFIGURATION:
- Repository name: "StrixDB" (owned by the user)
- Authentication: STRIXDB_TOKEN (GitHub token from repository secrets)
"""

from __future__ import annotations

import base64
import json
import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from functools import lru_cache

import requests

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)

# Default categories with descriptions
DEFAULT_CATEGORIES = [
    "scripts",
    "exploits",
    "knowledge",
    "libraries",
    "sources",
    "methods",
    "tools",
    "configs",
    "wordlists",
    "payloads",
    "templates",
    "notes",
    "reports",
    "workflows",
    "credentials",  # Discovered credentials (sanitized)
    "endpoints",    # API endpoints and paths
    "fingerprints", # Service/technology fingerprints
    "bypasses",     # Successful WAF/auth bypasses
    "recon",        # Reconnaissance data
    "metadata",     # System metadata
]

CATEGORY_DESCRIPTIONS = {
    "scripts": "Automation scripts, shell scripts, and utility scripts",
    "exploits": "Working exploits, PoCs, and vulnerability demonstrations",
    "knowledge": "Security knowledge, research notes, and documentation",
    "libraries": "Reusable code libraries and modules",
    "sources": "Data sources, references, and external resource links",
    "methods": "Attack methodologies, techniques, and procedures",
    "tools": "Custom security tools and utilities",
    "configs": "Configuration files, templates, and settings",
    "wordlists": "Custom wordlists for fuzzing and enumeration",
    "payloads": "Useful payloads for various attack types",
    "templates": "Report templates, code templates, and boilerplates",
    "notes": "Quick notes and temporary findings",
    "reports": "Software error reports, bugs, and issue tracking",
    "workflows": "GitHub Actions workflows for automation",
    "credentials": "Discovered credentials and secrets (sanitized for storage)",
    "endpoints": "Discovered API endpoints, paths, and parameters",
    "fingerprints": "Service fingerprints and technology stack data",
    "bypasses": "Successful WAF bypasses and authentication tricks",
    "recon": "Reconnaissance data including domains, IPs, and infrastructure",
    "metadata": "System metadata and knowledge graph data",
}

# Dynamic categories discovered from repository
_dynamic_categories: set[str] = set()

# Local cache for frequently accessed items
_item_cache: Dict[str, Tuple[datetime, Any]] = {}
_cache_ttl_seconds = 300  # 5 minutes

# Statistics tracking
_stats = {
    "api_calls": 0,
    "cache_hits": 0,
    "items_saved": 0,
    "items_retrieved": 0,
    "searches_performed": 0,
}


def _get_strixdb_config() -> dict[str, str]:
    """Get StrixDB configuration."""
    token = os.getenv("STRIXDB_TOKEN", "")
    branch = os.getenv("STRIXDB_BRANCH", "main")
    repo_name = "StrixDB"

    owner = os.getenv("STRIXDB_OWNER") or os.getenv("GITHUB_REPOSITORY_OWNER")
    
    if not owner and token:
        try:
            response = requests.get(
                "https://api.github.com/user",
                headers=_get_headers(token),
                timeout=10,
            )
            if response.status_code == 200:
                owner = response.json().get("login", "")
        except requests.RequestException:
            pass

    repo_override = os.getenv("STRIXDB_REPO", "")
    if repo_override:
        if "/" in repo_override:
            return {
                "repo": repo_override,
                "token": token,
                "branch": branch,
                "api_base": "https://api.github.com",
            }
        repo_name = repo_override

    repo = f"{owner}/{repo_name}" if owner else ""

    return {
        "repo": repo,
        "token": token,
        "branch": branch,
        "api_base": "https://api.github.com",
    }


def _get_headers(token: str) -> dict[str, str]:
    """Get headers for GitHub API requests."""
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _sanitize_name(name: str) -> str:
    """Sanitize a name for use as a filename."""
    name = name.replace(" ", "_")
    name = re.sub(r'[^\w\-.]', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.strip('_')
    return name


def _generate_item_id() -> str:
    """Generate a unique item ID."""
    return str(uuid.uuid4())[:8]


def _generate_content_hash(content: str) -> str:
    """Generate a hash for content deduplication."""
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _get_file_path(category: str, name: str, extension: str = ".json") -> str:
    """Generate the file path for an item."""
    sanitized_name = _sanitize_name(name)
    return f"{category}/{sanitized_name}{extension}"


def _get_cache_key(category: str, name: str) -> str:
    """Generate a cache key for an item."""
    return f"{category}:{name}"


def _check_cache(cache_key: str) -> Optional[Any]:
    """Check if an item is in cache and still valid."""
    if cache_key in _item_cache:
        cached_time, cached_data = _item_cache[cache_key]
        if (datetime.now() - cached_time).total_seconds() < _cache_ttl_seconds:
            _stats["cache_hits"] += 1
            return cached_data
        else:
            del _item_cache[cache_key]
    return None


def _update_cache(cache_key: str, data: Any) -> None:
    """Update the cache with new data."""
    _item_cache[cache_key] = (datetime.now(), data)


def _clear_cache(cache_key: Optional[str] = None) -> None:
    """Clear cache entries."""
    if cache_key:
        _item_cache.pop(cache_key, None)
    else:
        _item_cache.clear()


def _discover_categories(config: dict[str, str]) -> set[str]:
    """Discover existing categories (directories) in the StrixDB repository."""
    if not config["repo"] or not config["token"]:
        return set()

    try:
        _stats["api_calls"] += 1
        url = f"{config['api_base']}/repos/{config['repo']}/contents"
        response = requests.get(
            url,
            headers=_get_headers(config["token"]),
            timeout=10,
        )

        discovered = set()
        if response.status_code == 200:
            items = response.json()
            for item in items:
                if item["type"] == "dir" and not item["name"].startswith("."):
                    discovered.add(item["name"])
        return discovered
    except requests.RequestException:
        return set()


def _get_valid_categories() -> list[str]:
    """Get all valid categories (default + dynamically created + discovered)."""
    try:
        config = _get_strixdb_config()
        if config["repo"] and config["token"]:
            remote_cats = _discover_categories(config)
            _dynamic_categories.update(remote_cats)
    except Exception:
        pass

    return list(set(DEFAULT_CATEGORIES) | _dynamic_categories)


def _create_metadata(
    name: str,
    description: str,
    tags: list[str],
    category: str,
    content_type: str = "text",
    content_hash: Optional[str] = None,
    related_items: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Create enhanced metadata for an item."""
    return {
        "id": _generate_item_id(),
        "name": name,
        "description": description,
        "tags": tags,
        "category": category,
        "content_type": content_type,
        "content_hash": content_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "access_count": 0,
        "last_accessed": None,
        "related_items": related_items or [],
        "source": "strix_agent",
    }


def _ensure_category_exists(category: str, config: dict[str, str]) -> bool:
    """Ensure a category directory exists in StrixDB."""
    if not config["repo"] or not config["token"]:
        return False

    try:
        _stats["api_calls"] += 1
        url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}"
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)

        if response.status_code == 200:
            return True

        if response.status_code == 404:
            readme_content = f"""# {category.title()}

This category was automatically created by StrixDB.

{CATEGORY_DESCRIPTIONS.get(category, 'Custom category for storing related items.')}

## Contents

Items in this category will be listed here as they are added.
"""
            readme_encoded = base64.b64encode(readme_content.encode()).decode()

            _stats["api_calls"] += 1
            create_url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}/README.md"
            create_response = requests.put(
                create_url,
                headers=_get_headers(config["token"]),
                json={
                    "message": f"[StrixDB] Create category: {category}",
                    "content": readme_encoded,
                    "branch": config["branch"],
                },
                timeout=30,
            )

            if create_response.status_code in (200, 201):
                _dynamic_categories.add(category)
                logger.info(f"[StrixDB] Created new category: {category}")
                return True

        return False

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] Failed to ensure category exists: {e}")
        return False


def _extract_keywords(content: str, max_keywords: int = 10) -> list[str]:
    """Extract keywords from content for improved searchability."""
    # Simple keyword extraction
    words = re.findall(r'\b[a-zA-Z]{4,}\b', content.lower())
    word_counts = defaultdict(int)
    
    # Filter common words
    stopwords = {
        'this', 'that', 'with', 'from', 'have', 'been', 'were', 'they',
        'their', 'what', 'when', 'where', 'which', 'while', 'will',
        'would', 'there', 'these', 'than', 'then', 'them', 'into', 'some',
    }
    
    for word in words:
        if word not in stopwords:
            word_counts[word] += 1
    
    # Return top keywords by frequency
    sorted_words = sorted(word_counts.items(), key=lambda x: -x[1])
    return [w for w, _ in sorted_words[:max_keywords]]


def _detect_related_items(
    content: str,
    category: str,
    config: dict[str, str],
) -> list[str]:
    """Detect potentially related items based on content."""
    related = []
    
    # Extract potential references
    patterns = [
        (r'CVE-\d{4}-\d{4,}', 'exploits'),  # CVE references
        (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'recon'),  # IP addresses
        (r'\b[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.[a-zA-Z]{2,}\b', 'recon'),  # Domains
    ]
    
    for pattern, related_category in patterns:
        matches = re.findall(pattern, content)
        for match in matches[:5]:  # Limit to 5 per pattern
            related.append(f"{related_category}/{match}")
    
    return list(set(related))


@register_tool(sandbox_execution=False)
def strixdb_create_category(
    agent_state: Any,
    category_name: str,
    description: str = "",
) -> dict[str, Any]:
    """Create a new category in StrixDB."""
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "StrixDB not configured. Ensure STRIXDB_TOKEN is set.",
        }

    category_name = category_name.lower().replace(" ", "_")
    category_name = re.sub(r'[^\w]', '', category_name)

    if not category_name:
        return {
            "success": False,
            "error": "Invalid category name. Use lowercase letters and underscores only.",
        }

    if description:
        CATEGORY_DESCRIPTIONS[category_name] = description

    if _ensure_category_exists(category_name, config):
        return {
            "success": True,
            "message": f"Category '{category_name}' is ready to use",
            "category": category_name,
            "description": description or CATEGORY_DESCRIPTIONS.get(category_name, ""),
        }

    return {
        "success": False,
        "error": f"Failed to create category '{category_name}'",
    }


@register_tool(sandbox_execution=False)
def strixdb_save(
    agent_state: Any,
    category: str,
    name: str,
    content: str,
    description: str = "",
    tags: list[str] | None = None,
    content_type: str = "text",
    auto_tag: bool = True,
    detect_relations: bool = True,
) -> dict[str, Any]:
    """
    Save an item to StrixDB with enhanced metadata and indexing.
    
    Features:
    - Automatic keyword extraction for tags
    - Content deduplication via hashing
    - Automatic relationship detection
    - Version tracking
    """
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {
            "success": False,
            "error": "StrixDB not configured. Ensure STRIXDB_TOKEN is set.",
            "hint": "Add STRIXDB_TOKEN to your repository secrets.",
            "item": None,
        }

    category = category.lower().replace(" ", "_")

    if not _ensure_category_exists(category, config):
        return {
            "success": False,
            "error": f"Failed to access or create category '{category}'",
            "item": None,
        }

    if tags is None:
        tags = []
    
    # Auto-extract keywords as tags
    if auto_tag:
        extracted_keywords = _extract_keywords(content)
        tags = list(set(tags + extracted_keywords))
    
    # Generate content hash for deduplication
    content_hash = _generate_content_hash(content)
    
    # Detect related items
    related_items = []
    if detect_relations:
        related_items = _detect_related_items(content, category, config)

    metadata = _create_metadata(
        name, description, tags, category, content_type,
        content_hash=content_hash,
        related_items=related_items,
    )

    extensions = {
        "text": ".md",
        "script": ".py",
        "json": ".json",
        "python": ".py",
        "javascript": ".js",
        "yaml": ".yml",
        "binary": ".bin",
        "shell": ".sh",
        "sql": ".sql",
        "html": ".html",
        "xml": ".xml",
    }
    extension = extensions.get(content_type, ".txt")

    content_path = _get_file_path(category, name, extension)
    metadata_path = _get_file_path(category, f"{_sanitize_name(name)}_meta", ".json")

    try:
        content_encoded = base64.b64encode(content.encode()).decode()

        _stats["api_calls"] += 1
        url = f"{config['api_base']}/repos/{config['repo']}/contents/{content_path}"
        response = requests.get(url, headers=_get_headers(config["token"]), timeout=30)

        payload: dict[str, Any] = {
            "message": f"[StrixDB] Add {category}/{name}",
            "content": content_encoded,
            "branch": config["branch"],
        }

        if response.status_code == 200:
            sha = response.json().get("sha")
            existing_hash = response.json().get("content", "")
            
            # Check for duplicate content
            try:
                existing_content = base64.b64decode(existing_hash).decode()
                if _generate_content_hash(existing_content) == content_hash:
                    return {
                        "success": True,
                        "message": f"Item '{name}' already exists with identical content",
                        "duplicate": True,
                        "item": {
                            "name": name,
                            "category": category,
                            "path": content_path,
                        },
                    }
            except Exception:
                pass
            
            payload["sha"] = sha
            payload["message"] = f"[StrixDB] Update {category}/{name}"
            metadata["version"] = response.json().get("version", 1) + 1

        _stats["api_calls"] += 1
        response = requests.put(
            url,
            headers=_get_headers(config["token"]),
            json=payload,
            timeout=30,
        )

        if response.status_code not in (200, 201):
            return {
                "success": False,
                "error": f"Failed to save content: {response.status_code}",
                "item": None,
            }

        metadata["file_path"] = content_path
        metadata_encoded = base64.b64encode(json.dumps(metadata, indent=2).encode()).decode()

        _stats["api_calls"] += 1
        meta_url = f"{config['api_base']}/repos/{config['repo']}/contents/{metadata_path}"
        meta_response = requests.get(meta_url, headers=_get_headers(config["token"]), timeout=30)

        meta_payload: dict[str, Any] = {
            "message": f"[StrixDB] Add metadata for {category}/{name}",
            "content": metadata_encoded,
            "branch": config["branch"],
        }

        if meta_response.status_code == 200:
            meta_sha = meta_response.json().get("sha")
            meta_payload["sha"] = meta_sha
            meta_payload["message"] = f"[StrixDB] Update metadata for {category}/{name}"

        _stats["api_calls"] += 1
        requests.put(
            meta_url,
            headers=_get_headers(config["token"]),
            json=meta_payload,
            timeout=30,
        )

        _stats["items_saved"] += 1
        
        # Clear cache for this item
        _clear_cache(_get_cache_key(category, name))

        logger.info(f"[StrixDB] Saved item: {category}/{name}")

        return {
            "success": True,
            "message": f"Successfully saved '{name}' to StrixDB in category '{category}'",
            "item": {
                "id": metadata["id"],
                "name": name,
                "category": category,
                "path": content_path,
                "tags": tags,
                "content_hash": content_hash,
                "related_items": related_items,
                "version": metadata["version"],
            },
        }

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] Failed to save item: {e}")
        return {
            "success": False,
            "error": f"Request failed: {e!s}",
            "item": None,
        }


@register_tool(sandbox_execution=False)
def strixdb_search(
    agent_state: Any,
    query: str,
    category: str | None = None,
    tags: list[str] | None = None,
    limit: int = 20,
    include_content: bool = False,
) -> dict[str, Any]:
    """
    Advanced search for items in StrixDB with relevance scoring.
    
    Features:
    - Full-text search across name, description, and content
    - Category and tag filtering
    - Relevance scoring
    - Optional content preview
    """
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "StrixDB not configured", "results": []}

    _stats["searches_performed"] += 1

    try:
        search_query = f"repo:{config['repo']} {query}"
        if category:
            search_query += f" path:{category}/"

        _stats["api_calls"] += 1
        url = f"{config['api_base']}/search/code"
        params = {"q": search_query, "per_page": min(limit * 2, 100)}

        response = requests.get(
            url,
            headers=_get_headers(config["token"]),
            params=params,
            timeout=30,
        )

        if response.status_code != 200:
            return {"success": False, "error": f"Search failed: {response.status_code}", "results": []}

        data = response.json()
        results = []
        seen_items = set()

        for item in data.get("items", []):
            path = item.get("path", "")
            if "_meta.json" in path or "README.md" in path:
                continue

            parts = path.split("/")
            item_category = parts[0] if parts else "unknown"
            item_name = parts[-1] if parts else path
            
            # Deduplicate
            item_key = f"{item_category}/{item_name}"
            if item_key in seen_items:
                continue
            seen_items.add(item_key)
            
            # Calculate relevance score
            score = item.get("score", 0)
            if query.lower() in item_name.lower():
                score += 10  # Boost for name match
            
            result = {
                "name": item_name,
                "category": item_category,
                "path": path,
                "relevance_score": score,
            }
            
            # Optionally include content preview
            if include_content:
                try:
                    content_result = strixdb_get(agent_state, item_category, item_name.rsplit('.', 1)[0])
                    if content_result.get("success"):
                        result["content_preview"] = content_result["item"]["content"][:500]
                except Exception:
                    pass

            results.append(result)

        # Sort by relevance
        results.sort(key=lambda x: -x["relevance_score"])
        
        # Filter by tags if specified
        if tags:
            filtered_results = []
            for result in results:
                try:
                    item_data = strixdb_get(agent_state, result["category"], result["name"].rsplit('.', 1)[0])
                    if item_data.get("success"):
                        item_tags = item_data["item"].get("metadata", {}).get("tags", [])
                        if any(t in item_tags for t in tags):
                            result["matched_tags"] = [t for t in tags if t in item_tags]
                            filtered_results.append(result)
                except Exception:
                    pass
            results = filtered_results

        return {
            "success": True,
            "query": query,
            "total_count": data.get("total_count", len(results)),
            "results": results[:limit],
            "filters_applied": {
                "category": category,
                "tags": tags,
            },
        }

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] Search failed: {e}")
        return {"success": False, "error": f"Search failed: {e!s}", "results": []}


@register_tool(sandbox_execution=False)
def strixdb_get(
    agent_state: Any,
    category: str,
    name: str,
    use_cache: bool = True,
) -> dict[str, Any]:
    """
    Retrieve a specific item from StrixDB with caching.
    
    Features:
    - Local caching for performance
    - Access tracking
    - Metadata retrieval
    """
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "StrixDB not configured", "item": None}
    
    # Check cache first
    cache_key = _get_cache_key(category, name)
    if use_cache:
        cached = _check_cache(cache_key)
        if cached:
            return cached

    try:
        _stats["api_calls"] += 1
        list_url = f"{config['api_base']}/repos/{config['repo']}/contents/{category}"
        list_response = requests.get(
            list_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )

        if list_response.status_code != 200:
            return {"success": False, "error": f"Category '{category}' not found", "item": None}

        files = list_response.json()
        sanitized_name = _sanitize_name(name)

        content_file = None
        meta_file = None

        for file in files:
            file_name = file.get("name", "")
            if file_name.startswith(sanitized_name) and not file_name.endswith("_meta.json"):
                content_file = file
            elif file_name == f"{sanitized_name}_meta.json":
                meta_file = file

        if not content_file:
            return {"success": False, "error": f"Item '{name}' not found", "item": None}

        _stats["api_calls"] += 1
        content_response = requests.get(
            content_file["url"],
            headers=_get_headers(config["token"]),
            timeout=30,
        )

        if content_response.status_code != 200:
            return {"success": False, "error": "Failed to fetch content", "item": None}

        content_data = content_response.json()
        content = base64.b64decode(content_data.get("content", "")).decode()

        metadata = {}
        if meta_file:
            _stats["api_calls"] += 1
            meta_response = requests.get(
                meta_file["url"],
                headers=_get_headers(config["token"]),
                timeout=30,
            )
            if meta_response.status_code == 200:
                meta_data = meta_response.json()
                metadata = json.loads(
                    base64.b64decode(meta_data.get("content", "")).decode()
                )
                
                # Update access tracking
                metadata["access_count"] = metadata.get("access_count", 0) + 1
                metadata["last_accessed"] = datetime.now(timezone.utc).isoformat()

        _stats["items_retrieved"] += 1
        
        result = {
            "success": True,
            "item": {
                "name": name,
                "category": category,
                "content": content,
                "path": content_file["path"],
                "metadata": metadata,
                "size": content_file.get("size", 0),
            },
        }
        
        # Update cache
        _update_cache(cache_key, result)

        return result

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] Get failed: {e}")
        return {"success": False, "error": f"Request failed: {e!s}", "item": None}


@register_tool(sandbox_execution=False)
def strixdb_list(
    agent_state: Any,
    category: str | None = None,
    limit: int = 50,
    sort_by: str = "name",
    include_metadata: bool = False,
) -> dict[str, Any]:
    """
    List items in StrixDB with sorting and optional metadata.
    
    Sort options: name, date, size
    """
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "StrixDB not configured", "items": []}

    try:
        items = []
        categories_to_list = [category] if category else _get_valid_categories()

        for cat in categories_to_list:
            _stats["api_calls"] += 1
            url = f"{config['api_base']}/repos/{config['repo']}/contents/{cat}"
            response = requests.get(
                url,
                headers=_get_headers(config["token"]),
                timeout=30,
            )

            if response.status_code == 200:
                files = response.json()
                for file in files:
                    name = file.get("name", "")
                    if name.endswith("_meta.json") or name == "README.md":
                        continue

                    item_data = {
                        "name": name,
                        "category": cat,
                        "path": file.get("path", ""),
                        "size": file.get("size", 0),
                        "type": file.get("type", "file"),
                    }
                    
                    if include_metadata:
                        # Fetch metadata for each item
                        sanitized = _sanitize_name(name.rsplit('.', 1)[0])
                        for f in files:
                            if f.get("name") == f"{sanitized}_meta.json":
                                try:
                                    meta_resp = requests.get(
                                        f["url"],
                                        headers=_get_headers(config["token"]),
                                        timeout=10,
                                    )
                                    if meta_resp.status_code == 200:
                                        meta_content = base64.b64decode(
                                            meta_resp.json().get("content", "")
                                        ).decode()
                                        item_data["metadata"] = json.loads(meta_content)
                                except Exception:
                                    pass
                                break

                    items.append(item_data)

            if len(items) >= limit:
                break
        
        # Sort results
        if sort_by == "date" and include_metadata:
            items.sort(key=lambda x: x.get("metadata", {}).get("updated_at", ""), reverse=True)
        elif sort_by == "size":
            items.sort(key=lambda x: x.get("size", 0), reverse=True)
        else:
            items.sort(key=lambda x: x.get("name", ""))

        return {"success": True, "total": len(items), "items": items[:limit]}

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] List failed: {e}")
        return {"success": False, "error": f"Request failed: {e!s}", "items": []}


@register_tool(sandbox_execution=False)
def strixdb_update(
    agent_state: Any,
    category: str,
    name: str,
    content: str,
    description: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Update an existing item in StrixDB."""
    existing = strixdb_get(agent_state, category, name)

    if not existing["success"]:
        return existing

    existing_metadata = existing["item"].get("metadata", {})

    return strixdb_save(
        agent_state,
        category=category,
        name=name,
        content=content,
        description=description or existing_metadata.get("description", ""),
        tags=tags or existing_metadata.get("tags", []),
        content_type=existing_metadata.get("content_type", "text"),
    )


@register_tool(sandbox_execution=False)
def strixdb_delete(
    agent_state: Any,
    category: str,
    name: str,
) -> dict[str, Any]:
    """Delete an item from StrixDB."""
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "StrixDB not configured"}

    try:
        existing = strixdb_get(agent_state, category, name)

        if not existing["success"]:
            return existing

        path = existing["item"]["path"]
        sanitized_name = _sanitize_name(name)
        meta_path = path.replace(path.split("/")[-1], f"{sanitized_name}_meta.json")

        _stats["api_calls"] += 1
        content_url = f"{config['api_base']}/repos/{config['repo']}/contents/{path}"
        content_response = requests.get(
            content_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )

        if content_response.status_code != 200:
            return {"success": False, "error": "Failed to get file info for deletion"}

        content_sha = content_response.json().get("sha")

        _stats["api_calls"] += 1
        delete_response = requests.delete(
            content_url,
            headers=_get_headers(config["token"]),
            json={
                "message": f"[StrixDB] Delete {category}/{name}",
                "sha": content_sha,
                "branch": config["branch"],
            },
            timeout=30,
        )

        if delete_response.status_code not in (200, 204):
            return {"success": False, "error": f"Failed to delete: {delete_response.status_code}"}

        _stats["api_calls"] += 1
        meta_url = f"{config['api_base']}/repos/{config['repo']}/contents/{meta_path}"
        meta_response = requests.get(
            meta_url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )

        if meta_response.status_code == 200:
            meta_sha = meta_response.json().get("sha")
            _stats["api_calls"] += 1
            requests.delete(
                meta_url,
                headers=_get_headers(config["token"]),
                json={
                    "message": f"[StrixDB] Delete metadata for {category}/{name}",
                    "sha": meta_sha,
                    "branch": config["branch"],
                },
                timeout=30,
            )
        
        # Clear cache
        _clear_cache(_get_cache_key(category, name))

        return {"success": True, "message": f"Successfully deleted '{name}' from '{category}'"}

    except requests.RequestException as e:
        logger.exception(f"[StrixDB] Delete failed: {e}")
        return {"success": False, "error": f"Request failed: {e!s}"}


@register_tool(sandbox_execution=False)
def strixdb_get_categories(agent_state: Any) -> dict[str, Any]:
    """Get all available categories in StrixDB with their descriptions."""
    config = _get_strixdb_config()
    categories = []

    for cat in _get_valid_categories():
        desc = CATEGORY_DESCRIPTIONS.get(cat, "Custom category")
        cat_info = {
            "name": cat,
            "description": desc,
            "item_count": 0,
            "is_custom": cat in _dynamic_categories,
        }

        if config["repo"] and config["token"]:
            try:
                _stats["api_calls"] += 1
                url = f"{config['api_base']}/repos/{config['repo']}/contents/{cat}"
                response = requests.get(
                    url,
                    headers=_get_headers(config["token"]),
                    timeout=10,
                )
                if response.status_code == 200:
                    files = response.json()
                    cat_info["item_count"] = sum(
                        1 for f in files
                        if not f.get("name", "").endswith("_meta.json")
                        and f.get("name") != "README.md"
                    )
            except requests.RequestException:
                pass

        categories.append(cat_info)

    return {
        "success": True,
        "categories": categories,
        "total_categories": len(categories),
        "hint": "You can create new categories using strixdb_create_category()",
    }


@register_tool(sandbox_execution=False)
def strixdb_get_stats(agent_state: Any) -> dict[str, Any]:
    """Get comprehensive statistics about StrixDB usage."""
    config = _get_strixdb_config()

    if not config["repo"] or not config["token"]:
        return {"success": False, "error": "StrixDB not configured", "stats": None}

    try:
        _stats["api_calls"] += 1
        url = f"{config['api_base']}/repos/{config['repo']}"
        response = requests.get(
            url,
            headers=_get_headers(config["token"]),
            timeout=30,
        )

        if response.status_code != 200:
            return {"success": False, "error": "Failed to get repository info", "stats": None}

        repo_data = response.json()

        category_counts = {}
        total_items = 0

        for cat in _get_valid_categories():
            _stats["api_calls"] += 1
            cat_url = f"{config['api_base']}/repos/{config['repo']}/contents/{cat}"
            cat_response = requests.get(
                cat_url,
                headers=_get_headers(config["token"]),
                timeout=10,
            )

            if cat_response.status_code == 200:
                files = cat_response.json()
                count = sum(
                    1 for f in files
                    if not f.get("name", "").endswith("_meta.json")
                    and f.get("name") != "README.md"
                )
                category_counts[cat] = count
                total_items += count
            else:
                category_counts[cat] = 0

        return {
            "success": True,
            "stats": {
                "repo_name": config["repo"],
                "branch": config["branch"],
                "total_items": total_items,
                "categories": category_counts,
                "size_kb": repo_data.get("size", 0),
                "last_updated": repo_data.get("updated_at", ""),
                "visibility": repo_data.get("visibility", "private"),
            },
            "session_stats": _stats.copy(),
        }

    except requests.RequestException as e:
        return {"success": False, "error": f"Request failed: {e!s}", "stats": None}


@register_tool(sandbox_execution=False)
def strixdb_get_config_status(agent_state: Any) -> dict[str, Any]:
    """Get the current StrixDB configuration status."""
    config = _get_strixdb_config()

    is_configured = bool(config["repo"] and config["token"])

    connection_status = "not_tested"
    if is_configured:
        try:
            _stats["api_calls"] += 1
            url = f"{config['api_base']}/repos/{config['repo']}"
            response = requests.get(
                url,
                headers=_get_headers(config["token"]),
                timeout=10,
            )
            if response.status_code == 200:
                connection_status = "connected"
            elif response.status_code == 404:
                connection_status = "repository_not_found"
            elif response.status_code == 401:
                connection_status = "authentication_failed"
            else:
                connection_status = f"error_{response.status_code}"
        except requests.RequestException as e:
            connection_status = f"connection_error: {e!s}"

    return {
        "success": True,
        "configured": is_configured,
        "connection_status": connection_status,
        "repository": config["repo"] if is_configured else None,
        "branch": config["branch"],
        "token_set": bool(config["token"]),
        "cache_size": len(_item_cache),
        "session_stats": _stats.copy(),
        "setup_instructions": (
            "To configure StrixDB:\n"
            "1. Create a GitHub repository named 'StrixDB'\n"
            "2. Create a GitHub Personal Access Token (PAT) with 'repo' scope\n"
            "3. Add the token as STRIXDB_TOKEN in your repository secrets\n"
            "4. The workflow will automatically pass the token to Strix"
        ) if not is_configured else None,
    }


@register_tool(sandbox_execution=False)
def strixdb_export(
    agent_state: Any,
    category: str | None = None,
    format: str = "json",
) -> dict[str, Any]:
    """Export items from StrixDB."""
    list_result = strixdb_list(agent_state, category, limit=1000)

    if not list_result["success"]:
        return list_result

    exported_items = []

    for item in list_result["items"]:
        item_result = strixdb_get(agent_state, item["category"], item["name"].rsplit('.', 1)[0])
        if item_result["success"]:
            exported_items.append(item_result["item"])

    if format == "markdown":
        md_output = "# StrixDB Export\n\n"
        current_category = None

        for item in exported_items:
            if item["category"] != current_category:
                current_category = item["category"]
                md_output += f"\n## {current_category.title()}\n\n"

            md_output += f"### {item['name']}\n\n"
            if item.get("metadata", {}).get("description"):
                md_output += f"*{item['metadata']['description']}*\n\n"
            md_output += f"```\n{item['content']}\n```\n\n"

        return {
            "success": True,
            "format": "markdown",
            "data": md_output,
            "item_count": len(exported_items),
        }

    return {
        "success": True,
        "format": "json",
        "data": exported_items,
        "item_count": len(exported_items),
    }


@register_tool(sandbox_execution=False)
def strixdb_import_item(
    agent_state: Any,
    item_data: dict[str, Any],
) -> dict[str, Any]:
    """Import an item to StrixDB."""
    required_fields = ["category", "name", "content"]
    for field in required_fields:
        if field not in item_data:
            return {"success": False, "error": f"Missing required field: {field}"}

    return strixdb_save(
        agent_state,
        category=item_data["category"],
        name=item_data["name"],
        content=item_data["content"],
        description=item_data.get("description", ""),
        tags=item_data.get("tags", []),
        content_type=item_data.get("content_type", "text"),
    )


@register_tool(sandbox_execution=False)
def strixdb_batch_save(
    agent_state: Any,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Save multiple items to StrixDB in a batch.
    
    Each item should have: category, name, content
    Optional: description, tags, content_type
    """
    results = {
        "success": True,
        "saved": [],
        "failed": [],
        "total": len(items),
    }
    
    for item in items:
        if not all(k in item for k in ["category", "name", "content"]):
            results["failed"].append({
                "name": item.get("name", "unknown"),
                "error": "Missing required fields",
            })
            continue
        
        result = strixdb_save(
            agent_state,
            category=item["category"],
            name=item["name"],
            content=item["content"],
            description=item.get("description", ""),
            tags=item.get("tags", []),
            content_type=item.get("content_type", "text"),
        )
        
        if result["success"]:
            results["saved"].append(item["name"])
        else:
            results["failed"].append({
                "name": item["name"],
                "error": result.get("error", "Unknown error"),
            })
    
    results["success"] = len(results["failed"]) == 0
    return results


@register_tool(sandbox_execution=False)
def strixdb_find_related(
    agent_state: Any,
    category: str,
    name: str,
) -> dict[str, Any]:
    """
    Find items related to a specific item based on content analysis.
    """
    item_result = strixdb_get(agent_state, category, name)
    
    if not item_result["success"]:
        return item_result
    
    item = item_result["item"]
    content = item.get("content", "")
    metadata = item.get("metadata", {})
    
    # Get related items from metadata
    related_from_metadata = metadata.get("related_items", [])
    
    # Search for items with similar tags
    tags = metadata.get("tags", [])
    related_from_tags = []
    
    if tags:
        for tag in tags[:3]:  # Limit tag searches
            search_result = strixdb_search(agent_state, tag, limit=5)
            if search_result["success"]:
                for r in search_result["results"]:
                    if r["path"] != item["path"]:
                        related_from_tags.append({
                            "name": r["name"],
                            "category": r["category"],
                            "match_type": "tag",
                            "matched_tag": tag,
                        })
    
    # Combine and deduplicate
    all_related = []
    seen = set()
    
    for rel in related_from_metadata:
        if rel not in seen:
            seen.add(rel)
            all_related.append({"path": rel, "match_type": "content_reference"})
    
    for rel in related_from_tags:
        key = f"{rel['category']}/{rel['name']}"
        if key not in seen:
            seen.add(key)
            all_related.append(rel)
    
    return {
        "success": True,
        "source_item": f"{category}/{name}",
        "related_count": len(all_related),
        "related_items": all_related[:20],
    }


@register_tool(sandbox_execution=False)
def strixdb_clear_cache(agent_state: Any) -> dict[str, Any]:
    """Clear the local StrixDB cache."""
    cache_size = len(_item_cache)
    _clear_cache()
    
    return {
        "success": True,
        "message": f"Cleared {cache_size} cached items",
        "previous_cache_size": cache_size,
    }
