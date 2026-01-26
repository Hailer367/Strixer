"""StrixDB module - Advanced GitHub-based persistent storage for AI agent artifacts.

This module provides comprehensive persistence and intelligence capabilities:
- Core CRUD operations for artifact storage
- Target lifecycle management for security assessments
- Intelligent caching and batch operations
- Cross-reference and relationship detection
- Vector search preparation (future enhancement)
"""

from strix.tools.strixdb.strixdb_actions import (
    strixdb_create_category,
    strixdb_delete,
    strixdb_export,
    strixdb_get,
    strixdb_get_categories,
    strixdb_get_config_status,
    strixdb_get_stats,
    strixdb_import_item,
    strixdb_list,
    strixdb_save,
    strixdb_search,
    strixdb_update,
    strixdb_batch_save,
    strixdb_find_related,
    strixdb_clear_cache,
)
from strix.tools.strixdb.strixdb_targets import (
    strixdb_target_init,
    strixdb_target_session_start,
    strixdb_target_session_end,
    strixdb_target_add_finding,
    strixdb_target_add_endpoint,
    strixdb_target_get_summary,
)
from strix.tools.strixdb.strixdb_monitor import (
    view_all_agents_activity,
)

__all__ = [
    # Core operations
    "strixdb_create_category",
    "strixdb_delete",
    "strixdb_export",
    "strixdb_get",
    "strixdb_get_categories",
    "strixdb_get_config_status",
    "strixdb_get_stats",
    "strixdb_import_item",
    "strixdb_list",
    "strixdb_save",
    "strixdb_search",
    "strixdb_update",
    # Advanced operations
    "strixdb_batch_save",
    "strixdb_find_related",
    "strixdb_clear_cache",
    # Target lifecycle
    "strixdb_target_init",
    "strixdb_target_session_start",
    "strixdb_target_session_end",
    "strixdb_target_add_finding",
    "strixdb_target_add_endpoint",
    "strixdb_target_get_summary",
    # Monitoring
    "view_all_agents_activity",
]
