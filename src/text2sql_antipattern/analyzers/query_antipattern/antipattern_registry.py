"""
Centralized registry for SQL antipattern patterns and metadata.

This module provides a single source of truth for antipattern pattern names,
human-readable labels, and metadata. Used across detector, analyzer, storage, and reporting.
"""

from enum import Enum
from typing import Dict


# Severity display configuration (emoji + label)
# This is for common severity levels - custom levels will use fallback
# NOTE: Config can define ANY severity levels - if not found here,
#       fallback will use severity name as-is without emoji
SEVERITY_DISPLAY: Dict[str, Dict[str, any]] = {
    "critical": {"emoji": "🔴", "label": "Critical", "order": 1},
    "high": {"emoji": "⚠️", "label": "High", "order": 2},
    "medium": {"emoji": "🔵", "label": "Medium", "order": 3},
    "low": {"emoji": "🟢", "label": "Low", "order": 4},
    # Add more as needed, e.g.:
    # "info": {"emoji": "ℹ️", "label": "Info", "order": 5},
}

# Default severity penalties for quality score calculation
# These are used if penalties are not specified in config
# Quality Score = 100 - sum(penalty * count_at_severity)
DEFAULT_SEVERITY_PENALTIES: Dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 2,
}

# Default penalty for custom severity levels not in the mapping
DEFAULT_CUSTOM_PENALTY: int = 10


class AntipatternPattern(str, Enum):
    """Enumeration of all SQL antipattern patterns."""
    
    # Critical severity antipatterns (data correctness)
    UNSAFE_UPDATE_DELETE = "unsafe_update_delete"  # Combined flag for both
    UNSAFE_DELETE = "unsafe_delete"                # Specific pattern
    UNSAFE_UPDATE = "unsafe_update"                # Specific pattern
    NULL_COMPARISON_EQUALS = "null_comparison_equals"
    CARTESIAN_PRODUCT = "cartesian_product"
    MISSING_GROUP_BY = "missing_group_by"
    
    # High severity antipatterns (performance/correctness)
    FUNCTION_IN_WHERE = "function_in_where"
    NOT_IN_NULLABLE = "not_in_nullable"
    LEADING_WILDCARD_LIKE = "leading_wildcard_like"
    LIMIT_WITHOUT_ORDER_BY = "limit_without_order_by"
    OFFSET_WITHOUT_ORDER_BY = "offset_without_order_by"
    
    # Medium severity antipatterns (configurable)
    REDUNDANT_DISTINCT = "redundant_distinct"
    CORRELATED_SUBQUERY = "correlated_subquery"
    SELECT_STAR = "select_star"
    SELECT_IN_EXISTS = "select_in_exists"


# Human-readable names for antipatterns
ANTIPATTERN_NAMES: Dict[str, str] = {
    AntipatternPattern.UNSAFE_UPDATE_DELETE: "Unsafe UPDATE/DELETE (no WHERE)",
    AntipatternPattern.UNSAFE_DELETE: "Unsafe DELETE (no WHERE)",
    AntipatternPattern.UNSAFE_UPDATE: "Unsafe UPDATE (no WHERE)",
    AntipatternPattern.NULL_COMPARISON_EQUALS: "= NULL comparison",
    AntipatternPattern.CARTESIAN_PRODUCT: "Cartesian product",
    AntipatternPattern.MISSING_GROUP_BY: "Missing GROUP BY",
    AntipatternPattern.FUNCTION_IN_WHERE: "Function in WHERE",
    AntipatternPattern.NOT_IN_NULLABLE: "NOT IN with nullable",
    AntipatternPattern.LEADING_WILDCARD_LIKE: "Leading wildcard LIKE",
    AntipatternPattern.LIMIT_WITHOUT_ORDER_BY: "LIMIT without ORDER BY",
    AntipatternPattern.OFFSET_WITHOUT_ORDER_BY: "OFFSET without ORDER BY",
    AntipatternPattern.REDUNDANT_DISTINCT: "Redundant DISTINCT",
    AntipatternPattern.CORRELATED_SUBQUERY: "Correlated subquery",
    AntipatternPattern.SELECT_STAR: "SELECT *",
    AntipatternPattern.SELECT_IN_EXISTS: "SELECT in EXISTS",
}


# Mapping from pattern to boolean field name (for backward compatibility with boolean columns)
PATTERN_TO_BOOLEAN_FIELD: Dict[str, str] = {
    AntipatternPattern.UNSAFE_UPDATE_DELETE: "has_unsafe_update_delete",
    AntipatternPattern.UNSAFE_DELETE: "has_unsafe_update_delete",
    AntipatternPattern.UNSAFE_UPDATE: "has_unsafe_update_delete",
    AntipatternPattern.NULL_COMPARISON_EQUALS: "has_null_comparison_equals",
    AntipatternPattern.CARTESIAN_PRODUCT: "has_cartesian_product",
    AntipatternPattern.MISSING_GROUP_BY: "has_missing_group_by",
    AntipatternPattern.FUNCTION_IN_WHERE: "has_function_in_where",
    AntipatternPattern.NOT_IN_NULLABLE: "has_not_in_nullable",
    AntipatternPattern.LEADING_WILDCARD_LIKE: "has_leading_wildcard_like",
    AntipatternPattern.LIMIT_WITHOUT_ORDER_BY: "has_limit_without_order_by",
    AntipatternPattern.OFFSET_WITHOUT_ORDER_BY: "has_offset_without_order_by",
    AntipatternPattern.REDUNDANT_DISTINCT: "has_redundant_distinct",
    AntipatternPattern.CORRELATED_SUBQUERY: "has_correlated_subquery",
    AntipatternPattern.SELECT_STAR: "has_select_star",
    AntipatternPattern.SELECT_IN_EXISTS: "has_select_in_exists",
}


def get_antipattern_name(pattern: str) -> str:
    """
    Get human-readable name for an antipattern pattern.
    
    Args:
        pattern: Pattern identifier (e.g., "select_star")
        
    Returns:
        Human-readable name, or formatted pattern if not found
    """
    return ANTIPATTERN_NAMES.get(pattern, pattern.replace("_", " ").title())


def get_boolean_field_name(pattern: str) -> str:
    """
    Get boolean field name for an antipattern pattern.
    
    Args:
        pattern: Pattern identifier
        
    Returns:
        Boolean field name (e.g., "has_select_star")
    """
    return PATTERN_TO_BOOLEAN_FIELD.get(pattern, f"has_{pattern}")


def get_severity_emoji(severity: str) -> str:
    """
    Get emoji for a severity level.
    
    Returns "⚪" (white circle) for custom severity levels not in SEVERITY_DISPLAY.
    """
    return SEVERITY_DISPLAY.get(severity, {}).get("emoji", "⚪")


def get_severity_label(severity: str) -> str:
    """
    Get display label for a severity level.
    
    For custom severity levels not in SEVERITY_DISPLAY, returns the capitalized name.
    Example: "p0" -> "P0", "blocker" -> "Blocker"
    """
    return SEVERITY_DISPLAY.get(severity, {}).get("label", severity.capitalize())


def get_severity_order(severity: str) -> int:
    """
    Get sort order for a severity level (lower = higher priority).
    
    Custom severity levels not in SEVERITY_DISPLAY get order 999 (lowest priority).
    """
    return SEVERITY_DISPLAY.get(severity, {}).get("order", 999)


def get_all_severity_levels() -> list[str]:
    """
    Get all defined severity levels in priority order.
    
    Note: Returns only the severity levels defined in SEVERITY_DISPLAY.
    Config can use additional custom severity levels not listed here.
    """
    return sorted(
        SEVERITY_DISPLAY.keys(),
        key=lambda s: get_severity_order(s)
    )


def select_config_for_dialect(antipatterns_config: Dict, dialect: str) -> Dict:
    """
    Select antipattern configuration for a specific SQL dialect.
    
    This function is dialect-agnostic selection logic that can be reused.
    
    Args:
        antipatterns_config: Full config dict with all dialects, or direct config dict
        dialect: SQL dialect name (e.g., "sqlite", "postgresql")
        
    Returns:
        Config dict for the dialect (keys are severity levels, values are pattern lists)
        Returns None if config is None or empty
        
    Examples:
        >>> config = {"sqlite": {"critical": [...], "high": [...]}}
        >>> select_config_for_dialect(config, "sqlite")
        {"critical": [...], "high": [...]}
        
        >>> config = {"critical": [...], "high": [...]}
        >>> select_config_for_dialect(config, "sqlite")
        {"critical": [...], "high": [...]}  # Already in right format
    """
    if not antipatterns_config:
        return None
    
    # Normalize dialect name
    dialect = (dialect or "sqlite").lower()
    
    # Map common dialect variations
    dialect_map = {
        "postgres": "postgresql",
        "pg": "postgresql"
    }
    dialect = dialect_map.get(dialect, dialect)
    
    # Heuristic: if config has known dialect keys, it's a multi-dialect config
    # Otherwise, assume it's already a direct severity→patterns config
    known_dialects = {"sqlite", "postgresql", "postgres", "mysql", "mssql", "oracle"}
    
    has_dialect_keys = any(key in known_dialects for key in antipatterns_config.keys())
    
    if not has_dialect_keys:
        # Direct config (already in right format)
        return antipatterns_config
    
    # Multi-dialect config - select the right one
    if dialect in antipatterns_config:
        return antipatterns_config[dialect]
    elif "sqlite" in antipatterns_config:
        # Fallback to sqlite
        return antipatterns_config["sqlite"]
    else:
        # No matching dialect found
        return None


def get_severity_penalties(penalties_config: Dict[str, int] = None) -> Dict[str, int]:
    """
    Get severity penalties for quality score calculation.
    
    Args:
        penalties_config: Optional custom penalties from config.
                         If None or empty, returns default penalties.
        
    Returns:
        Dict mapping severity level to penalty points.
        
    Examples:
        >>> get_severity_penalties(None)
        {"critical": 30, "high": 15, "medium": 5, "low": 2, ...}
        
        >>> get_severity_penalties({"critical": 50, "high": 20})
        {"critical": 50, "high": 20, "medium": 5, "low": 2, ...}  # Merged with defaults
    """
    # Start with defaults
    penalties = DEFAULT_SEVERITY_PENALTIES.copy()
    
    # Override with config values if provided
    if penalties_config:
        penalties.update(penalties_config)
    
    return penalties


def get_penalty_for_severity(severity: str, penalties: Dict[str, int] = None) -> int:
    """
    Get penalty points for a specific severity level.
    
    Args:
        severity: Severity level name (e.g., "critical", "high")
        penalties: Optional custom penalties dict. If None, uses defaults.
        
    Returns:
        Penalty points for the severity level.
        Returns DEFAULT_CUSTOM_PENALTY for unknown severity levels.
    """
    if penalties is None:
        penalties = DEFAULT_SEVERITY_PENALTIES
    
    return penalties.get(severity, DEFAULT_CUSTOM_PENALTY)

