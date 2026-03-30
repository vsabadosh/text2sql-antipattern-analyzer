from __future__ import annotations
from typing import List, Dict
from pydantic import BaseModel, Field

from text2sql_antipattern.core.metric import MetricEvent


class AntipatternInstance(BaseModel):
    """Single antipattern detection instance."""
    pattern: str
    severity: str
    message: str
    location: str = ""


class QueryAntipatternFeatures(BaseModel):
    """Aggregatable metrics for query antipattern detection."""

    parseable: bool = True

    total_antipatterns: int = 0

    antipatterns: List[AntipatternInstance] = Field(default_factory=list)

    # Critical severity
    has_unsafe_update_delete: bool = False
    has_null_comparison_equals: bool = False
    has_cartesian_product: bool = False
    has_missing_group_by: bool = False

    # High severity
    has_function_in_where: bool = False
    has_not_in_nullable: bool = False
    has_leading_wildcard_like: bool = False
    has_limit_without_order_by: bool = False
    has_offset_without_order_by: bool = False

    # Medium severity
    has_redundant_distinct: bool = False
    has_correlated_subquery: bool = False
    has_select_star: bool = False
    has_select_in_exists: bool = False

    quality_score: int = 100
    quality_level: str = "excellent"


class QueryAntipatternStats(BaseModel):
    """Detailed drill-down data for antipattern analysis."""
    collect_ms: float = 0.0
    parser: str = "sqlglot"
    dialect: str = "sqlite"
    errors: List[Dict[str, str]] = Field(default_factory=list)
    warnings: List[Dict[str, str]] = Field(default_factory=list)


class QueryAntipatternTags(BaseModel):
    """Context metadata for antipattern analysis."""
    dialect: str = "sqlite"
    analyzer_version: str = "1.0.0"


class QueryAntipatternMetricEvent(MetricEvent):
    """Typed metric event for query antipattern detection."""
    event_type: str = "query_analysis"
    name: str = "query_antipattern"

    features: QueryAntipatternFeatures
    stats: QueryAntipatternStats = Field(default_factory=QueryAntipatternStats)
    tags: QueryAntipatternTags = Field(default_factory=QueryAntipatternTags)
