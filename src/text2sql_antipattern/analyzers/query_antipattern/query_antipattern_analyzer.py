from __future__ import annotations
from typing import Iterable, Iterator
import time

from text2sql_antipattern.analyzers.query_antipattern.antipattern_detector import detect_antipatterns
from text2sql_antipattern.analyzers.query_antipattern.antipattern_registry import select_config_for_dialect
from text2sql_antipattern.core.contracts import AnnotatingAnalyzer, MetricsSink
from text2sql_antipattern.core.utils import has_previous_failure
from text2sql_antipattern.pipeline.registry import register_analyzer
from ...core.models import DataItem

from .metrics import (
    QueryAntipatternMetricEvent,
    QueryAntipatternFeatures,
    QueryAntipatternStats,
    QueryAntipatternTags
)


@register_analyzer("query_antipattern_analyzer")
class QueryAntipatternAnalyzer(AnnotatingAnalyzer):
    """
    SQL antipattern detector and code quality analyzer.

    Detects common SQL antipatterns and code smells with configurable
    severity levels and quality scoring.
    """

    name = "query_antipattern_analyzer"
    INJECT = ["dialect"]

    def __init__(
        self,
        dialect: str,
        enabled: bool,
        antipatterns: dict = None,
        penalties: dict = None
    ) -> None:
        self.db_dialect = dialect or "sqlite"
        self.enabled = enabled
        self.antipattern_config = select_config_for_dialect(antipatterns, self.db_dialect)
        self.penalties_config = penalties

    def analyze(self, items: Iterable[DataItem], sink: MetricsSink, dataset_id: str) -> Iterator[DataItem]:
        for item in items:
            if not self.enabled:
                yield item
                continue

            if has_previous_failure(item.metadata or {}):
                metric = QueryAntipatternMetricEvent(
                    dataset_id=dataset_id,
                    item_id=item.id,
                    db_id=item.dbId,
                    status="skipped",
                    success=False,
                    duration_ms=0.0,
                    err="skipped due to previous analyzer failure",
                    features=QueryAntipatternFeatures(parseable=False)
                )
                sink.write(metric)
                self._annotate_item_skipped(item)
                yield item
                continue

            start = time.perf_counter()

            features, stats, tags, parseable, err = self._analyze_query(item)

            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            stats.collect_ms = duration_ms

            if not parseable:
                status = "failed"
            elif features.total_antipatterns > 0:
                status = "warns"
            else:
                status = "ok"

            metric = QueryAntipatternMetricEvent(
                dataset_id=dataset_id,
                item_id=item.id,
                db_id=item.dbId,
                status=status,
                success=(status == "ok"),
                duration_ms=duration_ms,
                err=err,
                features=features,
                stats=stats,
                tags=tags
            )

            sink.write(metric)

            item.metadata = item.metadata or {}
            item.metadata.setdefault("analysisSteps", [])
            item.metadata["analysisSteps"].append({
                "name": "query_antipattern",
                "status": status,
                "quality_score": features.quality_score if parseable else None,
                "quality_level": features.quality_level if parseable else "unknown",
                "antipattern_count": features.total_antipatterns if parseable else None
            })

            yield item

    def _annotate_item_skipped(self, item: DataItem) -> None:
        item.metadata = item.metadata or {}
        item.metadata.setdefault("analysisSteps", [])
        item.metadata["analysisSteps"].append({
            "name": "query_antipattern",
            "status": "skipped",
            "reason": "previous analyzer failed",
            "quality_score": None,
            "quality_level": "unknown",
            "antipattern_count": None
        })

    def _analyze_query(self, item: DataItem):
        stats = QueryAntipatternStats(dialect=self.db_dialect or "sqlite")
        tags = QueryAntipatternTags(dialect=self.db_dialect or "sqlite")

        if not item.sql or not item.sql.strip():
            features = QueryAntipatternFeatures(parseable=False, quality_score=0, quality_level="poor")
            return features, stats, tags, False, "Empty or null SQL"

        try:
            features = detect_antipatterns(
                item.sql,
                self.db_dialect,
                config=self.antipattern_config,
                penalties=self.penalties_config
            )
            ok = features.parseable
            return features, stats, tags, ok, None if ok else "Unparseable SQL"
        except Exception as e:
            features = QueryAntipatternFeatures(parseable=False, quality_score=0, quality_level="poor")
            stats.errors.append({"kind": "detection_error", "message": str(e)})
            return features, stats, tags, False, f"Detection error: {e}"
