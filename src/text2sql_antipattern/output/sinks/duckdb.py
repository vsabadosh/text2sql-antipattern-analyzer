"""DuckDB Metrics Sink -- writes antipattern metrics to DuckDB tables."""

from __future__ import annotations
import duckdb
from typing import Dict, Any, Set
from pathlib import Path

from ...core.metric import MetricEvent
from ...core.contracts import MetricsSink


class DuckDBMetricsSink(MetricsSink):
    """Writes metrics to DuckDB tables with antipattern-specific schema."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = duckdb.connect(db_path)
        self._created_tables: Set[str] = set()
        self._batches: Dict[str, list[Dict[str, Any]]] = {}
        self._batch_size = 100

    def _ensure_table(self, table_name: str, analyzer_name: str) -> None:
        if table_name in self._created_tables:
            return

        schema_map = {
            "query_antipattern": lambda: self._query_antipattern_table(table_name),
        }

        schema_fn = schema_map.get(analyzer_name, lambda: self._generic_table(table_name))
        create_sql = schema_fn()

        try:
            self.conn.execute(create_sql)
            self._created_tables.add(table_name)
        except Exception as e:
            print(f"Warning: Table creation issue for {table_name}: {e}")

    def _query_antipattern_table(self, table_name: str) -> str:
        return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            ts TIMESTAMP,
            spec_version VARCHAR,
            dataset_id VARCHAR,
            item_id VARCHAR,
            db_id VARCHAR,
            event_type VARCHAR,
            name VARCHAR,
            status VARCHAR,
            success BOOLEAN,
            duration_ms DOUBLE,
            err VARCHAR,
            parseable BOOLEAN,
            has_unsafe_update_delete BOOLEAN,
            has_null_comparison_equals BOOLEAN,
            has_cartesian_product BOOLEAN,
            has_missing_group_by BOOLEAN,
            has_function_in_where BOOLEAN,
            has_not_in_nullable BOOLEAN,
            has_leading_wildcard_like BOOLEAN,
            has_redundant_distinct BOOLEAN,
            has_correlated_subquery BOOLEAN,
            has_select_star BOOLEAN,
            has_select_in_exists BOOLEAN,
            total_antipatterns INTEGER,
            quality_score DOUBLE,
            quality_level VARCHAR,
            antipatterns JSON,
            collect_ms DOUBLE,
            parser VARCHAR,
            dialect VARCHAR,
            errors JSON,
            warnings JSON,
            tags_dialect VARCHAR,
            PRIMARY KEY (dataset_id, item_id, ts)
        )
        """

    def _generic_table(self, table_name: str) -> str:
        return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            ts TIMESTAMP,
            spec_version VARCHAR,
            dataset_id VARCHAR,
            item_id VARCHAR,
            db_id VARCHAR,
            event_type VARCHAR,
            name VARCHAR,
            status VARCHAR,
            success BOOLEAN,
            duration_ms DOUBLE,
            err VARCHAR,
            features JSON,
            stats JSON,
            tags JSON,
            PRIMARY KEY (dataset_id, COALESCE(item_id, db_id), ts)
        )
        """

    def write(self, event: MetricEvent) -> None:
        table_name = f"metrics_{event.name}"
        analyzer_name = event.name
        self._ensure_table(table_name, analyzer_name)

        if table_name not in self._batches:
            self._batches[table_name] = []

        self._batches[table_name].append(event.model_dump())

        if len(self._batches[table_name]) >= self._batch_size:
            self._flush_table(table_name, analyzer_name)

    def flush(self) -> None:
        for table_name in list(self._batches.keys()):
            analyzer_name = table_name.replace("metrics_", "")
            self._flush_table(table_name, analyzer_name)

    def _flush_table(self, table_name: str, analyzer_name: str) -> None:
        if table_name not in self._batches or not self._batches[table_name]:
            return

        try:
            if analyzer_name == "query_antipattern":
                self._insert_query_antipattern(table_name, self._batches[table_name])
            else:
                self._insert_generic(table_name, self._batches[table_name])
            self._batches[table_name].clear()
        except Exception as e:
            print(f"Error flushing batch for {table_name}: {e}")
            raise

    def _insert_query_antipattern(self, table_name: str, records: list[Dict[str, Any]]) -> None:
        import json

        for rec in records:
            features = rec.get("features", {})
            stats = rec.get("stats", {})
            tags = rec.get("tags", {})

            self.conn.execute(f"""
                INSERT INTO {table_name} VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?
                )
            """, [
                rec.get("ts"),
                rec.get("spec_version"),
                rec.get("dataset_id"),
                rec.get("item_id"),
                rec.get("db_id"),
                rec.get("event_type"),
                rec.get("name"),
                rec.get("status"),
                rec.get("success"),
                rec.get("duration_ms"),
                rec.get("err"),
                features.get("parseable"),
                features.get("has_unsafe_update_delete"),
                features.get("has_null_comparison_equals"),
                features.get("has_cartesian_product"),
                features.get("has_missing_group_by"),
                features.get("has_function_in_where"),
                features.get("has_not_in_nullable"),
                features.get("has_leading_wildcard_like"),
                features.get("has_redundant_distinct"),
                features.get("has_correlated_subquery"),
                features.get("has_select_star"),
                features.get("has_select_in_exists"),
                features.get("total_antipatterns"),
                features.get("quality_score"),
                features.get("quality_level"),
                json.dumps(features.get("antipatterns", [])),
                stats.get("collect_ms"),
                stats.get("parser"),
                stats.get("dialect"),
                json.dumps(stats.get("errors", [])),
                json.dumps(stats.get("warnings", [])),
                tags.get("dialect")
            ])

    def _insert_generic(self, table_name: str, records: list[Dict[str, Any]]) -> None:
        import json

        for rec in records:
            self.conn.execute(f"""
                INSERT INTO {table_name} VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?
                )
            """, [
                rec.get("ts"),
                rec.get("spec_version"),
                rec.get("dataset_id"),
                rec.get("item_id"),
                rec.get("db_id"),
                rec.get("event_type"),
                rec.get("name"),
                rec.get("status"),
                rec.get("success"),
                rec.get("duration_ms"),
                rec.get("err"),
                json.dumps(rec.get("features", {})),
                json.dumps(rec.get("stats", {})),
                json.dumps(rec.get("tags", {}))
            ])

    def close(self) -> None:
        self.flush()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
