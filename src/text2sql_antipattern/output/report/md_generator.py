"""Markdown Report Generator -- generates antipattern quality reports from DuckDB metrics."""

from __future__ import annotations
import duckdb
from typing import Dict
from pathlib import Path
from datetime import datetime
import sqlglot

try:
    from text2sql_antipattern.analyzers.query_antipattern.antipattern_registry import (
        get_antipattern_name,
        get_severity_emoji,
        get_severity_label,
        get_severity_order
    )
except ImportError:
    def get_antipattern_name(pattern: str) -> str:
        return pattern.replace("_", " ").title()

    def get_severity_emoji(severity: str) -> str:
        return {"critical": "🔴", "high": "⚠️", "medium": "🔵", "low": "🟢"}.get(severity, "⚪")

    def get_severity_label(severity: str) -> str:
        return severity.capitalize()

    def get_severity_order(severity: str) -> int:
        return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(severity, 999)


class MarkdownReportGenerator:
    """Generate markdown reports from DuckDB metrics."""
    DIALECT_CHECKS: tuple[str, ...] = (
        "sqlite",
        "postgres",
        "duckdb",
        "mysql",
        "bigquery",
        "snowflake",
        "tsql",
    )

    def __init__(self, duckdb_path: str):
        self.duckdb_path = duckdb_path
        self.conn = duckdb.connect(duckdb_path, read_only=True)
        self.available_tables = self._detect_tables()

    def _detect_tables(self) -> Dict[str, str]:
        result = self.conn.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'main' AND table_name LIKE 'metrics_%'
        """).fetchall()

        tables = {}
        for (table_name,) in result:
            analyzer_name = table_name.replace("metrics_", "")
            tables[analyzer_name] = table_name
        return tables

    def _table_has_column(self, table_name: str, column_name: str) -> bool:
        result = self.conn.execute(
            """
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = 'main'
              AND table_name = ?
              AND column_name = ?
            """,
            [table_name, column_name],
        ).fetchone()
        return bool(result and result[0] > 0)

    def _classify_dialect_parseability(self, sql: str) -> tuple[list[str], list[str]]:
        parseable: list[str] = []
        not_parseable: list[str] = []
        for dialect in self.DIALECT_CHECKS:
            try:
                sqlglot.parse_one(sql, read=dialect)
                parseable.append(dialect)
            except Exception:
                not_parseable.append(dialect)
        return parseable, not_parseable

    def generate_query_quality_report(self, output_path: str) -> None:
        """Generate Query Quality Report."""
        antipattern_table = self.available_tables.get("query_antipattern")

        if not antipattern_table:
            Path(output_path).write_text("# Query Quality Report\n\nNo metrics available.", encoding="utf-8")
            return

        sections: list[str] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        sections.append(f"# Query Quality Report\n\n**Generated:** {now}")
        sections.append("")

        total_queries = 0
        analyzed_queries = 0
        quality_score_sum = 0
        antipatterns_sum = 0

        total_result = self.conn.execute(f"SELECT COUNT(*) FROM {antipattern_table}").fetchone()
        total_queries = total_result[0] or 0

        skipped_result = self.conn.execute(f"SELECT COUNT(*) FROM {antipattern_table} WHERE status = 'skipped'").fetchone()
        skipped_queries = skipped_result[0] or 0

        failed_result = self.conn.execute(
            f"SELECT COUNT(*) FROM {antipattern_table} WHERE status = 'failed'"
        ).fetchone()
        failed_queries = failed_result[0] or 0

        parseable_result = self.conn.execute(f"""
            SELECT COUNT(*)
            FROM {antipattern_table}
            WHERE parseable = true AND status != 'skipped'
        """).fetchone()
        analyzed_queries = parseable_result[0] or 0

        stats_result = self.conn.execute(f"""
            SELECT AVG(quality_score), AVG(total_antipatterns)
            FROM {antipattern_table}
            WHERE parseable = true AND status != 'skipped'
        """).fetchone()
        if stats_result:
            quality_score_sum = stats_result[0] or 0
            antipatterns_sum = stats_result[1] or 0

        sections.append("## Summary")
        sections.append("")
        if total_queries > 0:
            sections.append(
                f"- **Total Queries:** {total_queries:,} · **Analyzed (Parseable):** {analyzed_queries:,} · **Failed:** {failed_queries:,} · **Skipped:** {skipped_queries:,}"
            )
            if analyzed_queries > 0:
                sections.append(f"- **Avg Quality Score:** {quality_score_sum:.1f}/100 · **Avg Antipatterns:** {antipatterns_sum:.1f}")
        else:
            sections.append("- **Total Queries:** 0")
        sections.append("")

        sections.append("## Quality Indicators")
        sections.append("")

        sections.append(self._generate_antipatterns_quality(antipattern_table))
        sections.append(self._generate_failed_queries_section(antipattern_table))

        Path(output_path).write_text("\n".join(sections), encoding="utf-8")

    def _generate_antipatterns_quality(self, table: str) -> str:
        """Generate antipatterns section -- dynamically from JSON data."""
        lines = ["### Antipatterns Detected", ""]

        try:
            total = self.conn.execute(f"""
                SELECT COUNT(*) FROM {table} WHERE parseable = true AND status != 'skipped'
            """).fetchone()[0]

            if total == 0:
                lines.append("*No queries analyzed for antipatterns.*")
                lines.append("")
                return "\n".join(lines)

            antipattern_stats = self.conn.execute(f"""
                SELECT
                    json_extract_string(ap, '$.pattern') as pattern,
                    json_extract_string(ap, '$.severity') as severity,
                    ANY_VALUE(json_extract_string(ap, '$.message')) as example_message,
                    COUNT(*) as count,
                    COUNT(DISTINCT item_id) as affected_queries
                FROM (
                    SELECT
                        item_id,
                        unnest(
                            COALESCE(
                                TRY_CAST(antipatterns AS JSON[]),
                                []
                            )
                        ) as ap
                    FROM {table}
                    WHERE parseable = true AND status != 'skipped'
                )
                WHERE ap IS NOT NULL
                GROUP BY pattern, severity
            """).fetchall()

            antipattern_stats = sorted(
                antipattern_stats,
                key=lambda x: (get_severity_order(x[1]), -x[4])
            )

            if not antipattern_stats:
                lines.append("*No antipatterns detected.*")
                lines.append("")
            else:
                lines.append("| Antipattern | Occurrences | Affected Queries | % of Queries | Severity |")
                lines.append("|-------------|-------------|------------------|--------------|----------|")

                for pattern, severity, message, count, affected_queries in antipattern_stats:
                    emoji = get_severity_emoji(severity)
                    label = get_severity_label(severity)
                    severity_display = f"{emoji} {label}"
                    pattern_name = get_antipattern_name(pattern)
                    affected_pct = round(affected_queries * 100.0 / total, 1) if total > 0 else 0
                    lines.append(f"| {pattern_name} | {count:,} | {affected_queries:,} | {affected_pct}% | {severity_display} |")

                lines.append("")

            summary_stats = self.conn.execute(f"""
                SELECT
                    ROUND(AVG(quality_score), 1) as avg_quality,
                    ROUND(AVG(total_antipatterns), 1) as avg_antipatterns
                FROM {table} WHERE parseable = true AND status != 'skipped'
            """).fetchone()

            if summary_stats:
                avg_quality, avg_antipatterns = summary_stats
                lines.append(f"**Summary:** Avg quality score: {avg_quality or 0}/100 · Avg antipatterns per query: {avg_antipatterns or 0}")

            no_antipatterns_count = self.conn.execute(f"""
                SELECT COUNT(*)
                FROM {table}
                WHERE
                    parseable = true
                    AND status != 'skipped'
                    AND COALESCE(total_antipatterns, 0) = 0
            """).fetchone()[0]

            if total > 0:
                no_antipatterns_pct = round(no_antipatterns_count * 100.0 / total, 1)
            else:
                no_antipatterns_pct = 0.0

            lines.append(f"**Queries without antipatterns:** {no_antipatterns_count:,} ({no_antipatterns_pct}% of analyzed queries)")
            lines.append("")

            severity_counts = self.conn.execute(f"""
                SELECT
                    json_extract_string(ap, '$.severity') as severity,
                    COUNT(*) as count
                FROM (
                    SELECT
                        unnest(
                            COALESCE(
                                TRY_CAST(antipatterns AS JSON[]),
                                []
                            )
                        ) as ap
                    FROM {table}
                    WHERE parseable = true AND status != 'skipped'
                )
                WHERE ap IS NOT NULL
                GROUP BY severity
            """).fetchall()

            if severity_counts:
                severity_counts_sorted = sorted(
                    severity_counts,
                    key=lambda x: get_severity_order(x[0])
                )

                severity_parts = []
                for severity, count in severity_counts_sorted:
                    emoji = get_severity_emoji(severity)
                    label = get_severity_label(severity)
                    severity_parts.append(f"{label}: {count:,} {emoji}")

                lines.append(f"**By Severity:** {' · '.join(severity_parts)}")
                lines.append("")

            antipattern_details = self.conn.execute(f"""
                SELECT DISTINCT
                    json_extract_string(ap, '$.pattern') as pattern,
                    json_extract_string(ap, '$.severity') as severity,
                    item_id
                FROM (
                    SELECT
                        item_id,
                        unnest(
                            COALESCE(
                                TRY_CAST(antipatterns AS JSON[]),
                                []
                            )
                        ) as ap
                    FROM {table}
                    WHERE parseable = true AND status != 'skipped'
                )
                WHERE ap IS NOT NULL
                ORDER BY
                    pattern,
                    severity,
                    CAST(item_id AS INTEGER) NULLS LAST,
                    item_id
            """).fetchall()

            details_map: dict[tuple[str, str], list[int]] = {}
            for pattern, severity, item_id in antipattern_details:
                if pattern is None or severity is None or item_id is None:
                    continue
                key = (pattern, severity)
                details_map.setdefault(key, []).append(item_id)

            if antipattern_stats and antipattern_details:
                lines.append("#### Antipattern Details by item_id")
                lines.append("")

                for pattern, severity, message, count, affected_queries in antipattern_stats:
                    key = (pattern, severity)
                    item_ids = details_map.get(key, [])
                    if not item_ids:
                        continue

                    emoji = get_severity_emoji(severity)
                    label = get_severity_label(severity)
                    severity_display = f"{emoji} {label}"
                    pattern_name = get_antipattern_name(pattern)

                    lines.append(f"##### {pattern_name} ({severity_display})")
                    lines.append("")
                    lines.append(f"- **Occurrences:** {count:,}")
                    lines.append(f"- **Affected queries (item_id): {len(item_ids):,}")

                    try:
                        item_ids_sorted = sorted(item_ids, key=lambda x: int(x))
                    except (TypeError, ValueError):
                        item_ids_sorted = sorted(item_ids, key=lambda x: str(x))

                    item_ids_str = ", ".join(str(i) for i in item_ids_sorted)
                    lines.append(f"- **item_id list:** {item_ids_str}")
                    lines.append("")

        except Exception as e:
            lines.append(f"*Error generating antipatterns: {e}*")
            lines.append("")

        return "\n".join(lines)

    def _generate_failed_queries_section(self, table: str) -> str:
        lines = ["### Failed Query Parsing", ""]

        failed_count = self.conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE status = 'failed'"
        ).fetchone()[0]

        if not failed_count:
            lines.append("*No failed queries.*")
            lines.append("")
            return "\n".join(lines)

        lines.append(f"**Failed queries:** {failed_count:,}")
        lines.append("")

        has_failed_query = self._table_has_column(table, "failed_query")

        if has_failed_query:
            failed_rows = self.conn.execute(f"""
                SELECT item_id, err, failed_query
                FROM {table}
                WHERE status = 'failed'
                ORDER BY CAST(item_id AS INTEGER) NULLS LAST, item_id
            """).fetchall()
        else:
            failed_rows = self.conn.execute(f"""
                SELECT item_id, err, NULL as failed_query
                FROM {table}
                WHERE status = 'failed'
                ORDER BY CAST(item_id AS INTEGER) NULLS LAST, item_id
            """).fetchall()
            lines.append("*SQL text for failed rows is unavailable in this metrics database version.*")
            lines.append("")

        lines.append("#### Failed items")
        lines.append("")
        for item_id, err, failed_query in failed_rows:
            lines.append(f"- **item_id:** {item_id}")
            lines.append(f"- **error:** {err or 'unknown error'}")
            if failed_query:
                parseable_dialects, not_parseable_dialects = self._classify_dialect_parseability(
                    str(failed_query)
                )
                lines.append(
                    f"- **parseable dialects:** {', '.join(parseable_dialects) if parseable_dialects else 'none'}"
                )
                lines.append(
                    f"- **not parseable dialects:** {', '.join(not_parseable_dialects) if not_parseable_dialects else 'none'}"
                )
                lines.append("- **query:**")
                lines.append("```sql")
                lines.append(str(failed_query).strip())
                lines.append("```")
            else:
                lines.append("- **query:** _not available_")
            lines.append("")

        return "\n".join(lines)

    def close(self) -> None:
        self.conn.close()


def generate_query_quality_report(duckdb_path: str, output_path: str) -> None:
    """Generate Query Quality Report."""
    gen = MarkdownReportGenerator(duckdb_path)
    try:
        gen.generate_query_quality_report(output_path)
    finally:
        gen.close()
