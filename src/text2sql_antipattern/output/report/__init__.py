"""Report generation from metrics."""

from .md_generator import (
    MarkdownReportGenerator,
    generate_query_quality_report,
)


def generate_all_reports(output_dir: str, duckdb_path: str, config: dict = None) -> None:
    """Generate analysis reports from DuckDB metrics based on configuration."""
    import os
    from ...core.utils import get_logger

    logger = get_logger("text2sql.report_generator")

    if config is None:
        config = {
            "enabled": True,
            "output_dir": "all_reports",
            "query_quality": True,
        }

    if not config.get("enabled", False):
        logger.info("report generation disabled")
        return

    reports_subdir = config.get("output_dir", "all_reports")
    reports_dir = os.path.join(output_dir, reports_subdir)
    os.makedirs(reports_dir, exist_ok=True)

    available_reports = [
        ("query_quality", "query_quality_report.md", "generating Query Quality report", generate_query_quality_report),
    ]

    for toggle_key, filename, log_message, generator_func in available_reports:
        if config.get(toggle_key, False):
            report_path = os.path.join(reports_dir, filename)
            logger.info(log_message, extra={"report_path": report_path})
            try:
                generator_func(duckdb_path, report_path)
                logger.info(f"report generated", extra={"report_path": report_path})
            except Exception as e:
                logger.warning(f"report generation failed", extra={"error": str(e), "report_path": report_path})


__all__ = [
    "MarkdownReportGenerator",
    "generate_query_quality_report",
    "generate_all_reports",
]
