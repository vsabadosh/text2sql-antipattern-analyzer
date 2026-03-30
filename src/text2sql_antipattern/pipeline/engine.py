from __future__ import annotations
from typing import Dict, Any, Iterable, Iterator
import os

from ..core.io import yaml_load
from ..core.utils import get_logger
from ..output import RunOutputManager
from ..core.models import DataItem
from .progress import SimpleProgress
from ..di_container import PipelineContainer


def _dataset_name_from_cfg(cfg: Dict[str, Any]) -> str:
    out = (cfg.get("output") or {})
    if out.get("dataset_name"):
        return str(out["dataset_name"])
    lcfg = (cfg.get("load") or {})
    lparams = (lcfg.get("params") or {})
    path = (lparams.get("path") or "")
    base = os.path.basename(path)
    return os.path.splitext(base)[0] or lcfg.get("name", "dataset")


def run_pipeline(config_path: str) -> str:
    logger = get_logger("text2sql.engine")
    cfg: Dict[str, Any] = yaml_load(config_path)

    container = PipelineContainer()
    PipelineContainer.wire_from_config(container, cfg)

    progress_cfg = cfg.get("progress", {})
    expected_items = progress_cfg.get("expected_items")
    show_progress = progress_cfg.get("show_progress", True)

    loader = container.loader()
    items = loader.load()

    dataset_name = _dataset_name_from_cfg(cfg)
    output = RunOutputManager(
        dataset_name=dataset_name,
        config=cfg,
    )

    for n in container.normalizers_chain():
        items = n.normalize_stream(items)
    data_items: Iterable[DataItem] = items

    with output.metric_sink_context() as metric_sink:
        def _apply(an, upstream: Iterable[DataItem]) -> Iterable[DataItem]:
            def gen() -> Iterator[DataItem]:
                for it in an.analyze(upstream, metric_sink, dataset_name):
                    yield it
            return gen()

        for analyzer in container.analyzers_chain():
            data_items = _apply(analyzer, data_items)

        count = 0
        with SimpleProgress(expected_total=expected_items, enabled=show_progress) as progress:
            with output.annotated_writer() as writer:
                for item in data_items:
                    writer.write_record(item.model_dump())
                    count += 1
                    progress.update(1)

    logger.info("done", extra={"total_items": count, "output_dir": output.root_dir})

    output_cfg = cfg.get("output", {})
    reports_cfg = output_cfg.get("reports", {})

    if reports_cfg.get("enabled", False) and os.path.exists(output.duckdb_path):
        try:
            from ..output.report import generate_all_reports
            generate_all_reports(output.root_dir, output.duckdb_path, reports_cfg)
        except ImportError:
            logger.warning("report generation skipped - duckdb not installed")
        except Exception as e:
            logger.warning("report generation failed", extra={"error": str(e)})

    return output.root_dir
