"""JSONL Metrics Sink -- writes metrics to JSONL files, routing by event.name."""

from __future__ import annotations
import os
from typing import Dict

from ...core.metric import MetricEvent
from ...core.contracts import MetricsSink
from ...core.io import JsonlWriter


class JsonlMetricsSink(MetricsSink):
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self._writers: Dict[str, JsonlWriter] = {}
        self._file_handles: Dict[str, object] = {}

    def write(self, event: MetricEvent) -> None:
        file_key = event.name

        if file_key not in self._writers:
            self._open_writer(file_key)

        self._writers[file_key].write_record(event.model_dump())

    def _open_writer(self, file_key: str) -> None:
        file_path = os.path.join(self.output_dir, f"{file_key}_metrics.jsonl")
        fp = open(file_path, "w", encoding="utf-8")
        writer = JsonlWriter(fp)
        self._file_handles[file_key] = fp
        self._writers[file_key] = writer

    def flush(self) -> None:
        for fp in self._file_handles.values():
            try:
                fp.flush()
            except Exception:
                pass

    def close(self) -> None:
        for writer in self._writers.values():
            try:
                writer.close()
            except Exception:
                pass
        self._writers.clear()
        self._file_handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
