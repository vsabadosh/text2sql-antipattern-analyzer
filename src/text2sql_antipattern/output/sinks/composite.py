"""Composite Metrics Sink -- writes to multiple sinks simultaneously."""

from __future__ import annotations
from typing import List

from ...core.metric import MetricEvent
from ...core.contracts import MetricsSink


class CompositeMetricsSink(MetricsSink):
    def __init__(self, sinks: List[MetricsSink]):
        self.sinks = sinks

    def write(self, event: MetricEvent) -> None:
        for sink in self.sinks:
            try:
                sink.write(event)
            except Exception as e:
                print(f"Error writing to sink {sink.__class__.__name__}: {e}")

    def flush(self) -> None:
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception as e:
                print(f"Error flushing sink {sink.__class__.__name__}: {e}")

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                print(f"Error closing sink {sink.__class__.__name__}: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
