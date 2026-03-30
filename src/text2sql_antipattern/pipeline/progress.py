"""Simple progress tracking for streaming pipeline."""

from __future__ import annotations
from typing import Optional
import sys


class SimpleProgress:
    """Lightweight progress tracker for streaming pipelines."""

    def __init__(self, expected_total: Optional[int] = None, enabled: bool = True):
        self.expected_total = expected_total
        self.enabled = enabled
        self.processed = 0
        self._display = None

        if enabled:
            self._init_display()

    def _init_display(self):
        if not self.enabled:
            return

        try:
            from tqdm import tqdm
            self._display = tqdm(
                total=self.expected_total,
                desc="Processing",
                unit="items",
                disable=False
            )
            self._backend = "tqdm"
            return
        except ImportError:
            pass

        self._backend = "simple"
        self._last_print = 0
        print(f"Processing items... (expected: {self.expected_total or 'unknown'})")

    def update(self, n: int = 1):
        if not self.enabled:
            return

        self.processed += n

        if self._backend == "tqdm" and self._display:
            self._display.update(n)
        elif self._backend == "simple":
            if self.processed % 100 == 0 or self.processed == self.expected_total:
                if self.expected_total:
                    pct = (self.processed / self.expected_total) * 100
                    print(f"Progress: {self.processed}/{self.expected_total} ({pct:.1f}%)")
                else:
                    print(f"Processed: {self.processed} items")

    def close(self):
        if not self.enabled:
            return

        if self._backend == "tqdm" and self._display:
            self._display.close()
        elif self._backend == "simple":
            if self.expected_total:
                print(f"Completed: {self.processed}/{self.expected_total}")
            else:
                print(f"Completed: {self.processed} items")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
