from __future__ import annotations

import gzip
import json
from typing import Iterator, Dict, Any, Union
from pathlib import Path

from text2sql_antipattern.core.contracts import Loader
from text2sql_antipattern.pipeline.registry import register_loader


@register_loader("jsonl")
class JsonlLoader(Loader):
    def __init__(self, path: Union[str, Path], encoding: str = "utf-8") -> None:
        self.path = Path(path)
        self.encoding = encoding
        if not self.path.exists():
            raise FileNotFoundError(self.path)

    def load(self) -> Iterator[Dict[str, Any]]:
        return stream_jsonl(self.path, encoding=self.encoding)

def stream_jsonl(path: Union[str, Path], encoding: str = "utf-8") -> Iterator[Dict[str, Any]]:
    """Lazy JSONL reader; supports *.gz."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(p)

    if p.suffix == ".gz" or p.name.endswith(".jsonl.gz"):
        opener = lambda fp: gzip.open(fp, "rt", encoding=encoding)  # noqa: E731
    else:
        opener = lambda fp: open(fp, "rt", encoding=encoding)      # noqa: E731

    with opener(p) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{p}:{i} invalid JSON: {e}") from e
