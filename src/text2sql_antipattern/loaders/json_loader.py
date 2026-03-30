from __future__ import annotations

from pathlib import Path
from typing import Iterator, Dict, Any, Union
import json

from text2sql_antipattern.core.contracts import Loader
from text2sql_antipattern.pipeline.registry import register_loader


@register_loader("json")
class JsonLoader(Loader):
    """Loader for regular JSON file with an array of objects at the root."""
    def __init__(self, path: Union[str, Path], encoding: str = "utf-8") -> None:
        self.path = Path(path)
        self.encoding = encoding
        if not self.path.exists():
            raise FileNotFoundError(self.path)

    def load(self) -> Iterator[Dict[str, Any]]:
        with open(self.path, "rt", encoding=self.encoding) as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(
                f"Unsupported JSON structure in {self.path}. "
                "Expected a top-level array of objects."
            )

        for i, item in enumerate(data, 1):
            if not isinstance(item, dict):
                raise ValueError(f"Array element #{i} in {self.path} is not an object")
            yield item
