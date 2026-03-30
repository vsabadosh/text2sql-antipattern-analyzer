from __future__ import annotations

from typing import Iterable, Iterator, Dict, Any, Union

from text2sql_antipattern.core.contracts import Normalizer
from text2sql_antipattern.pipeline.registry import register_normalizer

from ..core.models import DataItem, SchemaDef

@register_normalizer("alias_mapper")
class AliasMapper(Normalizer):
    def __init__(self, mapping: Dict[str, str]):
        self.mapping = mapping

    def normalize_stream(self, items: Iterable[Union[DataItem, Dict[str, Any]]]) -> Iterator[DataItem]:
        for obj in items:
            if isinstance(obj, DataItem):
                yield obj
                continue
            std: Dict[str, Any] = {}
            metadata: Dict[str, Any] = {}
            for k, v in obj.items():
                mapped = None
                for std_key, src_key in self.mapping.items():
                    if k == src_key:
                        mapped = std_key
                        break
                if mapped in {"question", "sql", "schema", "dbId", "id"}:
                    std[mapped] = v
                else:
                    metadata[k] = v
            yield DataItem(
                id=maybe_str(std.get("id")),
                dbId=maybe_str(std.get("dbId")),
                question=maybe_str(std.get("question", "")),
                sql=maybe_str(std.get("sql", "")),
                schema=maybe_str(std.get("schema", None)),
                metadata=metadata,
            )

def maybe_str(v):
    return None if v is None else str(v)
