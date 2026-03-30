from __future__ import annotations

from typing import Protocol, Iterator, Iterable, Dict, Any, Union, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from .metric import MetricEvent

from .models import DataItem

@runtime_checkable
class Loader(Protocol):
    """Protocol for data loaders."""
    def load(self) -> Iterator[Dict[str, Any]]:
        ...

@runtime_checkable
class Normalizer(Protocol):
    def normalize_stream(self, items: Iterable[Union[DataItem, Dict[str, Any]]]) -> Iterator[DataItem]:
        ...

@runtime_checkable
class MetricsSink(Protocol):
    """Protocol for metric sinks."""
    def write(self, event: MetricEvent) -> None:
        ...
    
    def flush(self) -> None:
        ...
    
    def close(self) -> None:
        ...

@runtime_checkable
class AnnotatingAnalyzer(Protocol):
    name: str

    def analyze(self, items: Iterable[DataItem], sink: MetricsSink, dataset_id: str) -> Iterator[DataItem]:
         ...
