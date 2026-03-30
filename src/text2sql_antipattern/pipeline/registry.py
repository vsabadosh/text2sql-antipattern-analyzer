from __future__ import annotations
from typing import Callable, Dict, Mapping, MutableMapping, Type, TypeVar

T = TypeVar("T")

_LOADER_CLASSES: Dict[str, Type]     = {}
_NORMALIZER_CLASSES: Dict[str, Type] = {}
_ANALYZER_CLASSES: Dict[str, Type]   = {}

_plugins_loaded = False

def _canon(name: str) -> str:
    return name.strip().lower().replace(" ", "_")

def _make_registrar(bucket: MutableMapping[str, Type]) -> Callable[[str | None], Callable[[Type[T]], Type[T]]]:
    def registrar(name: str | None = None) -> Callable[[Type[T]], Type[T]]:
        def deco(cls: Type[T]) -> Type[T]:
            key = _canon(name or getattr(cls, "name", cls.__name__))
            bucket[key] = cls
            return cls
        return deco
    return registrar

register_loader     = _make_registrar(_LOADER_CLASSES)
register_normalizer = _make_registrar(_NORMALIZER_CLASSES)
register_analyzer   = _make_registrar(_ANALYZER_CLASSES)


def available(kind: str) -> Mapping[str, Type]:
    _ensure_plugins_loaded()
    kind = _canon(kind)
    if kind == "loader":     return dict(_LOADER_CLASSES)
    if kind == "normalizer": return dict(_NORMALIZER_CLASSES)
    if kind == "analyzer":   return dict(_ANALYZER_CLASSES)
    raise ValueError("kind must be one of: loader, normalizer, analyzer")

def get_class(kind: str, name: str) -> Type:
    bucket = available(kind)
    key = _canon(name)
    try:
        return bucket[key]
    except KeyError:
        raise KeyError(f"Unknown {kind} '{name}'. Available: {', '.join(sorted(bucket)) or '—'}")

def _ensure_plugins_loaded() -> None:
    if not (_LOADER_CLASSES or _NORMALIZER_CLASSES or _ANALYZER_CLASSES):
        from text2sql_antipattern.pipeline import import_builtin_plugins
        import_builtin_plugins()
