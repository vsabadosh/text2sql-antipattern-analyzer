from __future__ import annotations
from typing import Dict, Any, Optional, Literal
from datetime import datetime
from pydantic import BaseModel, Field
import time


class MetricEvent(BaseModel):
    """Universal metric event model for all analyzers."""
    spec_version: str = "1.0"
    ts: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    dataset_id: str
    item_id: Optional[str] = None
    db_id: Optional[str] = None

    event_type: str
    name: str

    status: Literal["ok", "failed", "errors", "warns", "skipped"]
    success: bool
    duration_ms: float
    err: Optional[str] = None

    features: Dict[str, Any] = Field(default_factory=dict)
    stats: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z"
        }


class MetricEventBuilder:
    """Builder helper to construct metric events without boilerplate."""

    def __init__(self, dataset_id: str, event_type: str, name: str):
        self.dataset_id = dataset_id
        self.event_type = event_type
        self.name = name
        self._start_time: Optional[float] = None

    def start(self) -> MetricEventBuilder:
        self._start_time = time.perf_counter()
        return self

    def build(
        self,
        item_id: Optional[str],
        db_id: Optional[str],
        success: bool,
        features: Dict[str, Any],
        stats: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        duration_ms = 0.0
        if self._start_time is not None:
            duration_ms = (time.perf_counter() - self._start_time) * 1000

        event = MetricEvent(
            ts=datetime.utcnow().isoformat() + "Z",
            dataset_id=self.dataset_id,
            item_id=item_id,
            db_id=db_id,
            event_type=self.event_type,
            name=self.name,
            status="ok" if success else "failed",
            success=success,
            duration_ms=round(duration_ms, 2),
            err=error,
            features=features,
            stats=stats or {},
            tags=tags or {}
        )
        return event.model_dump(exclude_none=False)

    def build_with_status(
        self,
        item_id: Optional[str],
        db_id: Optional[str],
        status: Literal["ok", "failed", "errors", "warns", "skipped"],
        features: Dict[str, Any],
        stats: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        duration_ms = 0.0
        if self._start_time is not None:
            duration_ms = (time.perf_counter() - self._start_time) * 1000

        event = MetricEvent(
            ts=datetime.utcnow().isoformat() + "Z",
            dataset_id=self.dataset_id,
            item_id=item_id,
            db_id=db_id,
            event_type=self.event_type,
            name=self.name,
            status=status,
            success=(status == "ok"),
            duration_ms=round(duration_ms, 2),
            err=error,
            features=features,
            stats=stats or {},
            tags=tags or {}
        )
        return event.model_dump(exclude_none=False)
