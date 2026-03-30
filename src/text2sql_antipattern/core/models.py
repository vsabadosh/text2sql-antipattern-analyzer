from __future__ import annotations

from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class SqlDialect(str, Enum):
    sqlite = "sqlite"
    postgresql = "postgresql"


class SchemaDef(BaseModel):
    tables: Dict[str, List[str]] = Field(default_factory=dict)
    fkeys: List[Dict[str, Any]] = Field(default_factory=list)


class DataItem(BaseModel):
    model_config = {"protected_namespaces": ()}

    id: Optional[str] = None
    dbId: Optional[str] = None
    question: Optional[str] = None
    sql: Optional[str] = None
    schema: "SchemaDef | str | None" = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    dialect: SqlDialect = SqlDialect.sqlite

class AnalysisResult(BaseModel):
    id: str
    dbId: str
    checks: Dict[str, Any]
    errors: List[Dict[str, Any]] = Field(default_factory=list)
