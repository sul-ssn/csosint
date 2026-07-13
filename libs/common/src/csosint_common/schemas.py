"""Pydantic v2-схемы, общие для API сервисов."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class TargetType(StrEnum):
    domain = "domain"
    ip = "ip"
    org = "org"


class HealthStatus(BaseModel):
    """Liveness: сервис жив и отвечает."""

    service: str
    status: Literal["ok"] = "ok"


class DependencyStatus(BaseModel):
    name: str
    ok: bool


class ReadinessStatus(BaseModel):
    """Readiness: сервис + его зависимости готовы принимать нагрузку."""

    service: str
    ready: bool
    dependencies: list[DependencyStatus] = Field(default_factory=list)


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    type: TargetType


class ScanJobCreated(BaseModel):
    job_id: int
    status: str
