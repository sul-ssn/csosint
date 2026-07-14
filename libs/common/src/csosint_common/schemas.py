"""Pydantic v2-схемы, общие для API сервисов."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from .netguard import is_public_ip, is_valid_domain


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

    @model_validator(mode="after")
    def _validate_target(self) -> ScanRequest:
        """Строгая валидация ввода (ТЗ §11.2): формат домена; для IP — блок
        приватных/служебных адресов на входе (SSRF-guard, §11.1)."""
        target = self.target.strip()
        if self.type == TargetType.ip:
            if not is_public_ip(target):
                raise ValueError(
                    "target: приватные/служебные IP заблокированы (ТЗ §11.1); нужен публичный IP"
                )
        elif self.type == TargetType.domain:
            if not is_valid_domain(target):
                raise ValueError("target: невалидный домен")
        return self


class ScanJobCreated(BaseModel):
    job_id: int
    status: str
