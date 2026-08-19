from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ServiceFinding(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


class HostFinding(BaseModel):
    address: str
    hostname: str | None = None
    status: str | None = None
    services: list[ServiceFinding] = Field(default_factory=list)

class DomainFinding(BaseModel):
    name: str
    source: str | None = None

class AssetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"


class Asset(BaseModel):
    value: str
    asset_type: AssetType
    discovered_by: str
    in_scope: bool = True
    related_domains: list[str] = Field(default_factory=list)

class ScanResult(BaseModel):
    scanner: str
    target: str
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    hosts: list[HostFinding] = Field(default_factory=list)
    domains: list[DomainFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

class ScanError(BaseModel):
    stage: str
    target: str
    scanner: str | None = None
    message: str

class ScanSession(BaseModel):
    target: str
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at: datetime | None = None
    assets: list[Asset] = Field(default_factory=list)
    scanner_results: list[ScanResult] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)

