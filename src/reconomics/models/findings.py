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
    SERVICE = "service"
    WEB_ENDPOINT = "web_endpoint"

class RelationshipType(str, Enum):
    RESOLVES_TO = "resolves_to"
    EXPOSES = "exposes"
    SERVES = "serves"
    USES = "uses"
    HAS_FINDING = "has_finding"

class AssetRelationship(BaseModel):
    source: str
    target: str
    relationship_type: RelationshipType
    discovered_by: str

class Asset(BaseModel):
    value: str
    asset_type: AssetType
    discovered_by: str
    in_scope: bool = True
    related_domains: list[str] = Field(default_factory=list)

    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None

    url: str | None = None
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = Field(default_factory=list)

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

class VulnerabilityFinding(BaseModel):
    title: str
    severity: str | None = None
    fixed_in: str | None = None
    references: list[str] = Field(default_factory=list)

class WordPressFinding(BaseModel):
    url: str
    version: str | None = None
    plugins: list[str] = Field(default_factory=list)
    themes: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)

class SecurityFinding(BaseModel):
    title: str
    severity: str
    discovered_by: str
    affected_asset: str

    description: str | None = None
    matched_at: str | None = None
    template_id: str | None = None

    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

class ScanSession(BaseModel):
    target: str
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    completed_at: datetime | None = None
    assets: list[Asset] = Field(default_factory=list)
    relationships: list[AssetRelationship] = Field(default_factory=list)
    scanner_results: list[ScanResult] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    wordpress_findings: list[WordPressFinding] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
