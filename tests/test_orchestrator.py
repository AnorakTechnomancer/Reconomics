from reconomics.models import (
    Asset,
    AssetRelationship,
    AssetType,
    HostFinding,
    RelationshipType,
    ScanResult,
    ScanSession,
    SecurityFinding,
    ServiceFinding,
    VulnerabilityFinding,
    WordPressFinding,
)
from reconomics.orchestrator import ScanOrchestrator
from reconomics.scanners.base import Scanner
from reconomics.targets import TargetType


class FakeScanner(Scanner):
    supported_target_types = {
        TargetType.IP,
        TargetType.NETWORK,
        TargetType.DOMAIN,
    }

    def scan(self, target: str) -> ScanResult:
        return ScanResult(
            scanner="fake",
            target=target,
        )


def test_orchestrator_builds_scan_session():
    orchestrator = ScanOrchestrator()

    orchestrator.scanners = [
        FakeScanner(),
    ]

    session = orchestrator.run("192.0.2.10")

    assert session.target == "192.0.2.10"
    assert session.completed_at is not None
    assert len(session.scanner_results) == 1

    result = session.scanner_results[0]

    assert result.scanner == "fake"
    assert result.target == "192.0.2.10"

class FailingScanner(Scanner):
    supported_target_types = {
        TargetType.IP,
        TargetType.NETWORK,
        TargetType.DOMAIN,
    }

    def scan(self, target: str) -> ScanResult:
        raise RuntimeError("simulated scanner failure")
    
def test_orchestrator_records_scanner_error():
    orchestrator = ScanOrchestrator()

    orchestrator.scanners = [
        FailingScanner(),
        FakeScanner(),
    ]

    session = orchestrator.run("192.0.2.10")

    assert len(session.errors) == 1
    assert session.errors[0].stage == "initial_scan"
    assert session.errors[0].target == "192.0.2.10"
    assert "simulated scanner failure" in session.errors[0].message

    assert len(session.scanner_results) == 1
    assert session.scanner_results[0].scanner == "fake"

def test_nmap_results_create_asset_graph():
    orchestrator = ScanOrchestrator()
    session = ScanSession(target="192.0.2.10")

    result = ScanResult(
        scanner="nmap",
        target="192.0.2.10",
        hosts=[
            HostFinding(
                address="192.0.2.10",
                status="up",
                services=[
                    ServiceFinding(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                    ),
                    ServiceFinding(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                    ),
                ],
            )
        ],
    )

    orchestrator._add_nmap_assets(session, result)

    asset_values = {
        asset.value
        for asset in session.assets
    }

    assert "192.0.2.10" in asset_values
    assert "192.0.2.10:tcp:80" in asset_values
    assert "192.0.2.10:tcp:443" in asset_values

    https_asset = next(
        asset
        for asset in session.assets
        if asset.value == "192.0.2.10:tcp:443"
    )

    assert https_asset.port == 443
    assert https_asset.protocol == "tcp"
    assert https_asset.service == "https"

    exposes_relationships = [
        relationship
        for relationship in session.relationships
        if relationship.relationship_type == RelationshipType.EXPOSES
    ]

    assert len(exposes_relationships) == 2

def test_nmap_graph_does_not_create_duplicates():
    orchestrator = ScanOrchestrator()
    session = ScanSession(target="192.0.2.10")

    result = ScanResult(
        scanner="nmap",
        target="192.0.2.10",
        hosts=[
            HostFinding(
                address="192.0.2.10",
                status="up",
                services=[
                    ServiceFinding(
                        port=443,
                        protocol="tcp",
                        state="open",
                        service="https",
                    )
                ],
            )
        ],
    )

    orchestrator._add_nmap_assets(session, result)
    orchestrator._add_nmap_assets(session, result)

    assert len(session.assets) == 2
    assert len(session.relationships) == 1

def test_unique_web_endpoints_deduplicates_redirects():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com",
        assets=[
            Asset(
                value="https://example.com",
                asset_type=AssetType.WEB_ENDPOINT,
                discovered_by="httpx",
                url="https://example.com",
                final_url="https://www.example.com",
            ),
            Asset(
                value="https://www.example.com",
                asset_type=AssetType.WEB_ENDPOINT,
                discovered_by="httpx",
                url="https://www.example.com",
                final_url="https://www.example.com",
            ),
        ],
    )

    endpoints = orchestrator._unique_web_endpoints(
        session
    )

    assert len(endpoints) == 1

    target_url = (
        endpoints[0].final_url
        or endpoints[0].url
    )

    assert target_url == "https://www.example.com"

def test_unique_web_endpoints_canonicalizes_urls():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com",
        assets=[
            Asset(
                value="https://example.com/",
                asset_type=AssetType.WEB_ENDPOINT,
                discovered_by="httpx",
                url="https://example.com/",
            ),
            Asset(
                value="https://example.com:443",
                asset_type=AssetType.WEB_ENDPOINT,
                discovered_by="httpx",
                url="https://example.com:443",
            ),
            Asset(
                value="https://EXAMPLE.COM",
                asset_type=AssetType.WEB_ENDPOINT,
                discovered_by="httpx",
                url="https://EXAMPLE.COM",
            ),
        ],
    )

    endpoints = orchestrator._unique_web_endpoints(
        session
    )

    assert len(endpoints) == 1


def test_wpscan_vulnerability_becomes_security_finding():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com"
    )

    finding = WordPressFinding(
        url="https://example.com",
        vulnerabilities=[
            VulnerabilityFinding(
                title="Example WordPress Vulnerability",
                severity="high",
                references=[
                    "https://example.com/advisory",
                ],
            )
        ],
    )

    orchestrator._add_wordpress_finding(
        session,
        finding,
        "https://example.com",
    )

    assert len(session.wordpress_findings) == 1
    assert len(session.security_findings) == 1

    security_finding = session.security_findings[0]

    assert (
        security_finding.title
        == "Example WordPress Vulnerability"
    )
    assert security_finding.severity == "high"
    assert security_finding.discovered_by == ["wpscan"]
    assert (
        security_finding.affected_asset
        == "https://example.com"
    )

def test_redirect_relationship_is_recorded():
    session = ScanSession(
        target="example.com",
        relationships=[
            AssetRelationship(
                source="https://example.com",
                target="https://www.example.com",
                relationship_type=RelationshipType.REDIRECTS_TO,
                discovered_by="httpx",
            )
        ],
    )

    assert len(session.relationships) == 1

    relationship = session.relationships[0]

    assert relationship.source == "https://example.com"
    assert relationship.target == "https://www.example.com"
    assert (
        relationship.relationship_type
        == RelationshipType.REDIRECTS_TO
    )
    assert relationship.discovered_by == "httpx"

def test_security_findings_are_deduplicated():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com",
        security_findings=[
            SecurityFinding(
                title="Example Vulnerability",
                severity="high",
                discovered_by=["nuclei"],
                affected_asset="https://example.com/",
                tags=["cve"],
                references=[
                    "https://example.com/one",
                ],
            ),
            SecurityFinding(
                title="example   vulnerability",
                severity="high",
                discovered_by=["wpscan"],
                affected_asset="https://example.com:443",
                tags=["wordpress"],
                references=[
                    "https://example.com/two",
                ],
            ),
        ],
    )

    orchestrator._deduplicate_security_findings(
        session
    )

    assert len(session.security_findings) == 1

    finding = session.security_findings[0]

    assert "cve" in finding.tags
    assert "wordpress" in finding.tags
    assert "https://example.com/one" in finding.references
    assert "https://example.com/two" in finding.references

    def test_duplicate_security_findings_merge_sources():
        orchestrator = ScanOrchestrator()

        session = ScanSession(
            target="example.com",
            security_findings=[
                SecurityFinding(
                    title="Example Vulnerability",
                    severity="high",
                    discovered_by=["nuclei"],
                    affected_asset="https://example.com",
                    tags=["cve"],
                    references=[
                        "https://example.com/nuclei",
                    ],
                ),
                SecurityFinding(
                    title="example   vulnerability",
                    severity="high",
                    discovered_by=["wpscan"],
                    affected_asset="https://example.com/",
                    tags=["wordpress"],
                    references=[
                        "https://example.com/wpscan",
                    ],
                ),
            ],
        )

        orchestrator._deduplicate_security_findings(
            session
        )

        assert len(session.security_findings) == 1

        finding = session.security_findings[0]

        assert finding.discovered_by == [
            "nuclei",
            "wpscan",
        ]

        assert set(finding.tags) == {
            "cve",
            "wordpress",
        }

        assert set(finding.references) == {
            "https://example.com/nuclei",
            "https://example.com/wpscan",
        }

def test_security_finding_creates_graph_relationship():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com",
        security_findings=[
            SecurityFinding(
                title="Example Vulnerability",
                severity="high",
                discovered_by=[
                    "nuclei",
                    "wpscan",
                ],
                affected_asset="https://example.com/",
            )
        ],
    )

    orchestrator._add_finding_relationships(
        session
    )

    assert len(session.relationships) == 1

    relationship = session.relationships[0]

    assert relationship.source == "https://example.com"
    assert relationship.target == "Example Vulnerability"
    assert (
        relationship.relationship_type
        == RelationshipType.HAS_FINDING
    )
    assert relationship.discovered_by == "nuclei, wpscan"

def test_finding_relationships_do_not_duplicate():
    orchestrator = ScanOrchestrator()

    session = ScanSession(
        target="example.com",
        security_findings=[
            SecurityFinding(
                title="Example Vulnerability",
                severity="high",
                discovered_by=["nuclei"],
                affected_asset="https://example.com",
            )
        ],
    )

    orchestrator._add_finding_relationships(
        session
    )

    orchestrator._add_finding_relationships(
        session
    )

    assert len(session.relationships) == 1