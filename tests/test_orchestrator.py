from reconomics.models import (
    HostFinding,
    RelationshipType,
    ScanResult,
    ScanSession,
    ServiceFinding,
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