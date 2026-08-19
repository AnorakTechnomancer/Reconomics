from reconomics.models import ScanResult
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