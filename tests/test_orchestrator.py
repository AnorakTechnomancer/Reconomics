from ai_pentest.models import ScanResult
from ai_pentest.orchestrator import ScanOrchestrator


class FakeScanner:
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