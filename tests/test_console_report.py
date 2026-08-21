from reconomics.models import (
    AssetRelationship,
    RelationshipType,
    ScanSession,
    SecurityFinding,
)
from reconomics.reporting.console_report import render_console


def test_console_report_renders_security_findings(capsys):
    session = ScanSession(
        target="example.com",
        security_findings=[
            SecurityFinding(
                title="Example Vulnerability",
                severity="high",
                discovered_by=["nuclei"],
                affected_asset="https://example.com",
                template_id="example-template",
            )
        ],
    )

    render_console(session)

    output = capsys.readouterr().out

    assert "Security Findings" in output
    assert "Example" in output
    assert "HIGH" in output
    assert "example.com" in output
    assert "nuclei" in output

def test_console_report_renders_redirects(capsys):
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

    render_console(session)

    output = capsys.readouterr().out

    assert "Redirects" in output
    assert "example.com" in output
    assert "www.example.com" in output