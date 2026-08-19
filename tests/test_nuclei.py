from reconomics.scanners.nuclei import NucleiScanner

SAMPLE_OUTPUT = "\n".join(
    [
        (
            '{"template-id":"example-cve",'
            '"info":{'
            '"name":"Example Vulnerability",'
            '"severity":"high",'
            '"description":"Example description",'
            '"tags":["cve","example"],'
            '"reference":["https://example.com/advisory"]'
            '},'
            '"matched-at":"https://example.com/test",'
            '"host":"https://example.com"}'
        ),
        (
            '{"template-id":"example-misconfig",'
            '"info":{'
            '"name":"Example Misconfiguration",'
            '"severity":"medium",'
            '"tags":["misconfig"]'
            '},'
            '"matched-at":"https://example.com/admin",'
            '"host":"https://example.com"}'
        ),
    ]
)


def test_nuclei_parser_extracts_findings():
    scanner = NucleiScanner()

    findings = scanner.parse_output(
        SAMPLE_OUTPUT,
    )

    assert len(findings) == 2

    first = findings[0]

    assert first.title == "Example Vulnerability"
    assert first.severity == "high"
    assert first.discovered_by == "nuclei"
    assert first.affected_asset == "https://example.com/test"
    assert first.template_id == "example-cve"
    assert first.description == "Example description"
    assert "cve" in first.tags
    assert "https://example.com/advisory" in first.references

    second = findings[1]

    assert second.title == "Example Misconfiguration"
    assert second.severity == "medium"
    assert second.template_id == "example-misconfig"