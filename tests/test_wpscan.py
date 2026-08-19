from reconomics.scanners.wpscan import WPScanScanner


def test_wpscan_parser_extracts_findings():
    scanner = WPScanScanner()

    data = {
        "version": {
            "number": "6.8.2",
            "vulnerabilities": [
                {
                    "title": "Example core vulnerability",
                }
            ],
        },
        "main_theme": {
            "slug": "twentytwentyfive",
        },
        "plugins": {
            "contact-form-7": {
                "vulnerabilities": [
                    {
                        "title": "Example plugin vulnerability",
                    }
                ]
            },
            "woocommerce": {
                "vulnerabilities": [],
            },
        },
    }

    finding = scanner.parse_output(
        data,
        "https://wordpress.example",
    )

    assert finding.url == "https://wordpress.example"
    assert finding.version == "6.8.2"
    assert "contact-form-7" in finding.plugins
    assert "woocommerce" in finding.plugins
    assert "twentytwentyfive" in finding.themes

    assert any(
        vuln.title == "Example core vulnerability"
        for vuln in finding.vulnerabilities
    )

    assert any(
        vuln.title == "Example plugin vulnerability"
        for vuln in finding.vulnerabilities
    )

def test_wpscan_scanner_accepts_api_token(monkeypatch):
    monkeypatch.setattr(
        "reconomics.scanners.wpscan.get_api_key",
        lambda provider, key_name: "test-token",
    )

    scanner = WPScanScanner()

    assert scanner.api_token == "test-token"