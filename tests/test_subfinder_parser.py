from reconomics.scanners.subfinder import SubfinderScanner


SAMPLE_OUTPUT = """
{"host":"www.example.com","source":"crtsh"}
{"host":"api.example.com","source":"hackertarget"}
{"host":"vpn.example.com","source":"urlscan"}
"""


def test_parse_subfinder_output():
    result = SubfinderScanner.parse_output(
        "example.com",
        SAMPLE_OUTPUT,
    )

    assert result.scanner == "subfinder"
    assert result.target == "example.com"

    assert len(result.domains) == 3

    assert result.domains[0].name == "www.example.com"
    assert result.domains[0].source == "crtsh"

    assert result.domains[1].name == "api.example.com"
    assert result.domains[2].name == "vpn.example.com"