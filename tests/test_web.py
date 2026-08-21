from reconomics.models import Asset, AssetType
from reconomics.web import canonicalize_url, is_web_service


def test_http_service_is_web_service():
    asset = Asset(
        value="192.0.2.10:tcp:80",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=80,
        protocol="tcp",
        service="http",
    )

    assert is_web_service(asset) is True


def test_https_service_is_web_service():
    asset = Asset(
        value="192.0.2.10:tcp:443",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=443,
        protocol="tcp",
        service="https",
    )

    assert is_web_service(asset) is True


def test_ssh_service_is_not_web_service():
    asset = Asset(
        value="192.0.2.10:tcp:22",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=22,
        protocol="tcp",
        service="ssh",
    )

    assert is_web_service(asset) is False

def test_web_endpoint_asset_stores_metadata():
    asset = Asset(
        value="https://example.com",
        asset_type=AssetType.WEB_ENDPOINT,
        discovered_by="httpx",
        url="https://example.com",
        status_code=200,
        title="Example Domain",
        technologies=["nginx", "PHP"],
    )

    assert asset.url == "https://example.com"
    assert asset.status_code == 200
    assert asset.title == "Example Domain"
    assert "nginx" in asset.technologies

def test_service_to_url_for_http():
    from reconomics.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()

    asset = Asset(
        value="192.0.2.10:tcp:80",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=80,
        protocol="tcp",
        service="http",
    )

    assert orchestrator._service_to_url(asset) == "http://192.0.2.10"


def test_service_to_url_for_https():
    from reconomics.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()

    asset = Asset(
        value="192.0.2.10:tcp:443",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=443,
        protocol="tcp",
        service="https",
    )

    assert orchestrator._service_to_url(asset) == "https://192.0.2.10"


def test_service_to_url_for_alternate_http_port():
    from reconomics.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()

    asset = Asset(
        value="192.0.2.10:tcp:8080",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=8080,
        protocol="tcp",
        service="http",
    )

    assert (
        orchestrator._service_to_url(asset)
        == "http://192.0.2.10:8080"
    )


def test_service_to_url_rejects_non_web_service():
    from reconomics.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()

    asset = Asset(
        value="192.0.2.10:tcp:22",
        asset_type=AssetType.SERVICE,
        discovered_by="nmap",
        port=22,
        protocol="tcp",
        service="ssh",
    )

    assert orchestrator._service_to_url(asset) is None

def test_canonicalize_url_removes_trailing_root_slash():
    assert (
        canonicalize_url("https://example.com/")
        == "https://example.com"
    )


def test_canonicalize_url_removes_default_https_port():
    assert (
        canonicalize_url("https://example.com:443/")
        == "https://example.com"
    )


def test_canonicalize_url_removes_default_http_port():
    assert (
        canonicalize_url("http://example.com:80/")
        == "http://example.com"
    )


def test_canonicalize_url_preserves_non_default_port():
    assert (
        canonicalize_url("https://example.com:8443/")
        == "https://example.com:8443"
    )


def test_canonicalize_url_normalizes_case():
    assert (
        canonicalize_url("HTTPS://Example.COM/")
        == "https://example.com"
    )