from reconomics.models import Asset, AssetType
from reconomics.technology import has_technology


def test_detects_wordpress():
    asset = Asset(
        value="https://example.com",
        asset_type=AssetType.WEB_ENDPOINT,
        discovered_by="httpx",
        technologies=["WordPress", "PHP"],
    )

    assert has_technology(asset, "WordPress") is True


def test_technology_match_is_case_insensitive():
    asset = Asset(
        value="https://example.com",
        asset_type=AssetType.WEB_ENDPOINT,
        discovered_by="httpx",
        technologies=["wordpress"],
    )

    assert has_technology(asset, "WordPress") is True


def test_non_web_asset_does_not_match():
    asset = Asset(
        value="192.0.2.10",
        asset_type=AssetType.IP,
        discovered_by="nmap",
    )

    assert has_technology(asset, "WordPress") is False