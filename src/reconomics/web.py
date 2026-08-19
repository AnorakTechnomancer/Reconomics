from reconomics.models import Asset, AssetType

WEB_SERVICES = {
    "http",
    "https",
    "http-proxy",
    "https-alt",
}


def is_web_service(asset: Asset) -> bool:
    if asset.asset_type != AssetType.SERVICE:
        return False

    if asset.service and asset.service.lower() in WEB_SERVICES:
        return True

    if asset.port in {80, 443, 8080, 8443}:
        return True

    return False