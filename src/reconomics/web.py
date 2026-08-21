from urllib.parse import urlsplit, urlunsplit

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

def canonicalize_url(url: str) -> str:
    parsed = urlsplit(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    port = parsed.port

    if (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        port = None

    if port is not None:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parsed.path or "/"

    if path == "/":
        path = ""

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )