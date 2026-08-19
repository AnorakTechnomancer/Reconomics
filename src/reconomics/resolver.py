import socket

from reconomics.models import Asset, AssetType


def resolve_domain(domain: str) -> list[Asset]:
    assets = []

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        return assets

    seen = set()

    for result in results:
        address = result[4][0]

        if address in seen:
            continue

        seen.add(address)

        assets.append(
            Asset(
                value=address,
                asset_type=AssetType.IP,
                discovered_by="dns",
                related_domains=[domain],
            )
        )

    return assets