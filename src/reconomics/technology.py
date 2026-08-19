from reconomics.models import Asset, AssetType


def has_technology(asset: Asset, technology: str) -> bool:
    if asset.asset_type != AssetType.WEB_ENDPOINT:
        return False

    target = technology.lower()

    return any(
        detected.lower() == target
        for detected in asset.technologies
    )