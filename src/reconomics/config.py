import tomllib
from pathlib import Path

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "reconomics"
DEFAULT_API_KEYS_FILE = DEFAULT_CONFIG_DIR / "api_keys.toml"


def load_api_keys(
    path: Path = DEFAULT_API_KEYS_FILE,
) -> dict:
    if not path.exists():
        return {}

    with path.open("rb") as file:
        return tomllib.load(file)


def get_api_key(
    provider: str,
    key_name: str,
    path: Path = DEFAULT_API_KEYS_FILE,
) -> str | None:
    config = load_api_keys(path)

    provider_config = config.get(provider, {})

    value = provider_config.get(key_name)

    if value is None:
        return None

    value = str(value).strip()

    placeholders = {
        "YOUR_WPSCAN_TOKEN",
        "YOUR_API_KEY",
        "CHANGE_ME",
    }

    if not value or value in placeholders:
        return None

    return value