from reconomics.config import get_api_key, load_api_keys


def test_load_api_keys(tmp_path):
    config_file = tmp_path / "api_keys.toml"

    config_file.write_text(
        """
[wpscan]
api_token = "test-token"

[shodan]
api_key = "test-shodan-key"
""",
        encoding="utf-8",
    )

    config = load_api_keys(config_file)

    assert config["wpscan"]["api_token"] == "test-token"
    assert config["shodan"]["api_key"] == "test-shodan-key"


def test_get_api_key(tmp_path):
    config_file = tmp_path / "api_keys.toml"

    config_file.write_text(
        """
[wpscan]
api_token = "test-token"
""",
        encoding="utf-8",
    )

    token = get_api_key(
        "wpscan",
        "api_token",
        config_file,
    )

    assert token == "test-token"


def test_missing_api_key_returns_none(tmp_path):
    config_file = tmp_path / "missing.toml"

    token = get_api_key(
        "wpscan",
        "api_token",
        config_file,
    )

    assert token is None