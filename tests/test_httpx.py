from reconomics.scanners.httpx import get_system_resolvers


def test_get_system_resolvers(monkeypatch, tmp_path):
    resolv_conf = tmp_path / "resolv.conf"

    resolv_conf.write_text(
        """
# Generated for testing
search example.local
nameserver 10.50.1.10
nameserver 10.50.1.121
""",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "reconomics.scanners.httpx.Path",
        lambda _: resolv_conf,
    )

    resolvers = get_system_resolvers()

    assert resolvers == [
        "10.50.1.10",
        "10.50.1.121",
    ]