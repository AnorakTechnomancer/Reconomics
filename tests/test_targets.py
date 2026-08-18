from ai_pentest.targets import TargetType, classify_target


def test_classifies_ipv4_address():
    assert classify_target("192.0.2.10") == TargetType.IP


def test_classifies_ipv6_address():
    assert classify_target("2001:db8::1") == TargetType.IP


def test_classifies_network():
    assert classify_target("192.0.2.0/24") == TargetType.NETWORK


def test_classifies_domain():
    assert classify_target("example.com") == TargetType.DOMAIN