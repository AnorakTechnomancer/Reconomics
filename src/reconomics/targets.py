import ipaddress
from enum import Enum


class TargetType(str, Enum):
    IP = "ip"
    NETWORK = "network"
    DOMAIN = "domain"


def classify_target(target: str) -> TargetType:
    try:
        ipaddress.ip_address(target)
        return TargetType.IP
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False)
        return TargetType.NETWORK
    except ValueError:
        pass

    return TargetType.DOMAIN