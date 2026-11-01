"""The guard after the fixes the ladder pointed at."""

import ipaddress
import socket
from typing import Protocol

BLOCKED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


class Resolver(Protocol):
    def resolve(self, name: str) -> str: ...


def is_blocked(
    host: str,
) -> bool:
    """True if the guard should refuse to connect to this host."""
    try:
        address = ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        return False  # not an address; the DNS check handles names
    if host != str(address):
        return True  # an unusual spelling: refuse rather than guess
    return any(address in network for network in BLOCKED)


def fetch(
    dns: Resolver,
    name: str,
    connections: list[str],
) -> None:
    """Look the name up once, check that address, connect to it."""
    address = dns.resolve(name)
    if is_blocked(address):
        return
    connections.append(address)
