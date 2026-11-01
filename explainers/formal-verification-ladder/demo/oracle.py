"""What the operating system would actually connect to."""

import ipaddress
import socket

BLOCKED = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def os_reaches_blocked(
    host: str,
) -> bool:
    """True if the OS would read host as a blocked address."""
    try:
        packed = socket.inet_aton(host)  # the C library's own parser
    except OSError:
        return False  # the OS reads it as a hostname, not an address
    address = ipaddress.IPv4Address(packed)
    return any(address in network for network in BLOCKED)
