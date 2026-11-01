"""A small SSRF guard against private addresses."""


def parse_ipv4(
    host: str,
) -> list[int] | None:
    """Read a dotted address like "10.0.0.5", or return None."""
    parts = host.split(".")
    if len(parts) != 4:
        return None
    try:
        numbers = [int(part) for part in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in numbers):
        return None
    return numbers


def is_blocked(
    host: str,
) -> bool:
    """True if the guard should refuse to connect to this host."""
    numbers = parse_ipv4(host)
    if numbers is None:
        return False  # not an IP address, so treat it as a hostname
    a, b = numbers[0], numbers[1]
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 32:
        return True
    return a == 192 and b == 168
