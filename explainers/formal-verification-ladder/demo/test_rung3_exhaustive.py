from guard import is_blocked
from oracle import os_reaches_blocked


def test_every_first_two_octets() -> None:
    """Only the first two numbers decide the answer: try all 65,536."""
    wrong = []
    for a in range(256):
        for b in range(256):
            host = f"{a}.{b}.0.1"
            if is_blocked(host) != os_reaches_blocked(host):
                wrong.append(host)
    assert wrong == [], "wrong:\n" + "\n".join(wrong)


def test_every_spelling_of_the_first_octet() -> None:
    """Each number 0-255 in decimal, octal and hex: 768 hosts."""
    wrong = []
    for a in range(256):
        for first in (str(a), "0" + format(a, "o"), hex(a)):
            host = f"{first}.0.0.1"
            if is_blocked(host) != os_reaches_blocked(host):
                wrong.append(host)
    assert wrong == [], "wrong:\n" + "\n".join(wrong)
