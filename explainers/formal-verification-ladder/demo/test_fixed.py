from hypothesis import given

import guard_fixed
from oracle import os_reaches_blocked
from test_rung2_property import hosts
from test_rung4_state import FetchMachine


@given(host=hosts())
def test_never_lets_a_blocked_address_through(
    host: str,
) -> None:
    if os_reaches_blocked(host):
        assert guard_fixed.is_blocked(host)


def test_every_first_two_octets() -> None:
    for a in range(256):
        for b in range(256):
            host = f"{a}.{b}.0.1"
            expected = os_reaches_blocked(host)
            assert guard_fixed.is_blocked(host) == expected


class FixedFetchMachine(FetchMachine):
    fetch_function = staticmethod(guard_fixed.fetch)


TestFixedFetch = FixedFetchMachine.TestCase
