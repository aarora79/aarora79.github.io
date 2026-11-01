from hypothesis import (
    given,
    strategies as st,
)

from guard import is_blocked
from oracle import os_reaches_blocked


def _spell(
    number: int,
    style: str,
) -> str:
    """Write a number the way inet_aton accepts it."""
    if style == "octal":
        return "0" + format(number, "o")
    if style == "hex":
        return "0x" + format(number, "x")
    return str(number)


# Mix the numbers the guard cares about in with random ones.
NUMBERS = st.one_of(
    st.sampled_from([0, 10, 127, 168, 172, 192, 255]),
    st.integers(min_value=0, max_value=255),
)


@st.composite
def hosts(draw: st.DrawFn) -> str:
    """Hosts with 1 to 4 parts, each in decimal, octal or hex."""
    count = draw(st.integers(min_value=1, max_value=4))
    parts = []
    for _ in range(count):
        number = draw(NUMBERS)
        style = draw(st.sampled_from(["decimal", "octal", "hex"]))
        parts.append(_spell(number, style))
    return ".".join(parts)


@given(host=hosts())
def test_guard_agrees_with_the_os(
    host: str,
) -> None:
    assert is_blocked(host) == os_reaches_blocked(host)
