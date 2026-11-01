from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    rule,
)

from guard import is_blocked
from oracle import os_reaches_blocked

PUBLIC = "93.184.216.34"
LOOPBACK = "127.0.0.1"


class FakeDns:
    """Hands out queued answers, then repeats the last one."""

    def __init__(self) -> None:
        self.answers: list[str] = [PUBLIC]

    def resolve(self, name: str) -> str:
        if len(self.answers) > 1:
            return self.answers.pop(0)
        return self.answers[0]


def fetch(
    dns: FakeDns,
    name: str,
    connections: list[str],
) -> None:
    """Check the address, then connect. It looks the name up twice."""
    if is_blocked(dns.resolve(name)):
        return
    connections.append(dns.resolve(name))


class FetchMachine(RuleBasedStateMachine):
    fetch_function = staticmethod(fetch)

    def __init__(self) -> None:
        super().__init__()
        self.dns = FakeDns()
        self.connections: list[str] = []

    @rule(answer=st.sampled_from([PUBLIC, LOOPBACK]))
    def dns_changes(self, answer: str) -> None:
        self.dns.answers.append(answer)

    @rule()
    def fetch_page(self) -> None:
        self.fetch_function(self.dns, "example.test", self.connections)

    @invariant()
    def never_connected_to_a_blocked_address(self) -> None:
        bad = [ip for ip in self.connections if os_reaches_blocked(ip)]
        assert bad == [], f"connected to {bad}"


TestFetch = FetchMachine.TestCase
