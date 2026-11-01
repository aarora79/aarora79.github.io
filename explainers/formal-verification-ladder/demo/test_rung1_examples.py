from guard import is_blocked


def test_blocks_loopback() -> None:
    assert is_blocked("127.0.0.1")


def test_blocks_private() -> None:
    assert is_blocked("10.0.0.5")
    assert is_blocked("192.168.1.20")


def test_allows_public() -> None:
    assert not is_blocked("8.8.8.8")
