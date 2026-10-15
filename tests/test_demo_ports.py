"""Demo launchers reject occupied listeners without affecting their owner."""

import socket

import pytest

from scripts.run_demo import _require_free_ports


def test_existing_listener_is_preserved() -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with pytest.raises(RuntimeError, match="already in use"):
            _require_free_ports((port,))
        assert listener.fileno() >= 0
    _require_free_ports((port,))
