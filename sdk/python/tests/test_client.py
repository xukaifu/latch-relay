"""Integration tests for LatchClient against a real latch-relay server."""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time

import pytest
import pytest_asyncio

from latch_relay.client import LatchClient

# Path to the Go relay server binary
RELAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "server"))


def _find_free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def relay_server():
    """Start a latch-relay server for the test session."""
    port = _find_free_port()
    env = os.environ.copy()
    env["PORT"] = str(port)

    proc = subprocess.Popen(
        ["go", "run", "."],
        cwd=RELAY_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to be ready
    import urllib.request
    url = f"http://localhost:{port}/healthz"
    for _ in range(50):
        try:
            urllib.request.urlopen(url, timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    else:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise RuntimeError(f"Server failed to start.\nstdout: {stdout.decode()}\nstderr: {stderr.decode()}")

    yield f"ws://localhost:{port}/v1/connect"

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.mark.asyncio
async def test_pair_and_exchange(relay_server):
    """Two clients pair with the same code and exchange encrypted messages."""
    code = f"TEST-{int(time.time())}"

    alice = LatchClient(relay_server, "alice")
    bob = LatchClient(relay_server, "bob")

    await alice.connect()
    await bob.connect()

    try:
        # Both pair concurrently
        alice_task = asyncio.create_task(alice.pair(code))
        # Small delay so alice is first (initiator)
        await asyncio.sleep(0.3)
        bob_task = asyncio.create_task(bob.pair(code))

        alice_ch, bob_ch = await asyncio.gather(alice_task, bob_task)

        assert alice_ch.channel_id == bob_ch.channel_id
        assert alice_ch.role == "initiator"
        assert bob_ch.role == "responder"
        assert alice_ch.peer_id == "bob"
        assert bob_ch.peer_id == "alice"

        # Exchange messages
        await alice.send(alice_ch.channel_id, b"Hello from Alice!")
        ch_id, peer_id, data = await bob.receive(timeout=5)
        assert data == b"Hello from Alice!"
        assert ch_id == bob_ch.channel_id

        await bob.send(bob_ch.channel_id, b"Hello from Bob!")
        ch_id, peer_id, data = await alice.receive(timeout=5)
        assert data == b"Hello from Bob!"

    finally:
        await alice.close()
        await bob.close()


@pytest.mark.asyncio
async def test_multiple_messages(relay_server):
    """Multiple messages can be sent on the same channel."""
    code = f"MULTI-{int(time.time())}"

    alice = LatchClient(relay_server, "alice-m")
    bob = LatchClient(relay_server, "bob-m")

    await alice.connect()
    await bob.connect()

    try:
        alice_task = asyncio.create_task(alice.pair(code))
        await asyncio.sleep(0.3)
        bob_task = asyncio.create_task(bob.pair(code))
        alice_ch, bob_ch = await asyncio.gather(alice_task, bob_task)

        for i in range(5):
            msg = f"message-{i}".encode()
            await alice.send(alice_ch.channel_id, msg)
            _, _, data = await bob.receive(timeout=5)
            assert data == msg

    finally:
        await alice.close()
        await bob.close()
