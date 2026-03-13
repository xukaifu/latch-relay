"""LatchClient: WebSocket client for latch-relay."""

from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass

import websockets

from . import crypto


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Decode unpadded base64url string to bytes."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


@dataclass
class ChannelState:
    """State of an established encrypted channel."""
    channel_id: str
    enc_key: bytes
    role: str
    peer_id: str
    active: bool = True


class LatchClient:
    """Client for connecting to a latch-relay WebSocket server."""

    def __init__(self, server_url: str, peer_id: str):
        self.server_url = server_url
        self.peer_id = peer_id
        self._ws = None
        self._channels: dict[str, ChannelState] = {}
        self._message_queue: asyncio.Queue = asyncio.Queue()
        self._recv_task: asyncio.Task | None = None
        self._waiters: dict[str, list[asyncio.Future]] = {}

    async def connect(self):
        """Connect to relay server via WebSocket."""
        self._ws = await websockets.connect(self.server_url, proxy=None)
        self._recv_task = asyncio.create_task(self._recv_loop())

    async def _recv_loop(self):
        """Background loop to receive and dispatch messages."""
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                msg_type = msg.get("type", "")
                ch = msg.get("ch", "")

                key = f"{msg_type}:{ch}"
                if key in self._waiters and self._waiters[key]:
                    fut = self._waiters[key].pop(0)
                    if not fut.done():
                        fut.set_result(msg)
                    continue

                if msg_type == "peer_left":
                    ch_state = self._channels.get(ch)
                    if ch_state:
                        ch_state.active = False
                    continue

                if msg_type == "message":
                    await self._message_queue.put(msg)
                    continue

                if msg_type == "error":
                    for wkey, wlist in list(self._waiters.items()):
                        if wkey.endswith(f":{ch}") and wlist:
                            fut = wlist.pop(0)
                            if not fut.done():
                                fut.set_exception(
                                    RuntimeError(f"Relay error: {msg.get('code', '')} - {msg.get('message', '')}")
                                )
                            break
                    continue

        except websockets.ConnectionClosed:
            pass

    def _wait_for(self, msg_type: str, ch: str) -> asyncio.Future:
        """Register a waiter for a specific message type on a channel."""
        key = f"{msg_type}:{ch}"
        if key not in self._waiters:
            self._waiters[key] = []
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._waiters[key].append(fut)
        return fut

    async def _send(self, msg: dict):
        """Send a JSON message over WebSocket."""
        await self._ws.send(json.dumps(msg))

    async def _pair_with_params(self, pairing_id: str, w: int) -> ChannelState:
        """Attempt pairing with specific pairing parameters.

        Both peers call pair() with the same code. The server assigns roles
        (initiator = first to arrive, responder = second). Since neither peer
        knows their role at the time of sending pubShare, both use the same
        blinding point (M). The role only affects transcript ordering and
        K computation uses the role-appropriate unblinding.
        """
        # Generate keypair -- always blind with M since role is unknown
        state = crypto.spake2_keypair(w, "initiator")

        # Send pair message
        pair_matched_fut = self._wait_for("pair_matched", pairing_id)
        await self._send({
            "type": "pair",
            "ch": pairing_id,
            "id": self.peer_id,
            "pubShare": _b64url_encode(state.pub_share),
        })

        # Wait for pair_matched
        matched = await asyncio.wait_for(pair_matched_fut, timeout=30)
        role = matched["role"]
        peer_pub_share = _b64url_decode(matched["pubShare"])
        peer_id = matched["id"]

        # Update state with assigned role (preserving original scalar/pubShare)
        state = crypto.SPAKE2State(
            scalar=state.scalar,
            pub_share=state.pub_share,
            role=role,
            w=w,
        )

        # Complete SPAKE2 -- determine initiator/responder IDs for transcript
        if role == "initiator":
            Ke = crypto.spake2_finish(state, peer_pub_share, pairing_id, self.peer_id, peer_id)
        else:
            Ke = crypto.spake2_finish(state, peer_pub_share, pairing_id, peer_id, self.peer_id)

        # Derive channel keys
        channel_id, enc_key = crypto.derive_channel_keys(Ke, pairing_id)

        # Join channel and handle challenge/response loop.
        # The server may re-challenge when the second peer joins, so we must
        # be prepared to respond to multiple challenges until verify_peer arrives.
        await self._send({
            "type": "join",
            "ch": channel_id,
            "id": self.peer_id,
        })

        verify_msg = None
        deadline = asyncio.get_running_loop().time() + 30.0
        while verify_msg is None:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for verify_peer")

            # Wait for either a challenge or verify_peer
            challenge_fut = self._wait_for("challenge", channel_id)
            verify_fut = self._wait_for("verify_peer", channel_id)

            done, pending = await asyncio.wait(
                [asyncio.ensure_future(challenge_fut), asyncio.ensure_future(verify_fut)],
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel pending futures
            for fut in pending:
                fut.cancel()
                # Remove from waiters to avoid leaks
                for wkey, wlist in list(self._waiters.items()):
                    if fut in wlist:
                        wlist.remove(fut)

            if not done:
                raise asyncio.TimeoutError("Timed out waiting for challenge/verify_peer")

            result = done.pop().result()
            if result["type"] == "challenge":
                nonce = _b64url_decode(result["nonce"])
                mac = crypto.compute_mac(enc_key, channel_id, nonce, self.peer_id, role)
                await self._send({
                    "type": "response",
                    "ch": channel_id,
                    "mac": _b64url_encode(mac),
                })
            elif result["type"] == "verify_peer":
                verify_msg = result

        peer_nonce = _b64url_decode(verify_msg["peerNonce"])
        peer_mac = _b64url_decode(verify_msg["peerMac"])
        verified_peer_id = verify_msg["peerId"]
        expected_peer_role = "responder" if role == "initiator" else "initiator"
        peer_role = verify_msg.get("peerRole", expected_peer_role)

        if verified_peer_id == self.peer_id:
            await self._send({"type": "error", "code": "verify_rejected", "ch": channel_id})
            raise RuntimeError("verify_peer contains own ID (possible reflection attack)")

        # Verify peer's MAC
        if not crypto.verify_mac(enc_key, channel_id, peer_nonce, verified_peer_id, peer_role, peer_mac):
            await self._send({
                "type": "error",
                "code": "verify_rejected",
                "ch": channel_id,
            })
            raise RuntimeError("Peer MAC verification failed")

        channel_state = ChannelState(
            channel_id=channel_id,
            enc_key=enc_key,
            role=role,
            peer_id=verified_peer_id,
        )
        self._channels[channel_id] = channel_state
        return channel_state

    async def pair(self, code: str) -> ChannelState:
        """Pair with another client using a pairing code.

        Tries the current time window first, then falls back to the previous window.
        """
        (current_id, current_w), (prev_id, prev_w) = crypto.derive_pairing_both_windows(code)
        try:
            return await self._pair_with_params(current_id, current_w)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return await self._pair_with_params(prev_id, prev_w)

    async def rejoin(self, channel_id: str, enc_key: bytes, role: str) -> ChannelState:
        """Rejoin an existing channel after reconnection."""
        await self._send({
            "type": "join",
            "ch": channel_id,
            "id": self.peer_id,
        })

        verify_msg = None
        deadline = asyncio.get_running_loop().time() + 30.0
        while verify_msg is None:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Timed out waiting for verify_peer")

            challenge_fut = self._wait_for("challenge", channel_id)
            verify_fut = self._wait_for("verify_peer", channel_id)

            done, pending = await asyncio.wait(
                [asyncio.ensure_future(challenge_fut), asyncio.ensure_future(verify_fut)],
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )

            for fut in pending:
                fut.cancel()
                for wkey, wlist in list(self._waiters.items()):
                    if fut in wlist:
                        wlist.remove(fut)

            if not done:
                raise asyncio.TimeoutError("Timed out waiting for challenge/verify_peer")

            result = done.pop().result()
            if result["type"] == "challenge":
                nonce = _b64url_decode(result["nonce"])
                mac = crypto.compute_mac(enc_key, channel_id, nonce, self.peer_id, role)
                await self._send({
                    "type": "response",
                    "ch": channel_id,
                    "mac": _b64url_encode(mac),
                })
            elif result["type"] == "verify_peer":
                verify_msg = result

        peer_nonce = _b64url_decode(verify_msg["peerNonce"])
        peer_mac = _b64url_decode(verify_msg["peerMac"])
        verified_peer_id = verify_msg["peerId"]
        expected_peer_role = "responder" if role == "initiator" else "initiator"
        peer_role = verify_msg.get("peerRole", expected_peer_role)

        if verified_peer_id == self.peer_id:
            await self._send({"type": "error", "code": "verify_rejected", "ch": channel_id})
            raise RuntimeError("verify_peer contains own ID (possible reflection attack)")

        if not crypto.verify_mac(enc_key, channel_id, peer_nonce, verified_peer_id, peer_role, peer_mac):
            await self._send({"type": "error", "code": "verify_rejected", "ch": channel_id})
            raise RuntimeError("Peer MAC verification failed")

        channel_state = ChannelState(
            channel_id=channel_id,
            enc_key=enc_key,
            role=role,
            peer_id=verified_peer_id,
        )
        self._channels[channel_id] = channel_state
        return channel_state

    async def send(self, channel_id: str, data: bytes):
        """Send an encrypted message on the channel."""
        ch_state = self._channels.get(channel_id)
        if not ch_state:
            raise RuntimeError(f"Channel {channel_id} not found")
        ct = crypto.encrypt(ch_state.enc_key, data, channel_id)
        await self._send({
            "type": "message",
            "ch": channel_id,
            "data": _b64url_encode(ct),
        })

    async def receive(self, timeout: float = 30.0) -> tuple[str, str, bytes]:
        """Receive a decrypted message. Returns (channel_id, peer_id, plaintext)."""
        msg = await asyncio.wait_for(self._message_queue.get(), timeout=timeout)
        ch_id = msg["ch"]
        peer_id = msg.get("peerId", "")
        ct = _b64url_decode(msg["data"])
        ch_state = self._channels.get(ch_id)
        if not ch_state:
            raise RuntimeError(f"No channel state for {ch_id}")
        plaintext = crypto.decrypt(ch_state.enc_key, ct, ch_id)
        return ch_id, peer_id, plaintext

    async def close(self):
        """Close connection."""
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            await self._ws.close()
