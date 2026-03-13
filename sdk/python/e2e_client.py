#!/usr/bin/env python3
"""CLI script for E2E testing of latch-relay.

Usage:
    python e2e_client.py --server URL --id PEER_ID --code CODE [--send MESSAGE]

Connects to the relay server, pairs using the code, optionally sends a message,
and prints received messages as JSON to stdout.
"""

import argparse
import asyncio
import base64
import json
import sys

from latch_relay.client import LatchClient


async def main():
    parser = argparse.ArgumentParser(description="latch-relay E2E test client")
    parser.add_argument("--server", required=True, help="WebSocket server URL")
    parser.add_argument("--id", required=True, help="Peer ID")
    parser.add_argument("--code", required=True, help="Pairing code")
    parser.add_argument("--send", help="Message to send after pairing")
    args = parser.parse_args()

    client = LatchClient(args.server, args.id)

    try:
        await client.connect()
        print(f"Connected to {args.server}", file=sys.stderr)

        channel = await client.pair(args.code)
        print(f"Paired: channel={channel.channel_id[:16]}... role={channel.role} peer={channel.peer_id}", file=sys.stderr)

        if args.send:
            await client.send(channel.channel_id, args.send.encode())
            print(f"Sent: {args.send}", file=sys.stderr)

            # In send mode, exit after receiving one message
            try:
                ch_id, peer_id, data = await client.receive(timeout=10)
                output = {
                    "from": peer_id,
                    "data": base64.b64encode(data).decode("ascii"),
                }
                print(json.dumps(output), flush=True)
            except asyncio.TimeoutError:
                print("No response (10s timeout)", file=sys.stderr)
            return

        # Listen-only mode: receive messages until timeout
        while True:
            try:
                ch_id, peer_id, data = await client.receive(timeout=10)
                output = {
                    "from": peer_id,
                    "data": base64.b64encode(data).decode("ascii"),
                }
                print(json.dumps(output), flush=True)
            except asyncio.TimeoutError:
                print("No more messages (10s timeout)", file=sys.stderr)
                break

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
