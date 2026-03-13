import { parseArgs } from 'node:util';
import { LatchClient } from './src/client.js';

const { values } = parseArgs({
    options: {
        server: { type: 'string' },
        id: { type: 'string' },
        code: { type: 'string' },
        send: { type: 'string' },
    },
});

if (!values.server || !values.id || !values.code) {
    console.error('Usage: npx tsx e2e-client.ts --server URL --id PEER_ID --code CODE [--send MESSAGE]');
    process.exit(1);
}

const client = new LatchClient(values.server, values.id);

const sendMode = !!values.send;
let receivedOne = false;
let inactivityTimer: ReturnType<typeof setTimeout>;

function resetTimer(): void {
    clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(async () => {
        console.error('Exiting after 10s inactivity');
        await client.close();
        process.exit(0);
    }, 10000);
}

client.onMessage = async (channelId, peerId, data) => {
    console.log(JSON.stringify({ from: peerId, data: data.toString('base64') }));
    if (sendMode && !receivedOne) {
        receivedOne = true;
        console.error('Received response, exiting');
        clearTimeout(inactivityTimer);
        await client.close();
        process.exit(0);
    }
    resetTimer();
};

async function main(): Promise<void> {
    await client.connect();
    console.error(`Connected to ${values.server}`);

    const channel = await client.pair(values.code!);
    console.error(`Paired on channel ${channel.channelId} as ${channel.role} with peer ${channel.peerId}`);

    if (values.send) {
        await client.send(channel.channelId, Buffer.from(values.send));
        console.error(`Sent message: ${values.send}`);
    }

    resetTimer();
}

main().catch((err) => {
    console.error('Error:', err.message);
    process.exit(1);
});
