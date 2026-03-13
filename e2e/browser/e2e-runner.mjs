#!/usr/bin/env node
/**
 * Browser E2E client runner.
 *
 * Bundles the browser SDK with esbuild, starts a local HTTP server to serve
 * a test page, launches a Chromium browser via Playwright, runs the pairing
 * flow inside the browser, and outputs JSON to stdout (matching the CLI
 * interface expected by the Go E2E test harness).
 *
 * Usage: node e2e-runner.mjs --server URL --id ID --code CODE [--send MSG]
 */

import { chromium } from 'playwright';
import * as esbuild from 'esbuild';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- Parse CLI args ---

function parseArgs() {
    const args = process.argv.slice(2);
    const opts = {};
    for (let i = 0; i < args.length; i += 2) {
        const key = args[i].replace(/^--/, '');
        opts[key] = args[i + 1];
    }
    if (!opts.server || !opts.id || !opts.code) {
        process.stderr.write('Usage: node e2e-runner.mjs --server URL --id ID --code CODE [--send MSG]\n');
        process.exit(1);
    }
    return opts;
}

// --- Bundle the browser SDK ---

async function bundleSDK() {
    const sdkRoot = path.resolve(__dirname, '..', '..', 'sdk', 'browser');
    const result = await esbuild.build({
        entryPoints: [path.join(sdkRoot, 'src', 'index.ts')],
        bundle: true,
        format: 'iife',
        globalName: 'LatchRelay',
        write: false,
        target: 'es2020',
        platform: 'browser',
    });
    return result.outputFiles[0].text;
}

// --- HTML test page ---

function buildHTML(sdkBundle) {
    return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>E2E</title></head>
<body>
<script>${sdkBundle}</script>
<script>
window.runE2E = async function(serverUrl, id, code, sendMsg) {
    const client = new LatchRelay.LatchClient(serverUrl, id);
    const result = { done: false, output: null, error: null };

    let receivedResolve;
    const receivedPromise = new Promise(r => { receivedResolve = r; });

    client.onMessage = (channelId, peerId, data) => {
        const b64 = btoa(String.fromCharCode(...data));
        result.output = JSON.stringify({ from: peerId, data: b64 });
        receivedResolve();
    };

    await client.connect();
    const channel = await client.pair(code);

    // Send our message
    await client.send(channel.channelId, new TextEncoder().encode(sendMsg));

    // Wait for peer's message
    await receivedPromise;
    await client.close();

    result.done = true;
    return result;
};
</script>
</body></html>`;
}

// --- Local HTTP server ---

function startLocalServer(html) {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        });
        server.listen(0, '127.0.0.1', () => {
            const port = server.address().port;
            resolve({ server, port });
        });
    });
}

// --- Main ---

async function main() {
    const opts = parseArgs();

    process.stderr.write(`Bundling browser SDK...\n`);
    const sdkBundle = await bundleSDK();

    const html = buildHTML(sdkBundle);
    const { server, port } = await startLocalServer(html);
    const pageUrl = `http://127.0.0.1:${port}/`;

    process.stderr.write(`Local server at ${pageUrl}\n`);
    process.stderr.write(`Launching browser...\n`);

    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();

    // Forward browser console to stderr
    page.on('console', msg => {
        process.stderr.write(`[browser] ${msg.text()}\n`);
    });

    await page.goto(pageUrl);

    process.stderr.write(`Running E2E: server=${opts.server} id=${opts.id} code=${opts.code} send=${opts.send || '(receiver)'}\n`);

    try {
        const result = await page.evaluate(
            async ({ serverUrl, id, code, sendMsg }) => {
                return await window.runE2E(serverUrl, id, code, sendMsg || null);
            },
            { serverUrl: opts.server, id: opts.id, code: opts.code, sendMsg: opts.send },
        );

        if (result.output) {
            process.stdout.write(result.output + '\n');
        }

        if (result.error) {
            process.stderr.write(`Error: ${result.error}\n`);
            process.exitCode = 1;
        }
    } catch (e) {
        process.stderr.write(`Playwright error: ${e.message}\n`);
        process.exitCode = 1;
    }

    await browser.close();
    server.close();
}

main().catch(e => {
    process.stderr.write(`Fatal: ${e.message}\n`);
    process.exit(1);
});
