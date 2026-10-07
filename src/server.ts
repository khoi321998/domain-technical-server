import { timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';

import type { ProxyConfiguration } from 'apify';
import { Actor } from 'apify';

import { browserSlotStats, closeBrowser, getBrowser, setMaxBrowserContexts } from './browser.js';
import { analyzeDomain, normalizeUrl } from './domain.js';
import { log, runWithJobPrefix } from './logger.js';

/**
 * Domain analysis HTTP server: keeps one browser warm and analyzes one domain per request.
 *
 *   POST /scrape  { "url": "https://...", "transactionId"?: "..." }  -> analysis + timing (requires header x-api-key)
 *   GET  /                                  -> health / status (no auth, for health checks)
 *
 * Env vars: API_KEY (required), PORT (8080), MAX_CONCURRENCY (4), MAX_BROWSER_CONCURRENCY (8), MAX_QUEUE (100), MAX_FETCH_ATTEMPTS (5), HTTP_FIRST (true),
 * USE_APIFY_PROXY (false) + APIFY_PROXY_PASSWORD, APIFY_PROXY_GROUPS (comma-separated, default RESIDENTIAL).
 */

function intEnv(name: string, fallback: number, min = 1): number {
    const raw = process.env[name];
    if (raw === undefined || raw === '') return fallback;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min) throw new Error(`Env var ${name} must be an integer >= ${min}, got "${raw}".`);
    return value;
}

const API_KEY = process.env.API_KEY ?? '';
if (API_KEY.length < 16) throw new Error('Env var API_KEY is required and must be at least 16 characters.');

const PORT = intEnv('PORT', 8080);
const MAX_CONCURRENCY = intEnv('MAX_CONCURRENCY', 4);
// Chrome contexts open at once. Requests that fall back to Chrome wait for a slot beyond this (HTTP fetches don't).
const MAX_BROWSER_CONCURRENCY = intEnv('MAX_BROWSER_CONCURRENCY', 8);
setMaxBrowserContexts(MAX_BROWSER_CONCURRENCY);
const MAX_QUEUE = intEnv('MAX_QUEUE', 100);
const MAX_FETCH_ATTEMPTS = intEnv('MAX_FETCH_ATTEMPTS', 5);
// Try a plain HTTP request (no browser) first and open the page in Chrome only when that is blocked or incomplete.
const HTTP_FIRST = process.env.HTTP_FIRST !== 'false';
const USE_APIFY_PROXY = process.env.USE_APIFY_PROXY === 'true';
const APIFY_PROXY_GROUPS = (process.env.APIFY_PROXY_GROUPS ?? 'RESIDENTIAL').split(',').map((g) => g.trim()).filter(Boolean);
const MAX_BODY_BYTES = 64 * 1024;
const MEMORY_LOG_INTERVAL_MS = 10 * 60_000;

interface Job {
    url: string;
    /** Optional id from the caller, logged with every line of this job so backend and server logs can be matched. */
    transactionId?: string;
    enqueuedAt: number;
    startedAt?: number;
}

/** "url" or "url [transactionId: x]" - every log line of a job starts with this. */
function describeJob(job: Job): string {
    return job.transactionId ? `${job.url} [transactionId: ${job.transactionId}]` : job.url;
}

// --- Concurrency: MAX_CONCURRENCY jobs run, the rest wait in FIFO order; MAX_QUEUE caps running + waiting. ---

let activeCount = 0;
let inProgress = 0;
const waiting: (() => void)[] = [];

async function acquireSlot() {
    if (activeCount < MAX_CONCURRENCY) {
        activeCount++;
        return;
    }
    // The slot is handed over by releaseSlot, so activeCount stays the same.
    await new Promise<void>((resolve) => {
        waiting.push(resolve);
    });
}

function releaseSlot() {
    const next = waiting.shift();
    if (next) next();
    else activeCount--;
}

/** Current load, for logs: requests, slots and Chrome slots. */
function describeLoad(): string {
    const chrome = browserSlotStats();
    return `in progress: ${inProgress}, active: ${activeCount}/${MAX_CONCURRENCY}, chrome: ${chrome.open}/${chrome.max} (${chrome.waiting} waiting)`;
}

// --- Proxy: Apify is used only for its residential proxy (needs APIFY_PROXY_PASSWORD, no Actor.init). ---

async function createProxyConfiguration(): Promise<ProxyConfiguration | undefined> {
    if (!USE_APIFY_PROXY) return undefined;
    const config = await Actor.createProxyConfiguration({ useApifyProxy: true, groups: APIFY_PROXY_GROUPS });
    if (!config) throw new Error('Failed to create Apify proxy configuration. Is APIFY_PROXY_PASSWORD set?');
    return config;
}

const proxyConfiguration = await createProxyConfiguration();

// --- HTTP helpers ---

const API_KEY_BUFFER = Buffer.from(API_KEY);

function isAuthorized(req: IncomingMessage): boolean {
    const provided = req.headers['x-api-key'];
    if (typeof provided !== 'string') return false;
    const providedBuffer = Buffer.from(provided);
    // Constant-time comparison so the key can't be guessed from response timing.
    return providedBuffer.length === API_KEY_BUFFER.length && timingSafeEqual(providedBuffer, API_KEY_BUFFER);
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
}

const NO_TIMING = { queueMs: 0, processMs: 0, totalMs: 0 };

/** Every failed /scrape response has the same shape, so the backend can read url / error / statusCode / timing. */
function sendFailed(
    res: ServerResponse,
    httpStatus: number,
    body: { url?: string | null; error: string; statusCode?: number | null; timing?: typeof NO_TIMING },
) {
    const { url = null, error, statusCode = null, timing: t = NO_TIMING } = body;
    sendJson(res, httpStatus, { status: 'failed', url, error, statusCode, timing: t });
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
        size += (chunk as Buffer).length;
        if (size > MAX_BODY_BYTES) throw new Error('Request body too large.');
        chunks.push(chunk as Buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

function parseTargetUrl(body: unknown): string | null {
    const url = (body as { url?: unknown })?.url;
    return typeof url === 'string' && url.trim() ? normalizeUrl(url) : null;
}

const TRANSACTION_ID_PATTERN = /^[\w.:-]{1,100}$/;

/** Optional `transactionId`: undefined when absent, null when invalid. Restricted characters keep log lines intact. */
function parseTransactionId(body: unknown): string | undefined | null {
    const id = (body as { transactionId?: unknown })?.transactionId;
    if (id === undefined || id === null) return undefined;
    return typeof id === 'string' && TRANSACTION_ID_PATTERN.test(id) ? id : null;
}

const DNS_CHECK_TIMEOUT_MS = 5000;

/**
 * Through a proxy, a domain that doesn't exist looks like a proxy error, and the analysis would rotate IPs and retry
 * for minutes. Look the domain up first and fail at once when DNS says it doesn't exist. Any other outcome
 * (timeout, temporary DNS failure) lets the analysis go ahead.
 */
async function assertDomainExists(url: string) {
    // IPv6 literals come with brackets ("[::1]"), which lookup() doesn't accept.
    const hostname = new URL(url).hostname.replace(/^\[|\]$/g, '');
    const result = await Promise.race([
        lookup(hostname).then(
            () => 'found',
            (error: NodeJS.ErrnoException) => error.code,
        ),
        sleep(DNS_CHECK_TIMEOUT_MS, 'timeout', { ref: false }),
    ]);
    if (result === 'ENOTFOUND') throw new Error(`Domain not found: ${hostname} has no DNS record.`);
}

function secs(ms: number): string {
    return `${(ms / 1000).toFixed(1)}s`;
}

function timing(job: Job) {
    const now = Date.now();
    const startedAt = job.startedAt ?? now;
    return { queueMs: startedAt - job.enqueuedAt, processMs: now - startedAt, totalMs: now - job.enqueuedAt };
}

async function handleScrape(req: IncomingMessage, res: ServerResponse) {
    let body: unknown;
    try {
        body = await readJsonBody(req);
    } catch (error) {
        sendFailed(res, 400, { error: `Invalid JSON body: ${(error as Error).message}` });
        return;
    }

    const url = parseTargetUrl(body);
    if (!url) {
        sendFailed(res, 400, { error: 'Body must be JSON like {"url": "https://example.com"}.' });
        return;
    }

    const transactionId = parseTransactionId(body);
    if (transactionId === null) {
        sendFailed(res, 400, { url, error: 'transactionId must be a string of 1-100 letters, digits or . _ : -' });
        return;
    }

    const job: Job = { url, transactionId, enqueuedAt: Date.now() };

    if (inProgress >= MAX_QUEUE) {
        log.warning(`Rejected ${describeJob(job)}: server busy (${describeLoad()}, MAX_QUEUE=${MAX_QUEUE})`);
        sendFailed(res, 503, { url, error: `Server busy: ${inProgress} requests in progress (MAX_QUEUE=${MAX_QUEUE}).` });
        return;
    }

    inProgress++;
    log.info(`Received ${describeJob(job)} (${describeLoad()})`);

    let statusCode: number | null = null;
    let slotAcquired = false;
    try {
        await assertDomainExists(url);
        await acquireSlot();
        slotAcquired = true;
        job.startedAt = Date.now();

        const result = await runWithJobPrefix(describeJob(job), async () =>
            analyzeDomain(url, { proxyConfiguration, maxFetchAttempts: MAX_FETCH_ATTEMPTS, httpFirst: HTTP_FIRST }),
        );
        statusCode = result.statusCode;
        if (!result.pageFetched) throw new Error(result.fetchError ?? 'Failed to fetch the page.');

        const t = timing(job);
        log.info(
            `Scraped ${describeJob(job)} (HTTP ${statusCode ?? '?'}, via ${result.output.http.fetchMethod ?? '?'}, platform: ${result.output.content.platformDetection?.platform ?? 'unknown'}) in ${secs(t.totalMs)} (queue ${secs(t.queueMs)}, scrape ${secs(t.processMs)})`,
        );
        sendJson(res, 200, { status: 'success', url, ...result.output, statusCode, timing: t });
    } catch (error) {
        const t = timing(job);
        const message = (error as Error).message.replace(/\s*\n\s*/g, ' ').trim();
        log.warning(`Scrape failed for ${describeJob(job)} (HTTP ${statusCode ?? 'no response'}) after ${secs(t.totalMs)}: ${message}`);
        sendFailed(res, 502, { url, error: message, statusCode, timing: t });
    } finally {
        if (slotAcquired) releaseSlot();
        inProgress--;
    }
}

setInterval(() => {
    const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
    log.info(`Memory: Node RSS ${rssMb} MB, ${describeLoad()}`);
}, MEMORY_LOG_INTERVAL_MS).unref();

const server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;

    if (req.method === 'GET' && path === '/') {
        sendJson(res, 200, {
            status: 'ok',
            maxConcurrency: MAX_CONCURRENCY,
            active: activeCount,
            inProgress,
            chrome: browserSlotStats(),
        });
        return;
    }

    if (req.method === 'POST' && path === '/scrape') {
        if (!isAuthorized(req)) {
            sendFailed(res, 401, { error: 'Missing or invalid x-api-key header.' });
            return;
        }
        handleScrape(req, res).catch((error) => {
            log.exception(error as Error, 'Unhandled error while handling /scrape');
            if (!res.headersSent) sendFailed(res, 500, { error: 'Internal server error.' });
        });
        return;
    }

    sendJson(res, 404, { error: 'Not found. Use POST /scrape or GET /.' });
});

// Start Chrome now, so the first request doesn't pay the cold start.
await getBrowser();

server.listen(PORT, () => {
    log.info(`Domain analysis server listening on port ${PORT}`);
    // Never log secrets: API_KEY and APIFY_PROXY_PASSWORD are reported only as set / not set.
    log.info('Server config', {
        PORT,
        MAX_CONCURRENCY,
        MAX_BROWSER_CONCURRENCY,
        MAX_QUEUE,
        MAX_FETCH_ATTEMPTS,
        HTTP_FIRST,
        USE_APIFY_PROXY,
        APIFY_PROXY_GROUPS: USE_APIFY_PROXY ? APIFY_PROXY_GROUPS : [],
        APIFY_PROXY_PASSWORD: process.env.APIFY_PROXY_PASSWORD ? 'set' : 'not set',
        API_KEY: 'set',
    });
});

async function shutdown(signal: string) {
    log.info(`Received ${signal}, shutting down.`);
    server.close();
    await closeBrowser();
    process.exit(0);
}

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, () => {
        shutdown(signal).catch((error) => {
            log.exception(error as Error, 'Error during shutdown');
            process.exit(1);
        });
    });
}
