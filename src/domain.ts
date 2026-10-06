// Fetches and returns domain-related technical data as structured JSON (one domain per call)
import dns from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';

import type { ProxyConfiguration } from 'apify';
import axios from 'axios';
import * as cheerio from 'cheerio';
import { Impit } from 'impit';
import type { HTTPResponse } from 'puppeteer';

import { getBrowser } from './browser.js';
import { jobLog } from './logger.js';

type HeadersMap = Record<string, any>;

interface FetchResult {
    success: boolean;
    html: string | null;
    headers: HeadersMap | null;
    httpStatus?: number | null;
    status: string | number;
    error?: string;
    /** How the page was fetched: plain HTTP (impit), headless Chrome, or the Axios fallback. */
    method?: 'http' | 'browser' | 'axios';
}

interface AxiosFetchResult {
    success: boolean;
    content: any;
    status?: number;
    headers?: HeadersMap;
    error?: string;
}

interface DnsSection {
    hostIp?: LookupAddress;
    nsRecords?: string[];
    cnameRecords?: string[];
    [key: string]: unknown;
}

interface PlatformDetectionResult {
    platform: string | null;
    confidence: number;
    matched: string[];
}

const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
};

const [dnsLookup, dnsResolve, dnsReverse] = [dns.lookup, dns.resolveAny, dns.reverse];

// Kör en DNS-fråga mot `host` först; om den ger ENODATA/ENOTFOUND (vanligt för
// www-subdomäner som saknar egen zon) görs ett nytt försök mot `baseDomain`.
// Returnerar { records, usedBase }. Kastar felet om även baseDomain misslyckas.
async function resolveWithBaseFallback<T>(
    fn: (hostname: string) => Promise<T>,
    host: string,
    baseDomain: string,
): Promise<{ records: T; usedBase: boolean }> {
    try {
        return { records: await fn(host), usedBase: false };
    } catch (err) {
        if (host !== baseDomain && ['ENODATA', 'ENOTFOUND'].includes(err.code)) {
            return { records: await fn(baseDomain), usedBase: true };
        }
        throw err;
    }
}

// Vendor-string-match för CNAME/NS
const vendorDefinitions: { match: string; vendor: string }[] = [
    { match: 'shopify', vendor: 'Shopify' },
    { match: 'cloudflare', vendor: 'Cloudflare' },
    { match: 'netlify', vendor: 'Netlify' },
    { match: 'herokudns', vendor: 'Heroku' },
    { match: 'github.io', vendor: 'GitHub Pages' },
    { match: 'wixdns', vendor: 'Wix' },
    { match: 'wixsite', vendor: 'Wix' },
    { match: 'squarespace', vendor: 'Squarespace' },
    { match: 'wpengine', vendor: 'WPEngine' },
    { match: 'onmicrosoft.com', vendor: 'Microsoft Azure' },
    { match: 'amazonaws.com', vendor: 'AWS' },
    { match: 'azurewebsites.net', vendor: 'Azure Websites' },
    { match: 'fastly.net', vendor: 'Fastly CDN' },
    { match: 'akamaiedge.net', vendor: 'Akamai CDN' },
    { match: 'edgesuite.net', vendor: 'Akamai CDN' },
    { match: 'akamai.net', vendor: 'Akamai CDN' },
    { match: 'stackpathdns.com', vendor: 'StackPath CDN' },
    { match: 'bigcommerce.com', vendor: 'BigCommerce' },
    { match: 'mybigcommerce.com', vendor: 'BigCommerce' },
    { match: 'lightspeedcdn.com', vendor: 'Lightspeed' },
    { match: 'pantheonsite.io', vendor: 'Pantheon' },
    { match: 'firebaseapp.com', vendor: 'Firebase Hosting' },
    { match: 'render.com', vendor: 'Render' },
    { match: 'digitaloceanspaces.com', vendor: 'DigitalOcean Spaces' },
    { match: 'srvcs.tumblr.com', vendor: 'Tumblr' },
    { match: 'webflow.io', vendor: 'Webflow' },
    { match: 'surge.sh', vendor: 'Surge' },
    { match: 'vercel-dns.com', vendor: 'Vercel' },
    { match: 'vercel.app', vendor: 'Vercel' },
    { match: 'cdn', vendor: 'Possible CDN' },
    // Lägg till fler här!
];

// IP-prefix-listan, utökad
// Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips-v4). They replace the old prefix list
// ('104.', '108.', '172.', ...), which tagged any IP in those /8 blocks as Cloudflare - e.g. AWS CloudFront
// 108.157.x.x came out as "Cloudflare".
const CLOUDFLARE_IPV4_CIDRS = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];

function ipv4ToInt(ip: string): number | null {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function ipInCidr(ip: string, cidr: string): boolean {
    const [range, bitsText] = cidr.split('/');
    const ipInt = ipv4ToInt(ip);
    const rangeInt = ipv4ToInt(range);
    if (ipInt === null || rangeInt === null) return false;
    const bits = Number(bitsText);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return ((ipInt & mask) >>> 0) === ((rangeInt & mask) >>> 0);
}

// Shodan CPE fragment -> vendor name (same names as the lists above). When Shodan identifies the
// provider of the IP, it wins over the IP-prefix guesses, whose AWS / Azure / Google lists overlap.
const SHODAN_CPE_VENDORS: { match: string; vendor: string }[] = [
    { match: 'cloudflare', vendor: 'Cloudflare' },
    { match: 'amazon', vendor: 'AWS' },
    { match: 'fastly', vendor: 'Fastly' },
    { match: 'akamai', vendor: 'Akamai' },
    { match: 'vercel', vendor: 'Vercel' },
    { match: 'netlify', vendor: 'Netlify' },
];

interface ShodanInfo {
    ports: number[];
    cpes: string[];
    tags: string[];
    hostnames: string[];
}

const SHODAN_TIMEOUT_MS = 5000;

// Open ports and provider info from Shodan InternetDB (free, no key): data from Shodan's last scan of
// the IP, not a live check. Nothing is sent to the analyzed site. null = Shodan has no data on the IP.
async function fetchShodan(ip: string): Promise<ShodanInfo | null> {
    const response = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
        signal: AbortSignal.timeout(SHODAN_TIMEOUT_MS),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Shodan InternetDB returned HTTP ${response.status}`);
    const data = (await response.json()) as Partial<ShodanInfo>;
    return {
        ports: [...(data.ports ?? [])].sort((a, b) => a - b),
        cpes: data.cpes ?? [],
        tags: data.tags ?? [],
        hostnames: data.hostnames ?? [],
    };
}

const ipRanges: { vendor: string; prefixes: string[] }[] = [
    { vendor: 'Shopify', prefixes: ['23.227.38.', '23.227.39.'] },
    { vendor: 'AWS', prefixes: ['52.', '54.', '18.', '3.', '13.', '35.', '15.'] },
    { vendor: 'Google Cloud', prefixes: ['34.', '35.', '104.196.', '107.178.', '130.211.'] },
    { vendor: 'Azure', prefixes: ['13.', '20.', '23.', '40.', '52.', '104.', '137.', '138.', '157.', '168.', '191.', '207.', '208.'] },
    { vendor: 'Fastly', prefixes: ['151.101.', '199.232.'] },
    { vendor: 'Akamai', prefixes: ['23.32.', '23.36.', '23.38.', '23.41.', '23.45.', '23.53.', '23.60.', '23.61.', '23.62.', '23.64.', '23.66.', '23.67.', '23.68.', '23.70.', '23.72.', '23.73.', '23.74.', '23.75.', '23.77.', '23.78.', '23.79.', '23.80.', '23.82.', '23.83.', '23.84.', '23.85.', '23.86.', '23.87.', '23.89.', '23.90.', '23.91.'] },
    { vendor: 'Squarespace', prefixes: ['198.185.159.', '198.49.23.'] },
    { vendor: 'Wix', prefixes: ['185.230.63.', '23.236.62.', '216.185.152.'] },
    { vendor: 'DigitalOcean', prefixes: ['104.236.', '138.197.', '159.203.', '174.138.', '192.241.', '198.199.', '45.55.', '46.101.'] },
    { vendor: 'GitHub Pages', prefixes: ['185.199.108.', '185.199.109.', '185.199.110.', '185.199.111.'] },
    { vendor: 'Vercel', prefixes: ['76.76.21.'] },
    { vendor: 'Netlify', prefixes: ['104.198.14.'] },
    { vendor: 'Heroku', prefixes: ['34.206.', '34.238.', '35.153.', '50.19.', '54.204.', '54.221.'] },
    { vendor: 'Pantheon', prefixes: ['23.185.0.'] },
    { vendor: 'BigCommerce', prefixes: ['63.141.128.'] },
    { vendor: 'Webflow', prefixes: ['75.2.70.', '99.83.190.'] },
    { vendor: 'Tumblr', prefixes: ['66.6.44.'] },
    { vendor: 'Render', prefixes: ['216.24.57.'] },
    { vendor: 'Surge', prefixes: ['138.68.0.'] },
    { vendor: 'StackPath CDN', prefixes: ['151.139.128.', '151.139.192.'] }
    // Fyll på vid behov!
];


// Resource types never needed for our data: the tags stay in the HTML (so favicon / platform patterns
// still match), only the files aren't downloaded. CSS also delays every sync script after it.
const BLOCKED_RESOURCE_TYPES = ['image', 'font', 'stylesheet', 'media'];

// Third-party trackers, ads and chat widgets. Their sync <script> tags can hold DOMContentLoaded for tens
// of seconds behind a residential proxy (e.g. cnzz.com / live800.com ~13-17s each). Their own tags stay in
// the HTML; only what they would inject is missing. Never add platform CDNs (Shopify, Wix, Squarespace,
// Webflow, HubSpot...) or anti-bot scripts (Cloudflare /cdn-cgi/, reCAPTCHA) here: detection and
// challenge pages depend on them. Matches the domain itself and all its subdomains.
const BLOCKED_THIRD_PARTY_DOMAINS = [
    // Analytics / tag managers
    'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
    'hotjar.com', 'hotjar.io', 'clarity.ms', 'mouseflow.com', 'crazyegg.com', 'luckyorange.com', 'fullstory.com',
    'segment.com', 'segment.io', 'mixpanel.com', 'amplitude.com', 'heap.io', 'heapanalytics.com',
    'newrelic.com', 'nr-data.net', 'scorecardresearch.com', 'quantserve.com', 'chartbeat.com',
    'cnzz.com', 'umeng.com', 'hm.baidu.com', 'mc.yandex.ru', 'mc.yandex.com',
    // Ads / pixels
    'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'adservice.google.com',
    'connect.facebook.net', 'analytics.tiktok.com', 'snap.licdn.com', 'px.ads.linkedin.com',
    'ads-twitter.com', 'bat.bing.com', 'criteo.com', 'criteo.net', 'adroll.com', 'taboola.com', 'outbrain.com',
    // Chat widgets
    'live800.com', '53kf.com', 'qiyukf.com', 'tawk.to', 'livechatinc.com', 'crisp.chat', 'intercom.io',
    'intercomcdn.com', 'zopim.com', 'zdassets.com', 'tidio.co', 'driftt.com', 'drift.com', 'olark.com',
    'smartsupp.com', 'jivosite.com', 'livezilla.net',
];

function isBlockedDomain(hostname: string): boolean {
    return BLOCKED_THIRD_PARTY_DOMAINS.some((d) => hostname === d || hostname.endsWith(`.${d}`));
}

async function fetchWithPuppeteer(url: string, proxyUrl: string | null = null): Promise<FetchResult> {

    const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    };

    // The browser is shared and kept warm; the proxy is set per browser context, so each attempt
    // (and each concurrent request) gets its own proxy session / exit IP.
    let proxyServer: string | undefined;
    let proxyAuth: { username: string; password: string } | null = null;
    if (proxyUrl) {
        try {
            const proxyParsed = new URL(proxyUrl);
            // For Puppeteer, proxy server should be host:port without protocol
            proxyServer = `${proxyParsed.hostname}:${proxyParsed.port}`;
            if (proxyParsed.username && proxyParsed.password) {
                proxyAuth = {
                    username: decodeURIComponent(proxyParsed.username),
                    password: decodeURIComponent(proxyParsed.password),
                };
            }
        } catch (error) {
            jobLog.warn('Failed to parse proxy URL:', error.message);
        }
    }

    const browser = await getBrowser();
    const context = await browser.createBrowserContext(proxyServer ? { proxyServer } : {});

    try {
        const page = await context.newPage();
        await page.setUserAgent(headers['User-Agent']);

        // Set proxy authentication if available
        if (proxyAuth) {
            try {
                await page.authenticate(proxyAuth);
            } catch (error) {
                jobLog.warn('Failed to set proxy authentication:', error.message);
            }
        }

        // Skip resources we don't need (see BLOCKED_RESOURCE_TYPES / BLOCKED_THIRD_PARTY_DOMAINS)
        await page.setRequestInterception(true);
        page.on('request', (req) => {
            // Never block the page itself, even when the analyzed site is on the blocklist (e.g. hotjar.com).
            if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
                void req.continue();
                return;
            }
            let hostname = '';
            try {
                hostname = new URL(req.url()).hostname;
            } catch { /* data: / blob: URLs */ }
            if (BLOCKED_RESOURCE_TYPES.includes(req.resourceType()) || isBlockedDomain(hostname)) void req.abort();
            else void req.continue();
        });

        // Set up response listener before navigation
        let mainResponse: HTTPResponse | null = null;
        page.on('response', response => {
            if (response.url().startsWith(url) && !mainResponse) {
                mainResponse = response;
            }
        });

        // Use longer timeouts for proxy connections
        const baseTimeout = proxyUrl ? 45000 : 15000;
        const retryTimeout = proxyUrl ? 60000 : 30000;

        // Final response of the navigation (after redirects). The listener above only sees the FIRST
        // response, which for a redirecting URL is the 301/302 itself, not the page we read.
        let finalResponse: HTTPResponse | null = null;

        try {
            // Attempt 1: Standard load with increased timeout for proxy
            finalResponse = await page.goto(url, {
                timeout: baseTimeout,
                waitUntil: 'domcontentloaded'
            });
            await new Promise(r => setTimeout(r, 1000)); // Give page time to settle
        } catch (error) {
            jobLog.warn(`⚠️ First attempt failed: ${error.message}`);

            try {
                // Attempt 2: Retry with longer timeout and network idle strategy
                finalResponse = await page.goto(url, {
                    timeout: retryTimeout,
                    waitUntil: 'networkidle2' // Wait for network to be mostly idle
                });
                await new Promise(r => setTimeout(r, 2000)); // Extra wait for proxy connections
            } catch (retryError) {
                jobLog.error(`❌ Retry failed: ${retryError.message}`);
                return {
                    success: false,
                    error: retryError.message,
                    html: null,
                    headers: null,
                    status: 'timeout'
                };
            }
        }

        let responseHeaders: HeadersMap = {};
        let httpStatus: number | null = null;
        // TS narrows `mainResponse` to null here since it is only assigned inside the listener callback.
        const capturedResponse = finalResponse ?? (mainResponse as HTTPResponse | null);
        if (capturedResponse) {
            responseHeaders = capturedResponse.headers();
            httpStatus = capturedResponse.status();
        }

        const html = await page.content();

        return {
            success: true,
            html,
            headers: responseHeaders, // <-- Nu är detta de *riktiga* HTTP headers!
            httpStatus,               // Numeric HTTP status code (e.g. 200, 503) for block detection
            status: 'ok'
        };
    } catch (error) {
        // e.g. the page crashed - let the caller fall back to Axios instead of aborting the whole analysis.
        jobLog.error(`❌ Puppeteer error: ${error.message}`);
        return { success: false, error: error.message, html: null, headers: null, status: 'error' };
    } finally {
        // Closes the page too. Only this attempt's context - the browser stays warm.
        await context.close().catch(() => {});
    }
}

// Simple Axios fallback for .txt/.json files
async function fetchWithAxios(url: string): Promise<AxiosFetchResult> {
    try {
        const response = await axios.get(url, { timeout: 5000 });
        return {
            success: true,
            content: response.data,
            status: response.status,
            headers: response.headers as HeadersMap
        };
    } catch (err) {
        return {
            success: false,
            error: err.message,
            content: null
        };
    }
}

// Unified fallback handler: Puppeteer → Axios
// A healthy page loads in ~3-5s over the residential proxy; past 10s it is almost always a bad exit IP.
const HTTP_TIMEOUT_MS = 10000;
// Network-level HTTP failures (bad exit IP) are retried over plain HTTP with a fresh IP, but only this
// many times: some sites drop non-browser TLS clients, which looks the same, and then need Chrome.
const HTTP_MAX_NETWORK_FAILURES = 2;

// impit errors carry a multi-line Rust debug dump ("Failed to connect to the server. Reason:
// hyper_util::...Error(Connect, Custom { kind: UnexpectedEof, error: "tls handshake eof" })").
// Keep one line for logs: "Failed to connect to the server. (UnexpectedEof: tls handshake eof)".
function condenseError(message: string): string {
    const firstLine = message.split('\n')[0].trim();
    const kind = message.match(/kind:\s*(\w+)/)?.[1];
    const detail = message.match(/(?:error|message):\s*"([^"]+)"/)?.[1];
    const reason = [kind, detail].filter(Boolean).join(': ');
    return reason ? `${firstLine} (${reason})` : message.replace(/\s*\n\s*/g, ' ').trim();
}

// Plain HTTP request (no browser, no JS) through the same proxy. impit impersonates Chrome's TLS/HTTP2
// fingerprint and headers, so bot protection sees a browser-like client. Title, favicon and the head
// snippet are in the server's HTML on almost every site, so this is enough for most pages in ~2-3s.
async function fetchWithHttp(url: string, proxyUrl: string | null = null): Promise<FetchResult> {
    try {
        const impit = new Impit({ browser: 'chrome', proxyUrl: proxyUrl ?? undefined, timeout: HTTP_TIMEOUT_MS });
        const response = await impit.fetch(url);
        const html = await response.text();
        const responseHeaders: HeadersMap = {};
        response.headers.forEach((value, key) => {
            responseHeaders[key.toLowerCase()] = value;
        });
        return { success: true, html, headers: responseHeaders, httpStatus: response.status, status: 'ok', method: 'http' };
    } catch (error) {
        return { success: false, error: condenseError(error.message), html: null, headers: null, status: 'error', method: 'http' };
    }
}

// Visible text of <body> without scripts/styles: a JS-rendered app shell has almost none.
const SPA_SHELL_MAX_TEXT_LENGTH = 200;

// Why the HTTP result can't be used and the page needs a real browser, or null when it is fine.
function needsBrowser(result: FetchResult): string | null {
    if (isBlockedOrFailed(result)) {
        return result.html ? `blocked (HTTP ${result.httpStatus})` : `failed (${result.error ?? `HTTP ${result.httpStatus}`})`;
    }
    if (String(result.headers?.['cf-mitigated'] ?? '').includes('challenge')) return 'Cloudflare challenge';
    const $ = cheerio.load(result.html!);
    if (!$('title').first().text().trim()) return 'no <title>';
    const body = $('body').clone();
    body.find('script, style, noscript, template').remove();
    const bodyText = body.text().replace(/\s+/g, ' ').trim();
    if (bodyText.length < SPA_SHELL_MAX_TEXT_LENGTH && $('body script').length > 0) return 'empty JS app shell';
    return null;
}

async function fetchWithFallback(url: string, proxyUrl: string | null = null): Promise<FetchResult> {
    const puppeteerResult = { ...(await fetchWithPuppeteer(url, proxyUrl)), method: 'browser' as const };

    if (puppeteerResult.success && puppeteerResult.html) {
        return puppeteerResult;
    }

    jobLog.warn(`⚠️ Puppeteer failed (${puppeteerResult.error}), falling back to Axios...`);
    const axiosResult = await fetchWithAxios(url);

    return {
        success: axiosResult.success,
        html: axiosResult.content,
        headers: axiosResult.headers || { error: axiosResult.error },
        httpStatus: typeof axiosResult.status === 'number' ? axiosResult.status : null,
        status: axiosResult.status || 'fallback',
        method: 'axios',
    };
}

// Unambiguous anti-bot "challenge" / block pages (LiteSpeed reCAPTCHA, Cloudflare, etc.).
// These strings essentially never appear on a normal page, so they count on their own.
const HARD_CHALLENGE_SIGNATURES = [
    /Bot Verification/i,
    /lsrecaptcha/i,                 // LiteSpeed's own challenge script
    /Checking your browser/i,
    /cf-browser-verification/i,
    /Just a moment/i,
    /Attention Required/i,
    /Please enable (?:JS|JavaScript) and cookies/i,
];

// Ambiguous signatures: they also show up on perfectly normal pages — reCAPTCHA v3 guarding
// a contact form, "Access denied" inside site copy. Only trusted on a challenge-sized page.
const SOFT_CHALLENGE_SIGNATURES = [
    /grecaptcha\.(?:execute|render)/i,
    /Access denied/i,
];

// Real challenge pages are tiny; a fully rendered site is not.
const CHALLENGE_MAX_HTML_LENGTH = 60000;

// Returns true when the response looks blocked/challenged or failed to load,
// i.e. rotating to a fresh IP and retrying is worth a shot.
function isBlockedOrFailed(result: FetchResult | null): boolean {
    if (!result) return true;
    if (!result.html) return true; // timeout / total failure — no usable HTML at all
    const codes = [result.httpStatus, result.status].filter((s): s is number => typeof s === 'number');
    if (codes.some(c => c === 403 || c === 429 || c === 503)) return true;
    if (HARD_CHALLENGE_SIGNATURES.some(re => re.test(result.html!))) return true;
    // A 500 KB render whose contact form loads reCAPTCHA is a successful fetch, not a challenge.
    if (result.html.length <= CHALLENGE_MAX_HTML_LENGTH) {
        return SOFT_CHALLENGE_SIGNATURES.some(re => re.test(result.html!));
    }
    return false;
}

// Fetch the page, rotating to a fresh proxy IP on each block/failure, up to `maxAttempts`.
// If every attempt is still blocked, the LAST result is returned as-is (no error) — i.e.
// behaviour identical to "no handling": we just take whatever value we got.
// Proxy for logs: the username carries group + session (= which exit IP); never the password.
function describeProxy(proxyUrl: string | null): string {
    if (!proxyUrl) return 'none (direct)';
    try {
        const { username, hostname, port } = new URL(proxyUrl);
        return username ? decodeURIComponent(username) : `${hostname}:${port}`;
    } catch {
        return 'unparseable proxy URL';
    }
}

async function fetchWithRotation(
    url: string,
    proxyConfiguration: ProxyConfiguration | undefined,
    maxAttempts = 5,
    httpFirst = true,
): Promise<FetchResult | null> {
    let lastResult: FetchResult | null = null;
    // Plain HTTP first. When the site answers but the page is blocked or incomplete, it needs a browser
    // (bot protection / JS-rendered), so this and every later attempt use Chrome. When there is no answer
    // at all (bad proxy exit IP), the next attempt retries plain HTTP with a fresh IP.
    let tryHttp = httpFirst;
    let httpNetworkFailures = 0;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        let proxyUrl: string | null = null;
        if (proxyConfiguration) {
            try {
                // Unique session id per attempt => a fresh residential IP each time. The random part keeps
                // concurrent requests that start in the same millisecond on different IPs.
                const sessionId = `s_${Date.now()}_${attempt}_${Math.random().toString(36).slice(2, 8)}`;
                proxyUrl = (await proxyConfiguration.newUrl(sessionId)) ?? null;
            } catch (err) {
                jobLog.warn(`Failed to get new proxy URL (attempt ${attempt}):`, err.message);
            }
        }

        jobLog.info(`STEP 9: fetch attempt ${attempt}/${maxAttempts}, proxy: ${describeProxy(proxyUrl)}`);

        if (tryHttp) {
            const httpResult = await fetchWithHttp(url, proxyUrl);

            if (!httpResult.html) {
                // No answer from the site: proxy/network problem, not a block.
                lastResult = httpResult;
                httpNetworkFailures++;
                // After HTTP_MAX_NETWORK_FAILURES, switch to Chrome - but on the next attempt, i.e. a fresh IP:
                // this IP just failed, so Chrome on it would most likely fail too (and take up to 45s + 60s).
                if (httpNetworkFailures >= HTTP_MAX_NETWORK_FAILURES) tryHttp = false;
                if (attempt < maxAttempts) {
                    const next = tryHttp ? 'retrying HTTP' : 'switching to Chrome';
                    jobLog.warn(`STEP 9: attempt ${attempt} HTTP got no response (${httpResult.error}), ${next} on a new IP...`);
                    continue;
                }
                // Last attempt: no fresh IP left, so try Chrome on this one rather than end without trying it.
                tryHttp = false;
                jobLog.warn(`STEP 9: attempt ${attempt} HTTP got no response (${httpResult.error}), last attempt - using Chrome`);
            } else {
                const reason = needsBrowser(httpResult);
                if (!reason) {
                    jobLog.info(`STEP 9: attempt ${attempt} succeeded via HTTP (HTTP ${httpResult.httpStatus})`);
                    return httpResult;
                }
                tryHttp = false;
                jobLog.info(`STEP 9: HTTP result not usable (${reason}), using Chrome`);
            }
        }

        const result = await fetchWithFallback(url, proxyUrl);
        lastResult = result;

        if (!isBlockedOrFailed(result)) {
            jobLog.info(`STEP 9: attempt ${attempt} succeeded (not blocked)`);
            return result;
        }

        jobLog.warn(`STEP 9: attempt ${attempt} blocked/failed (httpStatus=${result && result.httpStatus}), rotating IP...`);
    }

    jobLog.warn(`STEP 9: still blocked after ${maxAttempts} attempts — returning last result as-is`);
    return lastResult;
}


/**
 * Adds `https://` when the scheme is missing (`example.com` and `https://example.com` both work).
 * Returns null when the result is not a valid http(s) URL.
 */
export function normalizeUrl(url: string): string | null {
    const trimmed = url.trim();
    // Another scheme (ftp://, file://...) is rejected rather than turned into "https://ftp://...".
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(trimmed) && !/^https?:\/\//i.test(trimmed)) return null;
    const parsedUrl = `${/^https?:\/\//i.test(trimmed) ? '' : 'https://'}${trimmed}`;
    try {
        const { protocol, hostname } = new URL(parsedUrl);
        return (protocol === 'http:' || protocol === 'https:') && hostname ? parsedUrl : null;
    } catch {
        return null;
    }
}

export interface DomainAnalysis {
    output: {
        meta: Record<string, unknown>;
        dns: DnsSection;
        ssl: Record<string, any>;
        http: Record<string, any>;
        content: Record<string, any>;
        network: Record<string, any>;
    };
    /** HTTP status of the page (last fetch attempt); null when no response came back. */
    statusCode: number | null;
    /** False when no HTML could be fetched at all (all attempts + Axios fallback failed). */
    pageFetched: boolean;
    /** Why the page fetch failed, when `pageFetched` is false. */
    fetchError: string | null;
}

export interface AnalyzeOptions {
    proxyConfiguration?: ProxyConfiguration;
    /** Fetch attempts, each with a fresh proxy IP, while the page looks blocked or fails. */
    maxFetchAttempts: number;
    /** Try a plain HTTP request before launching a page in Chrome. */
    httpFirst: boolean;
}

export async function analyzeDomain(parsedUrl: string, { proxyConfiguration, maxFetchAttempts, httpFirst }: AnalyzeOptions): Promise<DomainAnalysis> {
    jobLog.info('STEP 2: URL input received', parsedUrl);

    const { host, origin } = new URL(parsedUrl);
    const baseDomain = host.replace(/^www\./, '');
    jobLog.info('STEP 3: URL parsed', { host, origin });

    const dnsSection: DnsSection = {};
    const sslSection: Record<string, any> = {};
    const httpSection: Record<string, any> = {};
    const contentSection: Record<string, any> = {};
    const networkSection: Record<string, any> = {};

    const metaSection = {
        origin,
        host,
        baseDomain,
        comment: 'Root object including the parsed host, base domain and origin URL',
    };

    // The three branches don't depend on each other, so they run in parallel: the page fetch (slowest)
    // starts right away instead of waiting for DNS/SSL, and the Shodan lookup no longer waits for the page.
    // Each step catches its own errors, so one failing branch never affects the others.

    // B: DNS (STEP 4-7) + SSL (STEP 8) + Shodan (STEP 15, open ports + provider), which needs the host IP.
    const networkStep = async () => {
        let shouldTryReverse = true;
        // Started as soon as the IP is known, so it runs alongside the remaining DNS queries and SSL.
        let shodanPromise: Promise<ShodanInfo | null> | null = null;
        try {


            dnsSection.hostIp = await dnsLookup(host);
            shodanPromise = fetchShodan(dnsSection.hostIp.address);
            shodanPromise.catch(() => {}); // awaited below; avoids an unhandled rejection meanwhile

            try {
                let resolved = await dnsResolve(host);
                // resolveAny på en www-subdomän ger oftast bara A-posten (den kastar
                // inte ENODATA, så base-fallbacken ovan hjälper inte här). Slå ihop med
                // zon-posterna (MX/NS/TXT/SOA...) från basdomänen för fullständig bild.
                if (host !== baseDomain) {
                    try {
                        const baseResolved = await dnsResolve(baseDomain);
                        const extra = baseResolved.filter(r => r.type !== 'A');
                        if (extra.length) resolved = [...resolved, ...extra];
                    } catch (_) { /* basdomänen saknar extra poster */ }
                }
                dnsSection.hostResolve = resolved;
                dnsSection.hostResolveComment = 'All DNS records (via resolveAny)';
                jobLog.info('STEP 4b: resolveAny (all DNS records) done');
            } catch (err) {
                if (err.code === 'ENODATA') {
                    // "No records" - some resolvers answer an ANY query with an empty list, others with
                    // ENODATA. Report both the same way, as the Apify version did: an empty list.
                    dnsSection.hostResolve = [];
                    dnsSection.hostResolveComment = 'All DNS records (via resolveAny)';
                    jobLog.info('STEP 4b: resolveAny returned no records');
                } else {
                    dnsSection.hostResolveError = err.message;
                    jobLog.info('STEP 4b: resolveAny failed', err.message);
                }
            }
            try {
                const { records } = await resolveWithBaseFallback(dns.resolveNs, host, baseDomain);
                dnsSection.nsRecords = records;
                dnsSection.nsComment = 'Authoritative name servers (NS)';
                jobLog.info('STEP 4c: NS records fetched');
            } catch (err) {
                dnsSection.nsError = err.message;
                jobLog.info('STEP 4c: NS fetch failed', err.message);
            }

            try {
                const { records } = await resolveWithBaseFallback(dns.resolveSoa, host, baseDomain);
                dnsSection.soaRecord = records;
                dnsSection.soaComment = 'Start of Authority (SOA) record';
                jobLog.info('STEP 4d: SOA record fetched');
            } catch (err) {
                dnsSection.soaError = err.message;
                jobLog.info('STEP 4d: SOA fetch failed', err.message);
            }

            try {
                const { records } = await resolveWithBaseFallback(dns.resolveTxt, host, baseDomain);
                dnsSection.txtRecords = records;
                dnsSection.txtComment = 'All TXT records (not just SPF/DKIM)';
                jobLog.info('STEP 4e: TXT records fetched');
            } catch (err) {
                dnsSection.txtError = err.message;
                jobLog.info('STEP 4e: TXT fetch failed', err.message);
            }
            try {
                dnsSection.cnameRecords = await dns.resolveCname(host);
                dnsSection.cnameComment = 'CNAME records for host';
                jobLog.info('STEP 4f: CNAME records fetched', dnsSection.cnameRecords);
            } catch (err) {
                dnsSection.cnameError = err.message;
                jobLog.info('STEP 4f: CNAME fetch failed', err.message);
            }

            // Samla vendors från CNAME, NS och IP
            const detectedVendors: string[] = [];

            // CNAME records
            if (dnsSection.cnameRecords && dnsSection.cnameRecords.length > 0) {
                for (const cname of dnsSection.cnameRecords) {
                    for (const def of vendorDefinitions) {
                        if (cname.toLowerCase().includes(def.match)) detectedVendors.push(def.vendor);
                    }
                }
            }

            // NS records
            if (dnsSection.nsRecords && dnsSection.nsRecords.length > 0) {
                for (const ns of dnsSection.nsRecords) {
                    for (const def of vendorDefinitions) {
                        if (ns.toLowerCase().includes(def.match)) detectedVendors.push(def.vendor);
                    }
                }
            }

            // IP address: Shodan's provider (CPE) when it knows the IP, otherwise Cloudflare's official
            // ranges + the prefix lists (alla leverantörer med ipRanges)
            if (dnsSection.hostIp && dnsSection.hostIp.address) {
                const ip = dnsSection.hostIp.address;
                const shodan = await shodanPromise!.catch(() => null);
                const shodanVendors = SHODAN_CPE_VENDORS
                    .filter((def) => shodan?.cpes.some((cpe) => cpe.toLowerCase().includes(def.match)))
                    .map((def) => def.vendor);
                if (shodanVendors.length > 0) {
                    detectedVendors.push(...shodanVendors);
                } else {
                    if (CLOUDFLARE_IPV4_CIDRS.some((cidr) => ipInCidr(ip, cidr))) detectedVendors.push('Cloudflare');
                    for (const entry of ipRanges) {
                        if (entry.prefixes.some(prefix => ip.startsWith(prefix))) {
                            detectedVendors.push(entry.vendor);
                        }
                    }
                }
            }

            // Ta bort dubbletter och spara resultatet
            const uniqueVendors = [...new Set(detectedVendors)];
            dnsSection.vendorsDetected = uniqueVendors.length > 0 ? uniqueVendors.join(', ') : 'Unknown/Not Matched';
            dnsSection.vendorsComment = 'Vendors detected via CNAME, NS and the host IP (Shodan provider, else IP ranges)';

            dnsSection.hostComment = 'DNS lookup and resolveAny results';
            jobLog.info('STEP 4: DNS lookup done');
        } catch (error) {
            dnsSection.error = error.message;
            shouldTryReverse = false;
            jobLog.info('STEP 4: DNS lookup failed', error.message);
        }

        if (shouldTryReverse) {
            try {
                dnsSection.hostReverse = await dnsReverse(dnsSection.hostIp!.address);
                dnsSection.hostReverseComment = 'Reverse DNS lookup of host IP';
                jobLog.info('STEP 5: Reverse DNS success');
            } catch (error) {
                dnsSection.hostReverseError = error.message;
                jobLog.info('STEP 5: Reverse DNS failed', error.message);
            }
        }

        // TXT DNS Records
        // DMARC/DKIM publiceras på organisationsdomänen → använd baseDomain direkt.
        // SPF (TXT på domänen) provas på host först, med fallback till baseDomain.
        let dmarc: string[] = [], spf: string[] = [], dkim: string[] = [];
        try {
            const records = await dns.resolveTxt(`_dmarc.${baseDomain}`);
            dmarc = records.flat().filter(t => t.includes('v=DMARC1'));
        } catch (_) {}
        try {
            const { records } = await resolveWithBaseFallback(dns.resolveTxt, host, baseDomain);
            spf = records.flat().filter(t => t.includes('v=spf1'));
        } catch (_) {}
        try {
            const records = await dns.resolveTxt(`default._domainkey.${baseDomain}`);
            dkim = records.flat();
        } catch (_) {}
        dnsSection.dnsAuth = { dmarc, spf, dkim, comment: 'Email authentication DNS records' };
        jobLog.info('STEP 6: DNS auth done');

        let mxTried = false;
        try {
            const records = await dns.resolveMx(host);
            if (records && records.length > 0) {
                dnsSection.mxRecords = records;
                dnsSection.mxComment = 'Mail server records for host';
                mxTried = true;
                jobLog.info('STEP 7: MX records found (host)');
            }
        } catch (err) {
            jobLog.info('STEP 7: MX for host failed:', err.message);
        }

        if (!mxTried) {
            try {
                const records = await dns.resolveMx(baseDomain);
                if (records && records.length > 0) {
                    dnsSection.mxRecords = records;
                    dnsSection.mxComment = 'Mail server records for base domain';
                    jobLog.info('STEP 7: MX records found (base domain)');
                }
            } catch (err) {
                dnsSection.mxError = err.message;
                jobLog.info('STEP 7: MX failed for base domain:', err.message);
            }
        }

        // SSL
        try {
            const certInfo = await new Promise<Record<string, any>>((resolve, reject) => {
                const socket = tls.connect(443, host, { servername: host }, () => {
                    // `publicKeyAlgorithm` is not part of Node's typings, hence the loose type.
                    const cert: any = socket.getPeerCertificate(true);
                    const isSelfSigned = cert.issuerCertificate &&
                        cert.fingerprint === cert.issuerCertificate.fingerprint;

                    // SPLITTA SubjectAltName till array
                    const san = cert.subjectaltname
                        ? cert.subjectaltname.split(',').map((x: string) => x.trim().replace(/^DNS:/, ''))
                        : [];

                    const base: Record<string, any> = {
                        subject: cert.subject,
                        issuer: cert.issuer,
                        valid_from: cert.valid_from,
                        valid_to: cert.valid_to,
                        subjectaltname: cert.subjectaltname,         // kvar som string
                        subjectaltnameList: san,                     // <-- NYTT: lista
                        fingerprint: cert.fingerprint,
                        fingerprint256: cert.fingerprint256 || null, // <-- NYTT: SHA-256 fingerprint
                        serialNumber: cert.serialNumber,
                        publicKeyAlgorithm: cert.publicKeyAlgorithm || null,
                        keySize: cert.bits || null,
                        isSelfSigned
                    };

                    if (cert.issuerCertificate && cert.issuerCertificate.subject) {
                        base.issuerCertificate = {
                            subject: cert.issuerCertificate.subject,
                            issuer: cert.issuerCertificate.issuer,
                            valid_from: cert.issuerCertificate.valid_from,
                            valid_to: cert.issuerCertificate.valid_to,
                            fingerprint: cert.issuerCertificate.fingerprint,
                            serialNumber: cert.issuerCertificate.serialNumber
                        };
                    }

                    socket.end();
                    resolve(base);
                });
                socket.on('error', reject);
                // Without a timeout a stalled connection waits for the OS (~60s+) and holds the whole response.
                socket.setTimeout(10000, () => socket.destroy(new Error('TLS connection timed out after 10s')));
            });

            // Sätt till null om algoritm saknas
            if (!certInfo.publicKeyAlgorithm) {
                certInfo.publicKeyAlgorithm = null;
            }

            certInfo.algorithmSource = 'tls.getPeerCertificate';
            sslSection.sslCertificate = certInfo;
            sslSection.sslComment = 'Extracted SSL certificate info (includes subjectAltNameList and fingerprint256 if available)';
            jobLog.info('STEP 8: SSL info retrieved');
        } catch (err) {
            sslSection.sslCertificate = {
                error: err.message,
                publicKeyAlgorithm: null,
                algorithmSource: 'unavailable'
            };
            sslSection.sslComment = 'Failed to extract SSL certificate (openssl not available)';
            jobLog.info('STEP 8: SSL failed', err.message);
        }

        // No active port scan: scanning 1000 ports from the server's own IP was unreliable (CDNs drop it),
        // congested the network for concurrent requests and risks firewalls blocking the server.
        try {
            if (!shodanPromise) throw new Error('No host IP (DNS lookup failed)');
            const shodan = await shodanPromise;
            networkSection.openPorts = shodan?.ports ?? [];
            networkSection.openPortsComment = shodan
                ? "Open ports from Shodan InternetDB (Shodan's last scan of the host IP, not a live check)"
                : 'Shodan InternetDB has no data on the host IP';
            jobLog.info('STEP 15: Shodan ports', shodan ? networkSection.openPorts : 'no data');
        } catch (err) {
            networkSection.openPorts = [];
            networkSection.openPortsError = err.message;
            jobLog.info('STEP 15: Shodan lookup failed', err.message);
        }
    };

    let html: string | null = null;
    let statusCode: number | null = null;
    let fetchError: string | null = null;

    // A: the page itself (STEP 9) - headless Chrome through the proxy, rotating IPs while blocked.
    const fetchPageStep = async () => {
        try {

            // Non-null assertions mirror the original JS: a missing result/headers/html throws
            // here and is caught by the outer catch below.
            const response = (await fetchWithRotation(parsedUrl, proxyConfiguration, maxFetchAttempts, httpFirst))!;
            html = response.html;
            statusCode = response.httpStatus ?? null;
            if (!html) fetchError = response.error ?? response.headers?.error ?? `Page fetch failed (status: ${response.status})`;
            const responseHeaders = response.headers!;

            httpSection.headers = responseHeaders;  // Spara ALLA HTTP response headers
            httpSection.fetchMethod = response.method ?? null;
            httpSection.headersComment = `Full HTTP response headers (fetched via ${response.method === 'http' ? 'plain HTTP' : response.method === 'axios' ? 'Axios fallback' : 'Puppeteer'})`;

            httpSection.serverHeader      = responseHeaders['server']          || null;
            httpSection.xPoweredBy        = responseHeaders['x-powered-by']    || null;
            httpSection.viaHeader         = responseHeaders['via']             || null;
            httpSection.cfRay             = responseHeaders['cf-ray']          || null;
            httpSection.xShopifyStage     = responseHeaders['x-shopify-stage'] || null;
            httpSection.xMagentoVary      = responseHeaders['x-magento-vary']  || null;
            httpSection.xAkamaiEdgescape  = responseHeaders['x-akamai-edgescape'] || null;
            httpSection.xBackendServer    = responseHeaders['x-backend-server'] || null;
            httpSection.setCookieHeader   = responseHeaders['set-cookie'] || null;

            httpSection.cfCacheStatus      = responseHeaders['cf-cache-status'] || null;
            httpSection.xAmzCfPop          = responseHeaders['x-amz-cf-pop'] || null;
            httpSection.xEdgeOriginShield  = responseHeaders['x-edge-origin-shield'] || null;
            httpSection.xFastlyRequestId   = responseHeaders['x-fastly-request-id'] || null;
            httpSection.xServedBy          = responseHeaders['x-served-by'] || null;
            httpSection.xCache             = responseHeaders['x-cache'] || null;
            httpSection.xCacheHits         = responseHeaders['x-cache-hits'] || null;
            httpSection.xRequestId         = responseHeaders['x-request-id'] || null;
            httpSection.xVercelId          = responseHeaders['x-vercel-id'] || null;
            httpSection.xNowId             = responseHeaders['x-now-id'] || null;
            httpSection.xNowTrace          = responseHeaders['x-now-trace'] || null;
            httpSection.xGateway           = responseHeaders['x-gateway'] || null;
            httpSection.xAppEngineRegion   = responseHeaders['x-appengine-region'] || null;
            httpSection.xShopId            = responseHeaders['x-shop-id'] || null;
            httpSection.xShopifyShopDomain = responseHeaders['x-shopify-shop-domain'] || null;
            httpSection.xWixRequestId      = responseHeaders['x-wix-request-id'] || null;
            httpSection.xWixServer         = responseHeaders['x-wix-server'] || null;
            httpSection.xGeneratedBy       = responseHeaders['x-generated-by'] || null;
            httpSection.xPoweredCms        = responseHeaders['x-powered-cms'] || null;

            httpSection.strictTransportSecurity   = responseHeaders['strict-transport-security'] || null;
            httpSection.contentSecurityPolicy     = responseHeaders['content-security-policy'] || null;
            httpSection.xContentTypeOptions       = responseHeaders['x-content-type-options'] || null;
            httpSection.xFrameOptions             = responseHeaders['x-frame-options'] || null;
            httpSection.xXssProtection            = responseHeaders['x-xss-protection'] || null;
            httpSection.permissionsPolicy         = responseHeaders['permissions-policy'] || null;
            httpSection.reportTo                  = responseHeaders['report-to'] || null;
            httpSection.nel                       = responseHeaders['nel'] || null;
            httpSection.expectCt                  = responseHeaders['expect-ct'] || null;

            httpSection.etag              = responseHeaders['etag'] || null;
            httpSection.lastModified      = responseHeaders['last-modified'] || null;
            httpSection.expires           = responseHeaders['expires'] || null;
            httpSection.pragma            = responseHeaders['pragma'] || null;
            httpSection.cacheControl      = responseHeaders['cache-control'] || null;

            httpSection.viaHeader              = responseHeaders['via'] || null;
            httpSection.xForwardedForHeader    = responseHeaders['x-forwarded-for'] || null;
            httpSection.xRealIpHeader          = responseHeaders['x-real-ip'] || null;
            httpSection.cfConnectingIpHeader   = responseHeaders['cf-connecting-ip'] || null;
            httpSection.xAmznTraceIdHeader     = responseHeaders['x-amzn-trace-id'] || null;

            const pageHtml = html!;
            contentSection.htmlHeadSnippet = pageHtml.slice(0, 1200);

            jobLog.info('STEP 9: HTTP headers collected + HTML retrieved');

            // Parsed with Cheerio instead of regexes: attribute order doesn't matter (`href` before `rel`),
            // `rel` may hold several tokens or different case, and entities in the title are decoded.
            const $ = cheerio.load(pageHtml);
            const iconHref = $('link[rel~="icon" i]').first().attr('href')
                || $('link[rel~="apple-touch-icon" i]').first().attr('href');

            if (iconHref?.trim()) {
                const href = iconHref.trim();
                try {
                    // Alltid korrekt favicon-URL – hanterar absolut, root-relative och relativ
                    contentSection.faviconUrl = new URL(href, parsedUrl).href;
                } catch {
                    // Om nåt är fel, fallback på gammalt sätt
                    contentSection.faviconUrl = href;
                }
                contentSection.faviconComment = 'Parsed favicon from HTML';
                jobLog.info('STEP 9a: Favicon collected + HTML retrieved');
            }

            try {
                // The document title lives in <head>; an <svg><title> in the body must not win.
                const pageTitle = ($('head title').first().text() || $('title').first().text()).trim();
                if (pageTitle) {
                    contentSection.pageTitle = pageTitle;
                    contentSection.pageTitleComment = 'Title of the HTML page';
                    jobLog.info('STEP 9b: Page title extracted:', contentSection.pageTitle);
                } else {
                    contentSection.pageTitle = null;
                    contentSection.pageTitleComment = 'No <title> tag found';
                    jobLog.info('STEP 9b: No <title> tag found');
                }
            } catch (err) {
                contentSection.pageTitle = null;
                contentSection.pageTitleComment = 'Error while extracting page title';
                jobLog.info('STEP 9b: Error extracting title:', err.message);
            }

        } catch (err) {
            httpSection.headers = { error: err.message };
            if (!html) fetchError ??= err.message;
            jobLog.info('STEP 9: HTTP failed (outer)', err.message);
        }
    };

    // C: ads.txt + humans.txt, manifest.json (STEP 13), robots.txt (STEP 14).
    const sideFilesStep = async () => {
        // The four files are independent: fetch them at once, so a slow or hanging site costs one
        // 5s timeout instead of up to 3 x 5s.
        const adsAndHumansTxt = async () => {
            // ads.txt & humans.txt
            const validateTextResponse = (res: { headers?: HeadersMap; data?: unknown } | undefined) =>
                res?.headers?.['content-type']?.includes('text/plain') &&
                typeof res.data === 'string' &&
                !res.data.includes('<html');

            contentSection.adsTxt = null;
            contentSection.humansTxt = null;

            // allSettled, not all: a 404 on one file must not throw away the other one.
            const [adsRes, humansRes] = await Promise.allSettled([
                axios.get(`${origin}/ads.txt`, { headers, timeout: 5000 }),
                axios.get(`${origin}/humans.txt`, { headers, timeout: 5000 }),
            ]);

            if (adsRes.status === 'fulfilled' && validateTextResponse(adsRes.value)) {
                contentSection.adsTxt = adsRes.value.data;
                jobLog.info('ads.txt fetched and validated.');
            } else {
                jobLog.info('ads.txt invalid or not found:', adsRes.status === 'rejected' ? adsRes.reason?.message : 'not plain text');
            }

            if (humansRes.status === 'fulfilled' && validateTextResponse(humansRes.value)) {
                contentSection.humansTxt = humansRes.value.data;
                jobLog.info('humans.txt fetched and validated.');
            } else {
                jobLog.info('humans.txt invalid or not found:', humansRes.status === 'rejected' ? humansRes.reason?.message : 'not plain text');
            }

            contentSection.adsHumansComment = contentSection.adsTxt || contentSection.humansTxt
                ? 'ads.txt and humans.txt if available'
                : 'ads.txt and humans.txt not found or invalid';
        };

        const manifestJson = async () => {
            try {
                const res = await axios.get(`${origin}/manifest.json`, {
                    headers: {
                        ...headers,
                        Accept: 'application/json',
                    },
                    timeout: 5000
                });
                if (typeof res.data === 'object') contentSection.manifest = res.data;
                contentSection.manifestComment = 'Web app manifest.json if available';
                jobLog.info('STEP 13: manifest.json fetched');
            } catch (_) {
                jobLog.info('STEP 13: manifest.json failed fetched');
                contentSection.manifest = null;
                contentSection.manifestComment = 'manifest.json not found or invalid';
            }
        };

        const robotsTxt = async () => {
            try {
                const res = await axios.get(`${origin}/robots.txt`, { headers, timeout: 5000 });
                contentSection.robotsTxt = res.data;
                contentSection.robotsComment = 'robots.txt content';
                jobLog.info('STEP 14: robots.txt fetched');
            } catch (_) {
                jobLog.info('STEP 14: robots.txt failed fetched');
                contentSection.robotsTxt = null;
                contentSection.robotsComment = ' robots.txt not found or invalid';
            }
        };

        await Promise.all([adsAndHumansTxt(), manifestJson(), robotsTxt()]);
    };

    await Promise.all([fetchPageStep(), networkStep(), sideFilesStep()]);

    // Platform detection
    // Scoring-based: scans ALL indicators, picks the highest confidence
    // (tie-break: more matched patterns wins). Order of declaration is irrelevant.
    function detectPlatform(
        html: string | null,
        headers: HeadersMap | null | undefined,
        robotsTxt: string | null | undefined,
        faviconUrl: string | null | undefined,
    ): PlatformDetectionResult {
        const result: PlatformDetectionResult = { platform: null, confidence: 0, matched: [] };
        const indicators: { name: string; confidence: number; patterns: RegExp[] }[] = [
            // --- eCommerce / plugins ---
            {
                // Bare brand names are deliberately avoided throughout this list: an agency or
                // blog page that merely *mentions* (or shows a logo for) a platform is not
                // running it. Every pattern below must imply an actual install.
                name: 'WooCommerce', confidence: 90, patterns: [
                    /wc-ajax/i, /wp-content\/plugins\/woocommerce/i,
                    /woocommerce_cart_hash/i, /wp-json\/wc\//i, /class="[^"]*woocommerce-page/i
                ]
            },
            {
                name: 'Shopify', confidence: 90, patterns: [
                    /cdn\.shopify\.com/i, /X-ShopId/i, /shopify-features/i, /shopify-checkout/i
                ]
            },
            {
                name: 'Lightspeed', confidence: 90, patterns: [
                    /cdn\.shoplightspeed\.com/i, /x-shop-id/i, /shoplightspeed\.com/i
                ]
            },
            {
                name: 'Magento', confidence: 85, patterns: [
                    /X-Magento-Vary/i, /\/static\/version\d+\//i, /Mage\.Cookies/i, /\/js\/mage\//i, /"Magento_/i
                ]
            },
            {
                name: 'PrestaShop', confidence: 80, patterns: [
                    /var\s+prestashop\s*=/i, /generator.{0,40}PrestaShop/i,
                    /\/modules\/ps_\w+\//i, /PrestaShop-[0-9a-f]{16}/i
                ]
            },
            {
                name: 'BigCommerce', confidence: 80, patterns: [
                    /cdn\.bc0\.com/i, /cdn\d*\.bigcommerce\.com/i, /\/stencil\/[\w.-]+\//i, /X-BC-\w+/i
                ]
            },
            {
                name: 'Salesforce Commerce Cloud', confidence: 85, patterns: [
                    /demandware\.static/i, /dwsecuretoken/i, /\/on\/demandware\.store\//i
                ]
            },
            {
                name: 'Ecwid', confidence: 80, patterns: [
                    /app\.ecwid\.com/i, /d\w+\.ecwid\.com/i, /ecwid_html/i, /window\.Ecwid/i, /ecwid_script/i
                ]
            },
            {
                name: 'Volusion', confidence: 80, patterns: [
                    /[\w-]+\.volusion\.com/i, /\/vspfiles\//i
                ]
            },
            // --- CMS ---
            {
                // NOT bare /wp-content/: sites migrated off WordPress keep serving legacy
                // /wp-content/uploads/ media, which alone says nothing about the current stack.
                name: 'WordPress', confidence: 90, patterns: [
                    /wp-content\/(?:themes|plugins|mu-plugins)\//i, /wp-includes\//i,
                    /wp-json/i, /generator.{0,40}WordPress/i, /wp-admin/i
                ]
            },
            {
                name: 'Joomla', confidence: 85, patterns: [
                    /generator.{0,40}Joomla/i, /\/media\/jui\//i, /\/media\/system\/js\//i, /\/components\/com_/i,
                    /option=com_/i, /\/templates\/[\w-]+\/(?:css|js|images|fonts|html)\//i,
                    // robots.txt fingerprints (Joomla default Disallow list + unique comment header)
                    /If the Joomla site is installed within a folder/i,
                    /\/administrator\//i, /\/modules\/mod_/i, /Disallow:\s*\/(components|modules|plugins|administrator)\//i
                ]
            },
            {
                name: 'Drupal', confidence: 85, patterns: [
                    /Drupal\.settings/i, /sites\/(all|default)\/(themes|modules)/i, /X-Generator.{0,40}Drupal/i, /generator.{0,40}Drupal/i
                ]
            },
            {
                name: 'Ghost', confidence: 85, patterns: [
                    /\/ghost\/api\//i, /generator.{0,40}Ghost/i, /content\/images\/\d{4}\//i
                ]
            },
            {
                name: 'HubSpot CMS', confidence: 80, patterns: [
                    /hs-scripts\.com/i, /hs-sites\.com/i, /js\.hs-analytics\.net/i, /_hsq/i
                ]
            },
            {
                name: 'Craft CMS', confidence: 80, patterns: [
                    /X-Powered-By.{0,40}Craft CMS/i, /generator.{0,40}Craft CMS/i, /\/cpresources\//i
                ]
            },
            {
                name: 'Blogger', confidence: 85, patterns: [
                    /\.blogspot\.com/i, /blogger\.com\/(dyn-css|static)/i, /generator.{0,40}Blogger/i
                ]
            },
            // --- Site builders ---
            {
                name: 'Wix', confidence: 90, patterns: [
                    /X-Wix-Request-Id/i, /wixstatic\.com/i, /\.wixsite\.com/i, /wix-(?:perf-measure|bootstrap)/i
                ]
            },
            {
                name: 'Squarespace', confidence: 85, patterns: [
                    /static\d*\.squarespace\.com/i, /squarespace-cdn\.com/i,
                    /generator.{0,40}Squarespace/i, /Static\.SQUARESPACE_CONTEXT/i
                ]
            },
            {
                name: 'Webflow', confidence: 85, patterns: [
                    /generator.{0,40}Webflow/i, /website-files\.com/i, /data-wf-page/i, /assets\.website-files\.com/i
                ]
            },
            {
                name: 'Weebly', confidence: 80, patterns: [
                    /\.weebly\.com/i, /editmysite\.com/i, /weebly-(?:footer|nav)/i
                ]
            },
            {
                name: 'GoDaddy Website Builder', confidence: 80, patterns: [
                    /websitebuilder\.godaddy/i, /img1\.wsimg\.com/i
                ]
            },
            // --- JS frameworks (least specific, checked last) ---
            {
                name: 'Next.js', confidence: 70, patterns: [
                    /\/_next\/static\//i, /__NEXT_DATA__/i
                ]
            },
            {
                name: 'Nuxt', confidence: 70, patterns: [
                    /\/_nuxt\//i, /__NUXT__/i
                ]
            },
            {
                name: 'Gatsby', confidence: 70, patterns: [
                    /___gatsby/i, /\/page-data\/app-data\.json/i, /generator.{0,40}Gatsby/i
                ]
            },
            {
                name: 'Astro', confidence: 70, patterns: [
                    /\/_astro\//i, /data-astro-cid-/i, /astro-cid-[a-z0-9]{6}/i, /generator.{0,40}Astro/i
                ]
            },
        ];

        // Include headers (names + values via JSON), robots.txt and favicon URL
        // so path-based fingerprints (e.g. Joomla /administrator/) are covered.
        const allText = [
            html,
            headers ? JSON.stringify(headers) : null,
            robotsTxt,
            faviconUrl,
        ].filter(Boolean).join(' ');

        let best: { name: string; confidence: number; matched: RegExp[] } | null = null;
        for (const { name, confidence, patterns } of indicators) {
            const matched = patterns.filter(p => p.test(allText));
            if (matched.length === 0) continue;

            const candidate = { name, confidence, matched };
            const better = !best
                || candidate.confidence > best.confidence
                || (candidate.confidence === best.confidence && candidate.matched.length > best.matched.length);
            if (better) best = candidate;
        }

        if (best) {
            result.platform = best.name;
            result.confidence = best.confidence;
            result.matched = best.matched.map(p => p.toString());
        }

        return result;
    }

    // Run AFTER robots.txt + favicon are available so their fingerprints count.
    contentSection.platformDetection = detectPlatform(
        html,
        httpSection.headers,
        contentSection.robotsTxt,
        contentSection.faviconUrl,
    );
    contentSection.platformComment = 'Detected CMS or eCommerce platform';
    jobLog.info('STEP 12: Platform detection done', contentSection.platformDetection.platform);

    const finalOutput = {
        meta: metaSection,
        dns: dnsSection,
        ssl: sslSection,
        http: httpSection,
        content: contentSection,
        network: networkSection
    };

    jobLog.info('STEP 16: Analysis done');
    return { output: finalOutput, statusCode, pageFetched: !!html, fetchError };
}
