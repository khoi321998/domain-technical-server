# Domain Technical Web Server

A self-hosted HTTP server that analyzes one domain per request and returns its technical data in the response: DNS (A, NS, SOA, TXT, CNAME, MX, reverse DNS, DMARC/SPF/DKIM, hosting vendor), SSL certificate, HTTP response headers, page title / favicon / robots.txt / ads.txt / humans.txt / manifest.json, CMS / eCommerce platform detection and open TCP ports (from Shodan InternetDB, no active scan).

The page itself is fetched through Apify's residential proxy: first with a plain HTTP request that impersonates Chrome ([impit](https://github.com/apify/impit)), and with headless Chrome (Puppeteer) only when that result is blocked or incomplete. Each further attempt uses a fresh IP while the page looks blocked. Apify is used only for that proxy; this is not an Apify Actor.

One Chrome stays warm, so requests don't pay a cold start. `MAX_CONCURRENCY` requests run in parallel, the rest wait in a queue, and once `MAX_QUEUE` is reached the server returns `503`. Requests that fall back to Chrome also need one of `MAX_BROWSER_CONCURRENCY` Chrome slots and wait for one if all are in use, so memory stays bounded however many requests need Chrome.

## API

### `POST /scrape`

Analyzes one URL. Requires the `x-api-key` header.

```bash
curl -X POST http://localhost:8080/scrape \
  -H "Content-Type: application/json" \
  -H "x-api-key: <API_KEY>" \
  -d '{"url":"https://www.hdwebsoft.com/","transactionId":"order-1234"}'
```

| Field | Required | Description |
| --- | --- | --- |
| `url` | yes | Domain or http(s) URL. The scheme is optional: `example.com` becomes `https://example.com` |
| `transactionId` | no | Caller's id for this request, 1-100 letters, digits or `. _ : -`. Not returned in the response. Every log line of the request shows it next to the url (`https://... [transactionId: order-1234]`) |

Response `200`:

```json
{
    "status": "success",
    "url": "https://www.hdwebsoft.com/",
    "meta": { "origin": "...", "host": "...", "baseDomain": "..." },
    "dns": { "hostIp": {}, "nsRecords": [], "mxRecords": [], "dnsAuth": {}, "vendorsDetected": "...", "...": "..." },
    "ssl": { "sslCertificate": {} },
    "http": { "headers": {}, "serverHeader": "...", "...": "..." },
    "content": { "pageTitle": "...", "faviconUrl": "...", "robotsTxt": "...", "platformDetection": { "platform": "Astro", "confidence": 70, "matched": [] }, "...": "..." },
    "network": { "openPorts": [80, 443] },
    "statusCode": 200,
    "timing": { "queueMs": 90, "processMs": 12455, "totalMs": 12545 }
}
```

- `meta` / `dns` / `ssl` / `http` / `content` / `network` are the same sections the Apify Actor produced. See [src/domain.ts](src/domain.ts).
- How the page was fetched is in `http.fetchMethod`: `http` (plain HTTP, most sites, ~2-5 s), `browser` (headless Chrome) or `axios` (last-resort direct request). Chrome is used when the HTTP result is blocked (403 / 429 / 503, a challenge page, `cf-mitigated: challenge`), has no `<title>`, or is an empty JS app shell. After that, the remaining attempts use Chrome only.
- In Chrome, the page is loaded without images, fonts, CSS and media, and without third-party trackers, ads and chat widgets (`BLOCKED_THIRD_PARTY_DOMAINS` in [src/domain.ts](src/domain.ts)). Their tags stay in the HTML, so favicon and platform detection still see them; only the files aren't downloaded.
- `statusCode` is the HTTP status of the page in the last fetch attempt, after redirects. If every attempt looked blocked (`403`, `429`, `503`, a challenge page), the last result is still returned with `200` and that `statusCode`.
- `timing.queueMs` is the time before the analysis started (DNS pre-check + waiting for a free slot). `processMs` is the analysis itself.
- Every error response has the same body: `{ "status": "failed", "url", "error", "statusCode", "timing" }`. `url` is `null` when the request had no valid url. `statusCode` is `null` and `timing` is all zeros when no analysis ran.

| Status | Meaning |
| --- | --- |
| `200` | Analyzed successfully |
| `400` | Body is not valid JSON, `url` is missing or not http(s), or `transactionId` is invalid |
| `401` | Missing or wrong `x-api-key` |
| `502` | Analysis failed: the domain has no DNS record, or no HTML could be fetched after all attempts |
| `503` | Queue is full (`MAX_QUEUE`) |

### `GET /`

Health check. No auth. Returns `{"status":"ok","maxConcurrency":10,"active":1,"inProgress":3}`.

## Running with Docker

Put the configuration in `.env` next to the Dockerfile (see [Configuration](#configuration)). `.env` is ignored by git and Docker, so secrets are never committed or baked into the image.

```bash
docker build -t domain-technical-web-server .
docker run -d --name dtws-server -p 8080:8080 --cpus=4 --memory=4g --env-file .env domain-technical-web-server
```

To run new code, rebuild and recreate the container: `docker rm -f dtws-server`, then the two commands above.

### Production

Recommended: 4 CPU / 4 GB, `MAX_CONCURRENCY=30`, `MAX_BROWSER_CONCURRENCY=8`, `MAX_QUEUE=50`.

```bash
docker run -d --name dtws-server \
  --restart unless-stopped --init \
  -p <private-ip>:8080:8080 \
  --cpus=4 --memory=4g --shm-size=1g \
  --log-opt max-size=20m --log-opt max-file=5 \
  --env-file .env \
  domain-technical-web-server
```

- `--init` reaps exited Chrome processes so they don't pile up as zombies.
- Bind the port to a private IP (or `127.0.0.1` behind Nginx / Caddy). Docker's port publishing bypasses `ufw`.
- `--shm-size=1g` gives Chrome more shared memory than Docker's 64 MB default.
- Open ports come from [Shodan InternetDB](https://internetdb.shodan.io) (free, no key): Shodan's last scan of the host IP, not a live check. Nothing is sent to the site's other ports. An IP Shodan doesn't know gives `openPorts: []` with `openPortsComment` saying so. Check InternetDB's terms of use for your use case.

## Configuration

| Env var | Default | Description |
| --- | --- | --- |
| `API_KEY` | required | Shared secret the caller sends in `x-api-key` (at least 16 characters). Generate with `openssl rand -hex 32` |
| `PORT` | `8080` | HTTP port |
| `MAX_CONCURRENCY` | `4` | Requests analyzed in parallel |
| `MAX_BROWSER_CONCURRENCY` | `8` | Chrome contexts open at once. Requests that need Chrome beyond this wait for a slot (no `503`) |
| `MAX_QUEUE` | `100` | Max requests running or waiting. Beyond this, requests get `503` |
| `MAX_FETCH_ATTEMPTS` | `5` | Page fetch attempts, each with a fresh proxy IP, while the page looks blocked or fails |
| `HTTP_FIRST` | `true` | Try a plain HTTP request before Chrome. `false` = always use Chrome |
| `USE_APIFY_PROXY` | `false` | Fetch the page through Apify Proxy |
| `APIFY_PROXY_PASSWORD` | | Required when `USE_APIFY_PROXY=true` |
| `APIFY_PROXY_GROUPS` | `RESIDENTIAL` | Comma-separated proxy groups |

The server logs its effective configuration at startup. Secrets are shown only as `set` or `not set`, and proxy URLs are logged by username (group + session) only.

## Timeouts for callers

Each fetch attempt can take up to ~105 s through the proxy (45 s load, then a 60 s retry), plus an Axios fallback, and there are `MAX_FETCH_ATTEMPTS` attempts. A worst-case request can take several minutes. Set the caller's HTTP timeout above that, or lower `MAX_FETCH_ATTEMPTS`.

## Logs

Every line of a request starts with its url and `transactionId`, so one request can be found with `docker logs dtws-server 2>&1 | grep order-1234`. The lines are `Received ...`, the analysis steps (`... | STEP n: ...`), and then `Scraped ...` or `Scrape failed for ...`. A full queue logs `Rejected ...: server busy`.

## Development

```bash
npm install
npm run build        # tsc -> dist/
npm run lint
API_KEY=<key> npm run start:dev    # runs src/server.ts with tsx (needs Chrome installed locally)
```
