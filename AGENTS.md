# Domain Technical Web Server — Agent Guide

Self-hosted HTTP server that analyzes one domain per request (DNS, SSL, HTTP headers, platform detection, open ports from Shodan InternetDB) and returns the result in the response. It is **not** an Apify Actor anymore: there is no `Actor.init()`, no input schema and no dataset. The `apify` package is used only to build Apify residential proxy URLs and for its `log`.

## Structure

- `src/server.ts`: HTTP server (`POST /scrape`, `GET /`), env config, API key check, concurrency slots (`MAX_CONCURRENCY`) and queue limit (`MAX_QUEUE`).
- `src/domain.ts`: the analysis core (`analyzeDomain`). All extraction logic lives here.
- `src/domain.ts` fetches the page with plain HTTP first (`fetchWithHttp`, impit) and falls back to Chrome when `needsBrowser` says the result is blocked or incomplete.
- `src/browser.ts`: the single warm Chrome. Each fetch attempt opens its own browser context with its own proxy session.
- `src/logger.ts`: `jobLog` prefixes every line with the current request's url + `transactionId` (AsyncLocalStorage).

## Rules

- Configuration comes from env vars read in `src/server.ts`, with defaults in code. Add a new setting there, log it in the startup `Server config` line, and document it in README.md and `.env`.
- Never log secrets (`API_KEY`, `APIFY_PROXY_PASSWORD`, full proxy URLs). Log only whether they are set, and proxies by username.
- Don't accept code from requests. Request bodies carry data only.
- Inside the analysis, log with `jobLog`, never `console.*`, so concurrent requests stay grep-able by `transactionId`.
- Never launch a new Chrome per request. Use `getBrowser()` and close only the context.

## Commands

```bash
npm run build                     # tsc
npm run lint
docker build -t domain-technical-web-server .
docker run -d --name dtws-server -p 8080:8080 --cpus=4 --memory=4g --env-file .env domain-technical-web-server
```
