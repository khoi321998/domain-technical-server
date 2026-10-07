// Send POST /scrape requests in parallel (at most CONCURRENCY at a time) and print each result.
// Usage: node --env-file=.env scripts/send-parallel.mjs [server] [domain ...]
//   server defaults to http://localhost:8080
//   domains default to the list below (duplicates are removed)

// Keep this <= the server's MAX_QUEUE (50 in .env), or the extra requests get 503 "Server busy".
const CONCURRENCY = 30;

const server = process.argv[2] ?? 'http://localhost:8080';
const input = process.argv.slice(3).length
    ? process.argv.slice(3)
    : [
          'https://tflbearing.com/',
          'https://autoparts-bearing.com/',
          'https://sunrisesbearing.com/',
          'https://ht.hk-bearings.com/',
          'https://leyroinstruments.com/',
          'https://alierbearings.com/',
          'https://rollsbearing.com/',
          'https://tradebearings.com/',
          'https://bearing-a.com/',
          'https://pyton.com/',
          'https://www.skfbearing-china.com/index.html',
          'https://www.alierbearings.com/',
          'https://www.uniquebearing.com/',
          'https://lsbearing.com/',
          'https://stockbearing.com/',
          'https://www.bearingmotion.com/',
          'https://stepora.com/',
          'https://www.nike.com/vn/',
          'https://www.nike.com/nl/w/heren-vini-jr-a9on5znik1',
          'https://www.nike.com/fr/femme',
          'https://www.nike.com/gb/lockerroom',
          'https://www.nike.com/se',
          'https://karnz.de/',
          'https://www.melaniexboutiques.com/us/',
          'https://www.photopoint.ee/',
          'https://www.bossbyhugo.com/',
          'https://vnexpress.net/',
          'https://www.dincox.com/',
          'https://viettien.vn/',
          'https://www.converse.vn/',
      ];
const domains = [...new Set(input.map((url) => url.trim()))];

const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error('API_KEY is not set. Run with: node --env-file=.env scripts/send-parallel.mjs');

const seconds = (ms) => `${(ms / 1000).toFixed(1)}s`;

async function scrape(url, i) {
    const t0 = Date.now();
    try {
        const res = await fetch(`${server}/scrape`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-api-key': apiKey },
            body: JSON.stringify({ url, transactionId: `test-${i + 1}` }),
        });
        const body = await res.json();
        return { url, http: res.status, status: body.status, time: seconds(Date.now() - t0), error: body.error ?? '' };
    } catch (err) {
        return { url, http: '-', status: 'network error', time: seconds(Date.now() - t0), error: String(err.cause ?? err) };
    }
}

console.log(`Sending ${domains.length} URLs, ${CONCURRENCY} at a time...`);
const started = Date.now();
const results = new Array(domains.length);
let next = 0;
const workers = Array.from({ length: Math.min(CONCURRENCY, domains.length) }, async () => {
    while (next < domains.length) {
        const i = next++;
        results[i] = await scrape(domains[i], i);
        console.log(`[${i + 1}/${domains.length}] ${results[i].status} ${results[i].time} ${domains[i]}`);
    }
});
await Promise.all(workers);

console.table(results);
const ok = results.filter((r) => r.status === 'success').length;
console.log(`All ${domains.length} requests done in ${seconds(Date.now() - started)} (${ok} success, ${domains.length - ok} failed)`);
