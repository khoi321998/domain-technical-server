import { AsyncLocalStorage } from 'node:async_hooks';
import { inspect } from 'node:util';

import { log, LoggerText } from 'apify';

// Prefix every log line with a timestamp. Apify's log also censors tokens.
log.setOptions({ logger: new LoggerText({ skipTime: false }) });

export { log };

/** Prefix of the job running in the current async context: "url" or "url [transactionId: x]". */
const jobPrefix = new AsyncLocalStorage<string>();

export async function runWithJobPrefix<T>(prefix: string, fn: () => Promise<T>): Promise<T> {
    return jobPrefix.run(prefix, fn);
}

function format(args: unknown[]): string {
    const message = args.map((a) => (typeof a === 'string' ? a : inspect(a, { depth: 4, breakLength: Infinity }))).join(' ');
    const prefix = jobPrefix.getStore();
    return prefix ? `${prefix} | ${message}` : message;
}

/**
 * console-like logger for the domain analysis: concurrent jobs interleave in the logs, so every line
 * carries the url + transactionId of the job it belongs to (grep-able by transactionId).
 */
export const jobLog = {
    info: (...args: unknown[]) => log.info(format(args)),
    warn: (...args: unknown[]) => log.warning(format(args)),
    error: (...args: unknown[]) => log.error(format(args)),
};
