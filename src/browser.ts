import type { Browser } from 'puppeteer';
import puppeteer from 'puppeteer';

import { log } from './logger.js';

/**
 * One Chrome kept warm for the lifetime of the server, so requests don't pay a cold start.
 * Each fetch attempt opens its own browser context (with its own proxy session) and closes it afterwards.
 * If Chrome crashes or disconnects, the next request launches a new one.
 */
let browserPromise: Promise<Browser> | null = null;

async function launch(): Promise<Browser> {
    const browser = await puppeteer.launch({
        headless: true,
        // The Apify base image announces its Chrome via APIFY_CHROME_EXECUTABLE_PATH; fall back to Puppeteer's default.
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || process.env.APIFY_CHROME_EXECUTABLE_PATH || undefined,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-web-security'],
    });
    browser.on('disconnected', () => {
        log.warning('Chrome disconnected, it will be relaunched on the next request.');
        browserPromise = null;
    });
    log.info(`Chrome launched (${await browser.version()})`);
    return browser;
}

export async function getBrowser(): Promise<Browser> {
    if (!browserPromise) {
        browserPromise = launch().catch((error) => {
            browserPromise = null;
            throw error;
        });
    }
    return browserPromise;
}

/**
 * Chrome slots: at most maxBrowserContexts contexts are open at once, the rest wait in FIFO order.
 * Plain HTTP fetches are cheap, Chrome is not, so this caps memory/CPU however many requests fall back to Chrome.
 */
let maxBrowserContexts = 8;
let openContexts = 0;
const waitingForBrowser: (() => void)[] = [];

export function setMaxBrowserContexts(max: number) {
    maxBrowserContexts = max;
}

export function browserSlotStats() {
    return { open: openContexts, max: maxBrowserContexts, waiting: waitingForBrowser.length };
}

export async function acquireBrowserSlot() {
    if (openContexts < maxBrowserContexts) {
        openContexts++;
        return;
    }
    // The slot is handed over by releaseBrowserSlot, so openContexts stays the same.
    await new Promise<void>((resolve) => {
        waitingForBrowser.push(resolve);
    });
}

export function releaseBrowserSlot() {
    const next = waitingForBrowser.shift();
    if (next) next();
    else openContexts--;
}

export async function closeBrowser() {
    const browser = await browserPromise?.catch(() => null);
    browserPromise = null;
    await browser?.close();
}
