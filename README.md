# Tech Stack Detector

Find out what any website is built with — **CMS, frameworks, analytics, CDN, ecommerce, advertising, payment, hosting** — over plain HTTP, Wappalyzer-style. No headless browser, no waiting.

Feed it one or more URLs and get back one dataset row per site: the detected technology names, their categories, a tech count, the final URL (after redirects) and the HTTP status. Built for **sales prospecting** ("find me all Shopify stores"), **competitive research**, and **AI agents** that need to know what's behind a URL before acting on it.

## What it does

- **HTTP-only fingerprinting** — 30s timeout, browser-like User-Agent, follows redirects. A site analyzes in about a second.
- **~35-technology rule database** — response headers (`cf-ray`, `x-powered-by`, `x-vercel-id`…), `Set-Cookie` values (`_shopify_y`, `csrftoken`, `laravel_session`…), `<meta name="generator">`, script/link URLs (`/_next/static/`, `cdn.shopify.com`, `googletagmanager.com`…), and distinctive HTML snippets.
- **Categories** — every match is tagged: CMS, Framework, Analytics, CDN, Ecommerce, Advertising, Payment, Hosting.
- **Batch** — one URL per line; one bad URL never kills the batch, failures are reported per row (empty technology list).
- **Safe by default** — only public `http(s)` URLs are fetched; hosts resolving to private, loopback or link-local IPs are refused (SSRF guard).

## Input

| Field | Description |
|---|---|
| `urls` | Website URLs to analyze, one per line (required) |

Example input:

```json
{
  "urls": "https://www.shopify.com\nhttps://wordpress.org"
}
```

## Output

One dataset row per URL:

| Field | Description |
|---|---|
| `url` / `finalUrl` | Requested URL / URL after redirects |
| `statusCode` | HTTP status of the fetch |
| `technologies` | Detected technology names (e.g. `["Shopify", "Cloudflare"]`) |
| `categories` | Distinct categories (e.g. `["Ecommerce", "CDN"]`) |
| `techCount` | Number of technologies detected |

## Pricing

| Event | Price |
|---|---|
| Site analyzed | **$0.002** per site successfully analyzed |

You are only charged for sites that analyze successfully — failed fetches cost nothing. (Apify platform usage costs are paid by you as usual.)
