"""Tech Stack Detector actor: detect the technologies powering any website.

Each public URL is fetched over plain HTTP (no headless browser), and the
response is fingerprinted Wappalyzer-style: HTTP response headers, Set-Cookie
values, <meta name="generator">, script/link URLs, HTML comments and
distinctive HTML snippets are matched against a rule database of ~35
technologies (CMS, frameworks, analytics, CDN, ecommerce, advertising,
payment, hosting).

Pay-per-event charges ("site-analyzed") are emitted only for successfully
analyzed sites, never for failures.
"""

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx
from apify import Actor
from bs4 import BeautifulSoup

EVENT_SITE = 'site-analyzed'

REQUEST_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}

# Cap how much HTML we fingerprint (Wappalyzer works on the head anyway).
MAX_HTML_BYTES = 500_000

# ---------------------------------------------------------------------------
# Fingerprint database.
# Each entry: name, category, and regex rules (all case-insensitive) matched
# against response headers, Set-Cookie values, and the HTML body.
# A site can match many technologies; results are deduped by name.
# ---------------------------------------------------------------------------
FINGERPRINTS = [
    # ---- CMS ----
    {'name': 'WordPress', 'category': 'CMS',
     'html': [r'wp-content/', r'wp-includes/',
              r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*WordPress'],
     'cookies': [r'wordpress_test_cookie', r'wp-settings']},
    {'name': 'Shopify', 'category': 'Ecommerce',
     'html': [r'cdn\.shopify\.com',
              r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Shopify'],
     'cookies': [r'_shopify_y', r'_shopify_s', r'secure_customer_sig']},
    {'name': 'Wix', 'category': 'CMS',
     'html': [r'wixstatic\.com', r'wix\.com',
              r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Wix'],
     'headers': {'x-wix-request-id': r'.+'},
     'cookies': [r'svSession', r'hs']},
    {'name': 'Squarespace', 'category': 'CMS',
     'html': [r'static1\.squarespace\.com', r'squarespace\.com'],
     'cookies': [r'SS_MID', r'SS_CVT']},
    {'name': 'Webflow', 'category': 'CMS',
     'html': [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Webflow',
              r'webflow\.com', r'data-wf-page']},
    {'name': 'Ghost', 'category': 'CMS',
     'html': [r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Ghost']},
    {'name': 'Joomla', 'category': 'CMS',
     'html': [r'/media/jui/', r'/media/system/js/',
              r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Joomla']},
    {'name': 'Drupal', 'category': 'CMS',
     'html': [r'/sites/default/files', r'Drupal\.settings',
              r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Drupal']},
    {'name': 'HubSpot', 'category': 'CMS',
     'html': [r'hs-scripts\.com', r'js\.hsforms\.net', r'hubspot\.com']},
    {'name': 'WooCommerce', 'category': 'Ecommerce',
     'html': [r'/wp-content/plugins/woocommerce', r'woocommerce']},
    {'name': 'Magento', 'category': 'Ecommerce',
     'html': [r'static/frontend/Magento', r'/static/version', r'Magento_']},
    {'name': 'BigCommerce', 'category': 'Ecommerce',
     'html': [r'cdn\d*\.bigcommerce\.com', r'bigcommerce\.com']},
    # ---- Frameworks / languages ----
    {'name': 'Next.js', 'category': 'Framework',
     'html': [r'/_next/static/', r'__NEXT_DATA__']},
    {'name': 'Nuxt', 'category': 'Framework',
     'html': [r'/_nuxt/', r'__NUXT__']},
    {'name': 'Gatsby', 'category': 'Framework',
     'html': [r'gatsby-', r'/static/d/', r'___gatsby']},
    {'name': 'React', 'category': 'Framework',
     'html': [r'/static/js/main\.[a-f0-9]+\.js', r'react-dom', r'_reactRoot']},
    {'name': 'Angular', 'category': 'Framework',
     'html': [r'ng-version', r'<app-root']},
    {'name': 'Vue', 'category': 'Framework',
     'html': [r'__VUE__', r'/js/chunk-vendors', r'data-v-[a-f0-9]{8}']},
    {'name': 'Svelte', 'category': 'Framework',
     'html': [r'svelte']},
    {'name': 'Laravel', 'category': 'Framework',
     'cookies': [r'laravel_session']},
    {'name': 'Django', 'category': 'Framework',
     'cookies': [r'csrftoken']},
    {'name': 'Ruby on Rails', 'category': 'Framework',
     'html': [r'<meta[^>]+name=["\']csrf-param["\']']},
    {'name': 'PHP', 'category': 'Framework',
     'headers': {'x-powered-by': r'PHP'}},
    {'name': 'ASP.NET', 'category': 'Framework',
     'headers': {'x-powered-by': r'ASP\.NET', 'x-aspnet-version': r'.+'},
     'cookies': [r'ASP\.NET_SessionId']},
    {'name': 'Express', 'category': 'Framework',
     'headers': {'x-powered-by': r'Express'}},
    # ---- Analytics / marketing ----
    {'name': 'Google Analytics', 'category': 'Analytics',
     'html': [r'googletagmanager\.com/gtag/js', r'google-analytics\.com/analytics\.js',
              r"ga\(['\"]create['\"]", r'_ga=']},
    {'name': 'Google Tag Manager', 'category': 'Analytics',
     'html': [r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+']},
    {'name': 'Facebook Pixel', 'category': 'Advertising',
     'html': [r'connect\.facebook\.net', r'fbq\(']},
    {'name': 'Google AdSense', 'category': 'Advertising',
     'html': [r'pagead2\.googlesyndication\.com']},
    {'name': 'Hotjar', 'category': 'Analytics',
     'html': [r'static\.hotjar\.com']},
    {'name': 'Mixpanel', 'category': 'Analytics',
     'html': [r'cdn\.mxpnl\.com']},
    {'name': 'Segment', 'category': 'Analytics',
     'html': [r'cdn\.segment\.com']},
    # ---- CDN / hosting ----
    {'name': 'Cloudflare', 'category': 'CDN',
     'headers': {'cf-ray': r'.+', 'server': r'cloudflare'},
     'cookies': [r'__cf_bm', r'__cfduid', r'cf_clearance']},
    {'name': 'Fastly', 'category': 'CDN',
     'headers': {'x-fastly-request-id': r'.+', 'via': r'fastly'}},
    {'name': 'Akamai', 'category': 'CDN',
     'headers': {'x-akamai-request-bc': r'.+', 'server': r'Akamai'}},
    {'name': 'AWS CloudFront', 'category': 'CDN',
     'headers': {'via': r'cloudfront', 'x-amz-cf-id': r'.+'}},
    {'name': 'Vercel', 'category': 'Hosting',
     'headers': {'x-vercel-id': r'.+', 'server': r'vercel'}},
    {'name': 'Netlify', 'category': 'Hosting',
     'headers': {'x-nf-request-id': r'.+', 'server': r'netlify'}},
    # ---- Payment ----
    {'name': 'Stripe', 'category': 'Payment',
     'html': [r'js\.stripe\.com']},
    {'name': 'PayPal', 'category': 'Payment',
     'html': [r'paypal\.com/sdk/js', r'paypalobjects\.com']},
]

# Pre-compile all regexes once.
for _fp in FINGERPRINTS:
    _fp['html'] = [re.compile(p, re.IGNORECASE) for p in _fp.get('html', [])]
    _fp['cookies'] = [re.compile(p, re.IGNORECASE) for p in _fp.get('cookies', [])]
    _fp['headers'] = {h: re.compile(p, re.IGNORECASE)
                      for h, p in _fp.get('headers', {}).items()}


async def check_public_url(url: str) -> tuple[bool, str]:
    """SSRF guard: only allow http(s) URLs that resolve to public IPs."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'malformed URL'
    if parsed.scheme not in ('http', 'https'):
        return False, f"unsupported scheme '{parsed.scheme}' (only http/https allowed)"
    host = parsed.hostname
    if not host:
        return False, 'missing hostname'
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False, 'DNS resolution failed'
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            return False, f'resolves to non-public IP {ip}'
    return True, ''


def detect_technologies(headers: dict, cookies: list[str], html: str) -> list[dict]:
    """Match the fingerprint DB against headers, cookies and HTML.

    Returns a list of {'name': ..., 'category': ...}, deduped by name.
    """
    matched: dict[str, str] = {}
    for fp in FINGERPRINTS:
        hit = False
        for hname, pattern in fp['headers'].items():
            value = headers.get(hname)
            if value and pattern.search(value):
                hit = True
                break
        if not hit:
            for pattern in fp['cookies']:
                if any(pattern.search(c) for c in cookies):
                    hit = True
                    break
        if not hit:
            for pattern in fp['html']:
                if pattern.search(html):
                    hit = True
                    break
        if hit:
            matched[fp['name']] = fp['category']
    return [{'name': name, 'category': cat} for name, cat in matched.items()]


def fail_item(url: str, reason: str, status: int | None = None) -> dict:
    return {'url': url, 'finalUrl': None, 'technologies': [],
            'categories': None, 'techCount': 0, 'statusCode': status,
            '_ok': False, '_reason': reason}


async def analyze_one(client: httpx.AsyncClient, url: str) -> dict:
    """Fetch one URL and fingerprint it. Never raises; failures become items."""
    ok, reason = await check_public_url(url)
    if not ok:
        return fail_item(url, f'blocked: {reason}')
    try:
        resp = await client.get(url, timeout=30.0, follow_redirects=True)
    except httpx.TimeoutException:
        return fail_item(url, 'fetch timed out after 30s')
    except httpx.HTTPError:
        return fail_item(url, 'fetch failed')
    except Exception:
        return fail_item(url, 'fetch failed')

    status = resp.status_code
    if status >= 400:
        return fail_item(url, f'HTTP {status}', status)
    content_type = resp.headers.get('content-type', '').lower()
    if 'html' not in content_type and 'text' not in content_type:
        return fail_item(url, f'unsupported content type: {content_type}', status)

    final_url = str(resp.url)
    html = resp.text[:MAX_HTML_BYTES]
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = [f'{k}={v}' for k, v in resp.cookies.items()]

    try:
        techs = detect_technologies(headers, cookies, html)
    except Exception as exc:
        return fail_item(url, f'detection failed: {type(exc).__name__}', status)

    names = [t['name'] for t in techs]
    categories = sorted({t['category'] for t in techs})
    return {
        'url': url,
        'finalUrl': final_url,
        'technologies': names,
        'categories': categories,
        'techCount': len(names),
        'statusCode': status,
        '_ok': True,
        '_reason': '',
    }


async def charge_event(event_name: str) -> None:
    """Bill one pay-per-event charge. Never let billing break the run."""
    try:
        await Actor.charge(event_name=event_name)
    except Exception as exc:
        Actor.log.warning(f'Pay-per-event charge {event_name!r} failed: {exc}')


def parse_urls(raw) -> list[str]:
    if isinstance(raw, str):
        return [u.strip() for u in raw.splitlines() if u.strip()]
    if isinstance(raw, (list, tuple)):
        return [str(u).strip() for u in raw if str(u).strip()]
    return []


def build_client() -> httpx.AsyncClient:
    """Build the HTTP client.

    Falls back to ignoring environment proxies if the environment's proxy
    config is malformed (e.g. bare IPv6 literals in no_proxy, which some
    httpx versions cannot parse) — a broken proxy config must not kill runs.
    """
    try:
        return httpx.AsyncClient(headers=REQUEST_HEADERS,
                                 follow_redirects=True, timeout=30.0)
    except Exception as exc:
        Actor.log.warning(f'Unusable proxy environment ({exc}); '
                          'continuing without env proxies.')
        return httpx.AsyncClient(headers=REQUEST_HEADERS,
                                 follow_redirects=True, timeout=30.0,
                                 trust_env=False)


def public_item(item: dict) -> dict:
    """Strip internal bookkeeping keys before pushing to the dataset."""
    return {k: v for k, v in item.items() if not k.startswith('_')}


async def main() -> None:
    async with Actor:
        inp = await Actor.get_input() or {}
        urls = parse_urls(inp.get('urls'))

        if not urls:
            await Actor.set_value('OUTPUT', {
                'total': 0, 'succeeded': 0, 'failed': 0,
                'error': 'no URLs provided',
            })
            return

        succeeded = 0
        failed = 0
        async with build_client() as client:
            for url in urls:
                item = await analyze_one(client, url)
                # Push first; charge only after successful delivery.
                await Actor.push_data(public_item(item))
                if item['_ok']:
                    succeeded += 1
                    await charge_event(EVENT_SITE)
                else:
                    failed += 1
                    Actor.log.warning(f"Skipping {url}: {item['_reason']}")

        await Actor.set_value('OUTPUT', {
            'total': len(urls),
            'succeeded': succeeded,
            'failed': failed,
        })
