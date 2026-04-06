#!/usr/bin/env python3
"""
domain_discovery.py  –  WSL Ubuntu 24 edition  v4
==================================================
Discovers subdomains / URLs from root domains provided via a TXT file.

Passive sources (all free, no API key required):
  1. crt.sh          – Certificate Transparency logs
  2. HackerTarget    – subdomain API
  3. AlienVault OTX  – Open Threat Exchange passive DNS
  4. RapidDNS        – subdomain search
  5. ThreatCrowd     – passive DNS (deprecated but still useful)
  6. DNS resolution  – validates each discovered host
  7. HTTP/HTTPS probe + optional HTML crawl

Local cache:
  • On startup, loads previously discovered URLs from the output TXT / JSON
    files (if they exist) so already-known hosts are NOT re-probed.
  • New discoveries are merged and saved, preserving the full history.
  • Re-run at any time: only genuinely new hosts are probed.

crt.sh adaptive behaviour:
  • 404 → domain has no CT records → stop immediately, do not retry
  • Timeout → raise timeout by +10 s (cap 60 s); after 3 consecutive
    timeouts give up on that domain (not worth waiting further)
  • 429/503 → exponential cool-down, increase inter-domain delay
  • All parameters managed internally — no CLI flags needed

Usage:
  python3 domain_discovery.py -i domains.txt
  python3 domain_discovery.py -i domains.txt --skip-crawl
  python3 domain_discovery.py -i domains.txt -o urls.txt --threads 30 -v
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import itertools
import json
import logging
import random
import re
import socket
import sys
import time
import threading
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, urlunparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
LOG_FMT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("domain_discovery")


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class DiscoveredEntry:
    url:           str
    host:          str
    source:        str    # crtsh|hackertarget|rapiddns|threatcrowd|html_crawl|seed|cache
    resolves:      bool  = False
    http_alive:    bool  = False
    http_status:   int   = 0
    redirect_to:   str   = ""
    discovered_at: str   = ""


# ──────────────────────────────────────────────────────────────────────────────
# crt.sh adaptive config (managed internally)
# ──────────────────────────────────────────────────────────────────────────────
class CrtShConfig:
    TIMEOUT_INIT   = 20
    TIMEOUT_STEP   = 10
    TIMEOUT_MAX    = 60
    MAX_CONSEC_TO  = 3      # give up after 3 consecutive timeouts for one domain
    DELAY_INIT     = 2.0
    DELAY_STEP     = 1.5
    DELAY_MAX      = 15.0
    COOLDOWN_BASE  = 30
    COOLDOWN_MAX   = 180
    COOLDOWN_MULT  = 2.0
    RETRIES        = 6

    MAX_CONSEC_CONN_ERR = 2   # abort crt.sh for domain after N consecutive network errors

    def __init__(self):
        self.timeout          = self.TIMEOUT_INIT
        self.inter_delay      = self.DELAY_INIT
        self._cooldown        = self.COOLDOWN_BASE
        self._consec_429      = 0
        self._consec_to       = 0
        self._consec_conn_err = 0

    def on_conn_error(self) -> bool:
        """Increment conn-error counter. Returns True when abort limit reached."""
        self._consec_conn_err += 1
        return self._consec_conn_err >= self.MAX_CONSEC_CONN_ERR

    def on_success(self):
        self._consec_429      = 0
        self._consec_to       = 0
        self._consec_conn_err = 0

    def on_timeout(self) -> bool:
        """Returns True if caller should give up on this domain."""
        self._consec_to += 1
        self._consec_429 = 0
        old = self.timeout
        self.timeout = min(self.timeout + self.TIMEOUT_STEP, self.TIMEOUT_MAX)
        if self.timeout != old:
            log.info("crt.sh adaptive: timeout raised %d s → %d s", old, self.timeout)
        if self._consec_to >= self.MAX_CONSEC_TO:
            log.warning(
                "crt.sh: %d consecutive timeouts — giving up on this domain",
                self._consec_to,
            )
            self._consec_to = 0
            return True
        return False

    def on_rate_limit(self, retry_after: str = "") -> float:
        self._consec_429 += 1
        self._consec_to   = 0
        try:
            hint = int(retry_after)
        except (ValueError, TypeError):
            hint = 0
        cooldown = min(max(hint, self._cooldown), self.COOLDOWN_MAX)
        self._cooldown = min(int(self._cooldown * self.COOLDOWN_MULT), self.COOLDOWN_MAX)
        old = self.inter_delay
        self.inter_delay = min(self.inter_delay + self.DELAY_STEP, self.DELAY_MAX)
        if self.inter_delay != old:
            log.info("crt.sh adaptive: inter-delay %.1f s → %.1f s", old, self.inter_delay)
        return float(cooldown)

    def backoff(self, attempt: int) -> float:
        base = min(2.0 ** attempt, 30.0)
        return base * (0.75 + random.random() * 0.50)

    def __str__(self):
        return (
            f"CrtShConfig(timeout={self.timeout}s, "
            f"inter_delay={self.inter_delay:.1f}s, "
            f"cooldown_base={self._cooldown}s)"
        )


_crtsh_cfg = CrtShConfig()

# ──────────────────────────────────────────────────────────────────────────────
# User-Agent rotation
# ──────────────────────────────────────────────────────────────────────────────
_UA_POOL = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; DomainDiscovery/2.0)",
]
_ua_cycle = itertools.cycle(_UA_POOL)

def _hdrs(json_accept: bool = False) -> dict:
    accept = "application/json, */*" if json_accept else "text/html,*/*"
    return {"User-Agent": next(_ua_cycle), "Accept": accept}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_roots(path: Path) -> List[str]:
    roots = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "://" in line:
            line = urlparse(line).hostname or line
        line = line.split("/")[0].split(":")[0].lower().strip()
        if line:
            roots.append(line)
    return sorted(set(roots))


def is_in_scope(host: str, roots: List[str]) -> bool:
    h = host.lower().rstrip(".")
    return any(h == r or h.endswith("." + r) for r in roots)


def normalise_host(name: str) -> str:
    return name.strip().lower().lstrip("*.")


def dns_resolves(host: str, timeout: int = 5) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def http_probe(session: requests.Session, url: str, timeout: int):
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return True, r.status_code, r.url
    except Exception:
        return False, 0, ""


def extract_links(base_url: str, html: str, roots: List[str]) -> Set[str]:
    links: Set[str] = set()
    try:
        soup = BeautifulSoup(html[:800_000], "html.parser")
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href") or ""
            full = urljoin(base_url, href)
            p = urlparse(full)
            if (
                p.scheme in ("http", "https")
                and p.hostname
                and is_in_scope(p.hostname, roots)
            ):
                links.add(f"{p.scheme}://{p.netloc}/")
    except Exception:
        pass
    return links


# ──────────────────────────────────────────────────────────────────────────────
# Local cache  — read existing output files on startup
# ──────────────────────────────────────────────────────────────────────────────
def load_cache(txt_path: Path, json_path: Path) -> Dict[str, DiscoveredEntry]:
    """
    Returns a dict keyed by URL from any previously saved output files.
    Merges both TXT (URL-only) and JSON (full metadata) if present.
    JSON takes precedence when both exist.
    """
    cache: Dict[str, DiscoveredEntry] = {}

    # Load from JSON first (richer)
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            for item in data:
                e = DiscoveredEntry(**{k: item.get(k, v) for k, v in asdict(DiscoveredEntry("","","")).items()})
                e.source = "cache"
                cache[e.url] = e
            log.info("Cache: loaded %d entries from %s", len(cache), json_path)
        except Exception as err:
            log.warning("Cache: could not read %s — %s", json_path, err)

    # Supplement with TXT for any URLs not in JSON
    if txt_path.exists():
        try:
            for line in txt_path.read_text(encoding="utf-8").splitlines():
                url = line.strip()
                if url and url not in cache:
                    p = urlparse(url)
                    host = p.hostname or url
                    cache[url] = DiscoveredEntry(
                        url=url, host=host, source="cache",
                        discovered_at="",
                    )
            log.info("Cache: %d total entries after merging %s", len(cache), txt_path)
        except Exception as err:
            log.warning("Cache: could not read %s — %s", txt_path, err)

    return cache


def cached_hosts(cache: Dict[str, DiscoveredEntry]) -> Set[str]:
    return {e.host for e in cache.values()}


# ──────────────────────────────────────────────────────────────────────────────
# Passive source 1: crt.sh
# ──────────────────────────────────────────────────────────────────────────────
# ── crt.sh endpoint pool ─────────────────────────────────────────────────────
# Primary:  standard JSON endpoint (paged by default, all records returned)
# Fallback: identity-search endpoint — hits a different DB replica on crt.sh
#           and is therefore useful when the primary returns 503
_CRTSH_ENDPOINTS = [
    "https://crt.sh/?q=%25.{domain}&output=json",
    "https://crt.sh/?identity=%25.{domain}&output=json",   # fallback replica
]


def _parse_crtsh_response(data: list, domain: str) -> Set[str]:
    """Extract unique in-scope hostnames from a crt.sh JSON response list."""
    hosts: Set[str] = set()
    for entry in data:
        for name in (entry.get("name_value") or "").splitlines():
            n = normalise_host(name)
            if n and is_in_scope(n, [domain]):
                hosts.add(n)
        cn = normalise_host(entry.get("common_name") or "")
        if cn and is_in_scope(cn, [domain]):
            hosts.add(cn)
    return hosts


def _try_crtsh_endpoint(url: str, domain: str, cfg: "CrtShConfig") -> tuple:
    """
    Try a single crt.sh endpoint URL.
    Returns (status, hosts_set) where status is one of:
      'ok'         – parsed successfully
      'not_found'  – 404, domain has no CT records → stop all retries
      'overloaded' – 503, server overloaded → try fallback endpoint
      'ratelimit'  – 429 → cool-down then retry same endpoint
      'error'      – any other HTTP error or parse error → retry
      'timeout'    – read timeout → adaptive timeout increase
      'conn_error' – connection-level failure → retry
    """
    try:
        r = requests.get(url, timeout=cfg.timeout, headers=_hdrs(json_accept=True))

        if r.status_code == 404:
            return "not_found", set()

        if r.status_code == 503:
            # 503 = server overloaded (different from 429 rate-limit).
            # Signal caller to switch to fallback endpoint after a short sleep.
            cooldown = cfg.on_rate_limit(r.headers.get("Retry-After", ""))
            log.warning(
                "crt.sh 503 for %s (overloaded) — sleeping %.0f s then trying fallback endpoint",
                domain, cooldown,
            )
            time.sleep(cooldown)
            return "overloaded", set()

        if r.status_code == 429:
            cooldown = cfg.on_rate_limit(r.headers.get("Retry-After", ""))
            log.warning(
                "crt.sh 429 for %s — cooling down %.0f s",
                domain, cooldown,
            )
            time.sleep(cooldown)
            return "ratelimit", set()

        if r.status_code != 200:
            log.warning("crt.sh HTTP %d for %s", r.status_code, domain)
            return "error", set()

        try:
            data = r.json()
        except requests.exceptions.JSONDecodeError:
            log.warning("crt.sh non-JSON response for %s", domain)
            return "error", set()

        return "ok", _parse_crtsh_response(data, domain)

    except requests.exceptions.ReadTimeout:
        return "timeout", set()
    except requests.exceptions.ConnectionError as e:
        log.warning("crt.sh connection error for %s: %s", domain, e)
        time.sleep(5)   # brief pause before caller decides whether to abort
        return "conn_error", set()
    except Exception as e:
        log.error("crt.sh unexpected error for %s: %s", domain, e)
        return "error", set()


def query_crtsh(domain: str) -> Set[str]:
    """
    Query crt.sh with automatic endpoint fallback and adaptive back-off.

    Endpoint strategy
    -----------------
    • Starts with the primary endpoint  (/?q=…&output=json)
    • On 503 (server overloaded) switches to the identity fallback endpoint
      (/?identity=…&output=json) which hits a different DB replica
    • On 404 stops immediately — no CT records exist for this domain
    • On 429 cools down and retries the current endpoint
    • On repeated timeouts (≥ MAX_CONSEC_TO) gives up early
    """
    cfg = _crtsh_cfg
    hosts: Set[str] = set()

    # endpoint_idx cycles through _CRTSH_ENDPOINTS on overload signals
    endpoint_idx = 0
    overload_switched = False   # track if we already switched once

    for attempt in range(cfg.RETRIES):
        if attempt > 0:
            wait = cfg.backoff(attempt - 1)
            log.debug(
                "crt.sh retry back-off %.1f s (attempt %d/%d) for %s",
                wait, attempt + 1, cfg.RETRIES, domain,
            )
            time.sleep(wait)

        url = _CRTSH_ENDPOINTS[endpoint_idx].format(domain=domain)
        status, found = _try_crtsh_endpoint(url, domain, cfg)

        if status == "not_found":
            log.info("crt.sh: no CT records for %s (404) — stopping", domain)
            return hosts

        if status == "ok":
            hosts |= found
            cfg.on_success()
            log.info(
                "crt.sh → %d host candidates for %s (endpoint %d)",
                len(hosts), domain, endpoint_idx,
            )
            time.sleep(cfg.inter_delay)
            return hosts

        if status == "overloaded":
            # Switch to the next endpoint in the pool (if available)
            next_idx = (endpoint_idx + 1) % len(_CRTSH_ENDPOINTS)
            if next_idx != endpoint_idx and not overload_switched:
                log.info(
                    "crt.sh 503 — switching endpoint %d → %d for %s",
                    endpoint_idx, next_idx, domain,
                )
                endpoint_idx = next_idx
                overload_switched = True
            else:
                log.warning(
                    "crt.sh 503 — no more fallback endpoints for %s; retrying same",
                    domain,
                )
            # Don't consume a retry slot for an overload switch
            continue

        if status == "timeout":
            if cfg.on_timeout():   # True → consecutive timeout cap reached
                return hosts
            log.warning(
                "crt.sh timeout for %s (attempt %d/%d) — timeout now %d s",
                domain, attempt + 1, cfg.RETRIES, cfg.timeout,
            )
            continue

        if status == "conn_error":
            if cfg.on_conn_error():
                log.warning(
                    "crt.sh: network unreachable for %s after %d consecutive errors — "
                    "skipping (check connectivity to crt.sh)",
                    domain, cfg.MAX_CONSEC_CONN_ERR,
                )
                return hosts
            log.debug("crt.sh conn_error %d/%d for %s — retrying",
                      cfg._consec_conn_err, cfg.MAX_CONSEC_CONN_ERR, domain)
            continue

        # ratelimit / error → just retry with back-off (already done above)

    log.error("crt.sh gave up on %s after %d attempts — %d partial results",
              domain, cfg.RETRIES, len(hosts))
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Passive source 2: HackerTarget
# ──────────────────────────────────────────────────────────────────────────────
def query_hackertarget(domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=timeout, headers=_hdrs())
        if r.status_code != 200:
            log.warning("HackerTarget HTTP %d for %s", r.status_code, domain)
            return hosts
        if "error" in r.text.lower() and len(r.text) < 200:
            log.info("HackerTarget: no data for %s (%s)", domain, r.text.strip())
            return hosts
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                n = normalise_host(parts[0])
                if n and is_in_scope(n, [domain]):
                    hosts.add(n)
        log.info("HackerTarget → %d hosts for %s", len(hosts), domain)
    except Exception as e:
        log.warning("HackerTarget error for %s: %s", domain, e)
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Passive source 3: AlienVault OTX  (with 429 back-off)
# ──────────────────────────────────────────────────────────────────────────────
_OTX_RETRIES        = 3
_OTX_COOLDOWN       = 60     # base cool-down on 429 (seconds); doubles each attempt
_OTX_MIN_INTERVAL   = 3.0    # minimum seconds between ANY two OTX requests
_OTX_MAX_429        = 5      # disable OTX for this session after N global 429s
# Global OTX throttle state
_otx_lock           = threading.Lock()
_otx_last_call      = 0.0    # epoch of last OTX request
_otx_429_count      = 0      # cumulative 429s across all domains
_otx_disabled       = False  # set True after _OTX_MAX_429 consecutive 429s

def query_otx(domain: str, timeout: int) -> Set[str]:
    """
    Query AlienVault OTX passive DNS.

    Rate-limit strategy:
      - Global lock: only one OTX request in-flight at a time.
      - Minimum 3 s gap between consecutive requests (preventive).
      - On 429: exponential back-off (60 / 120 / 180 s).
      - After _OTX_MAX_429 cumulative 429s: OTX disabled for this session.
    """
    global _otx_last_call, _otx_429_count, _otx_disabled

    hosts: Set[str] = set()

    if _otx_disabled:
        log.debug("OTX disabled for this session — skipping %s", domain)
        return hosts

    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")

    for attempt in range(1, _OTX_RETRIES + 1):

        if _otx_disabled:
            return hosts

        # ── Global throttle: enforce minimum inter-request gap ────────────────
        with _otx_lock:
            now = time.monotonic()
            gap = now - _otx_last_call
            if gap < _OTX_MIN_INTERVAL:
                time.sleep(_OTX_MIN_INTERVAL - gap)
            _otx_last_call = time.monotonic()

        try:
            r = requests.get(url, timeout=timeout, headers=_hdrs(json_accept=True))

            # ── 429 handling ──────────────────────────────────────────────────
            if r.status_code == 429:
                with _otx_lock:
                    _otx_429_count += 1
                    count = _otx_429_count
                    if count >= _OTX_MAX_429:
                        _otx_disabled = True

                if _otx_disabled:
                    log.warning(
                        "OTX disabled after %d cumulative 429s — "
                        "will skip remaining domains. Use --skip-otx to suppress.",
                        count,
                    )
                    return hosts

                # Exponential back-off: honour Retry-After if provided
                retry_after = int(r.headers.get("Retry-After", 0))
                cooldown    = max(retry_after, _OTX_COOLDOWN * attempt)
                log.warning(
                    "OTX 429 for %s — cooling down %d s "
                    "(attempt %d/%d, cumulative 429s: %d)",
                    domain, cooldown, attempt, _OTX_RETRIES, count,
                )
                time.sleep(cooldown)
                continue

            if r.status_code != 200:
                log.debug("OTX HTTP %d for %s — skipping", r.status_code, domain)
                return hosts

            # ── Parse results ─────────────────────────────────────────────────
            data = r.json()
            for rec in data.get("passive_dns", []):
                n = normalise_host(rec.get("hostname", ""))
                if n and is_in_scope(n, [domain]):
                    hosts.add(n)
            log.info("OTX → %d hosts for %s", len(hosts), domain)
            return hosts

        except requests.exceptions.ReadTimeout:
            log.warning("OTX timeout for %s (attempt %d/%d)", domain, attempt, _OTX_RETRIES)
        except Exception as e:
            log.warning("OTX error for %s: %s", domain, e)
            return hosts

    log.warning("OTX gave up on %s after %d attempts", domain, _OTX_RETRIES)
    return hosts

# ──────────────────────────────────────────────────────────────────────────────
# Passive source 4: RapidDNS
# ──────────────────────────────────────────────────────────────────────────────
def query_rapiddns(domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = requests.get(url, timeout=timeout, headers=_hdrs())
        if r.status_code != 200:
            log.warning("RapidDNS HTTP %d for %s", r.status_code, domain)
            return hosts
        # Extract from HTML table
        soup = BeautifulSoup(r.text, "html.parser")
        for td in soup.find_all("td"):
            text = td.get_text(strip=True).lower()
            if text.endswith("." + domain) or text == domain:
                n = normalise_host(text)
                if n and is_in_scope(n, [domain]):
                    hosts.add(n)
        log.info("RapidDNS → %d hosts for %s", len(hosts), domain)
    except Exception as e:
        log.warning("RapidDNS error for %s: %s", domain, e)
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Passive source 5: AnubisDB  (replaces defunct ThreatCrowd)
# https://jldc.me/anubis/subdomains/<domain>
# Free, no API key, returns JSON array of subdomains
# ──────────────────────────────────────────────────────────────────────────────
def query_anubisdb(domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        r = requests.get(url, timeout=timeout, headers=_hdrs(json_accept=True))
        if r.status_code != 200:
            log.warning("AnubisDB HTTP %d for %s", r.status_code, domain)
            return hosts
        data = r.json()
        if isinstance(data, list):
            for item in data:
                n = normalise_host(str(item))
                if n and is_in_scope(n, [domain]):
                    hosts.add(n)
        log.info("AnubisDB → %d hosts for %s", len(hosts), domain)
    except Exception as e:
        log.warning("AnubisDB error for %s: %s", domain, e)
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Passive source 6: BufferOver (Riddler / DNS bufferover)
# ──────────────────────────────────────────────────────────────────────────────
def query_bufferover(domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        r = requests.get(url, timeout=timeout, headers=_hdrs(json_accept=True))
        if r.status_code != 200:
            return hosts
        data = r.json()
        for record in data.get("FDNS_A", []) + data.get("RDNS", []):
            # format: "IP,hostname"
            parts = str(record).split(",")
            for part in parts:
                n = normalise_host(part)
                if n and is_in_scope(n, [domain]):
                    hosts.add(n)
        log.info("BufferOver → %d hosts for %s", len(hosts), domain)
    except Exception as e:
        log.debug("BufferOver error for %s: %s", domain, e)
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Aggregate all passive sources for one domain
# ──────────────────────────────────────────────────────────────────────────────
def passive_enumerate(domain: str, timeout: int) -> Set[str]:
    """Run all passive sources and merge results."""
    hosts: Set[str] = set()

    # crt.sh is sequential and rate-limited internally
    hosts |= query_crtsh(domain)

    # Other sources can run concurrently
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        futs = {
            ex.submit(query_hackertarget, domain, timeout): "hackertarget",
            ex.submit(query_rapiddns,     domain, timeout): "rapiddns",
            ex.submit(query_anubisdb,     domain, timeout): "anubisdb",
            ex.submit(query_bufferover,   domain, timeout): "bufferover",
        }
        for fut in cf.as_completed(futs):
            src = futs[fut]
            try:
                hosts |= fut.result()
            except Exception as e:
                log.warning("Source %s error for %s: %s", src, domain, e)

    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Host probe  (DNS + HTTP + optional HTML crawl)
# ──────────────────────────────────────────────────────────────────────────────
def probe_host(
    host:    str,
    timeout: int,
    crawl:   bool,
    roots:   List[str],
    session: requests.Session,
    source:  str = "passive",
) -> List[DiscoveredEntry]:
    entries: List[DiscoveredEntry] = []
    now = dt.datetime.now(dt.timezone.utc).isoformat()

    if not dns_resolves(host, timeout):
        entries.append(DiscoveredEntry(
            url=f"https://{host}/", host=host, source=source,
            resolves=False, discovered_at=now,
        ))
        return entries

    extra: Set[str] = set()
    for scheme in ("https", "http"):
        base_url = f"{scheme}://{host}/"
        alive, status, final = http_probe(session, base_url, timeout)
        redirect = final if final and final != base_url else ""
        entries.append(DiscoveredEntry(
            url=base_url, host=host, source=source,
            resolves=True, http_alive=alive,
            http_status=status, redirect_to=redirect,
            discovered_at=now,
        ))
        if crawl and alive:
            try:
                r = session.get(base_url, timeout=timeout, verify=False, allow_redirects=True)
                for link in extract_links(r.url, r.text, roots):
                    extra.add(link)
            except Exception:
                pass
        if alive and scheme == "https":
            break

    for link_url in extra:
        h = urlparse(link_url).hostname or ""
        if h and h != host:
            entries.append(DiscoveredEntry(
                url=link_url, host=h, source="html_crawl",
                resolves=False, discovered_at=now,
            ))
    return entries


# ──────────────────────────────────────────────────────────────────────────────
# Orchestration
# ──────────────────────────────────────────────────────────────────────────────
def discover(
    roots:      List[str],
    threads:    int,
    timeout:    int,
    skip_crawl: bool,
    cache:      Dict[str, DiscoveredEntry],
) -> Dict[str, DiscoveredEntry]:
    """
    Returns the merged dict of ALL entries (cache + new), keyed by URL.
    """
    known_hosts = cached_hosts(cache)
    merged: Dict[str, DiscoveredEntry] = dict(cache)   # start from cache

    # ── Step 1: passive enumeration per root ─────────────────────────────────
    all_new_hosts: Set[str] = set(roots)
    log.info("Running passive enumeration for %d root domain(s)…", len(roots))
    for root in roots:
        discovered = passive_enumerate(root, timeout)
        new_for_root = discovered - known_hosts
        skipped = len(discovered) - len(new_for_root)
        if skipped:
            log.info("Skipped %d already-cached hosts for %s", skipped, root)
        all_new_hosts |= new_for_root

    new_to_probe = all_new_hosts - known_hosts
    log.info(
        "New host candidates to probe: %d  (cached/skipped: %d)",
        len(new_to_probe), len(known_hosts),
    )

    if not new_to_probe:
        log.info("No new hosts found — cache is up to date.")
        return merged

    # ── Step 2: DNS + HTTP probe ──────────────────────────────────────────────
    log.info("Probing new hosts (DNS+HTTP, crawl=%s, threads=%d)…", not skip_crawl, threads)
    session = requests.Session()
    session.headers.update({"User-Agent": _UA_POOL[0]})
    adapter = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    secondary: Set[str] = set()

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {
            ex.submit(probe_host, h, timeout, not skip_crawl, roots, session, "passive"): h
            for h in sorted(new_to_probe)
        }
        for fut in cf.as_completed(futs):
            try:
                for e in fut.result():
                    if e.url not in merged:
                        merged[e.url] = e
                    if e.source == "html_crawl" and e.host not in known_hosts and e.host not in new_to_probe:
                        secondary.add(e.host)
            except Exception as err:
                log.error("probe error: %s", err)

    # ── Step 3: probe secondary HTML-discovered hosts ─────────────────────────
    secondary -= known_hosts
    secondary -= new_to_probe
    if secondary and not skip_crawl:
        log.info("Probing %d secondary HTML-crawl hosts…", len(secondary))
        with cf.ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {
                ex.submit(probe_host, h, timeout, False, roots, session, "html_crawl"): h
                for h in sorted(secondary)
            }
            for fut in cf.as_completed(futs):
                try:
                    for e in fut.result():
                        if e.url not in merged:
                            merged[e.url] = e
                except Exception as err:
                    log.error("secondary probe error: %s", err)

    alive = sum(1 for e in merged.values() if e.http_alive)
    log.info(
        "Discovery complete — %d total URLs (%d alive, %d cached).",
        len(merged), alive, len(cache),
    )
    return merged


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────
def _to_https(url: str) -> str:
    """
    Rewrite an http:// URL to https://.
    Preserves host, port (dropping :80 when upgrading to https:443),
    path, and query.  Non-http schemes are returned unchanged.
    """
    if not url.startswith("http://"):
        return url
    p = urlparse(url)
    # Drop port 80 (standard HTTP); keep any other explicit port
    netloc = p.hostname or ""
    if p.port and p.port != 80:
        netloc = f"{netloc}:{p.port}"
    upgraded = urlunparse(("https", netloc, p.path or "/", p.params, p.query, ""))
    return upgraded


def write_txt(entries: Dict[str, DiscoveredEntry], path: Path) -> None:
    """
    Write discovered URLs to a text file — one per line, HTTPS only.

    Strategy:
    • For every host, prefer the https:// URL if one exists.
    • If only an http:// URL exists (https probes all failed), upgrade it to
      https:// anyway — certmon will probe it and report it as unreachable /
      no_ssl if https truly is not available.
    • Deduplicate after normalisation (e.g. http://host/ and https://host/
      both resolve to https://host/).
    """
    seen_https: set = set()
    ordered: list  = []

    # Pass 1 — collect https:// entries directly
    for url in sorted(entries.keys()):
        if url.startswith("https://"):
            seen_https.add(url)
            ordered.append(url)

    # Pass 2 — upgrade http:// entries that have no https counterpart
    for url in sorted(entries.keys()):
        if url.startswith("http://"):
            upgraded = _to_https(url)
            if upgraded not in seen_https:
                seen_https.add(upgraded)
                ordered.append(upgraded)
                log.debug("Upgraded http→https for output: %s → %s", url, upgraded)

    final = sorted(set(ordered))
    path.write_text("\n".join(final) + "\n", encoding="utf-8")
    log.info("Saved %d HTTPS URLs → %s", len(final), path)


def write_json(entries: Dict[str, DiscoveredEntry], path: Path) -> None:
    results = sorted(entries.values(), key=lambda e: (e.host, e.url))
    path.write_text(
        json.dumps([asdict(e) for e in results], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("Saved metadata → %s", path)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Discover subdomains/URLs via CT logs + passive DNS sources.\n"
            "Automatically skips hosts already present in local cache files."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input",     required=True,
                   help="TXT file with root domains, one per line")
    p.add_argument("-o", "--output",    default="discovered_urls.txt",
                   help="Output TXT file (one URL per line) — also used as cache")
    p.add_argument("--json-output",     default="discovered_urls.json",
                   help="Output JSON with full metadata — also used as cache")
    p.add_argument("--threads",         type=int, default=20,
                   help="Concurrent threads for DNS/HTTP probing")
    p.add_argument("--timeout",         type=int, default=10,
                   help="Timeout (s) for DNS/HTTP probes and non-crt.sh sources")
    p.add_argument("--skip-crawl",      action="store_true",
                   help="Skip HTML link extraction")
    p.add_argument("--no-cache",        action="store_true",
                   help="Ignore existing output files; re-probe everything")
    p.add_argument("--skip-otx",  action="store_true",
                   help="Disable AlienVault OTX entirely (avoids 429 on large scans)")
    p.add_argument("-v", "--verbose",   action="store_true",
                   help="Enable DEBUG logging")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    input_path = Path(args.input)
    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    global _otx_disabled
    if getattr(args, "skip_otx", False):
        _otx_disabled = True
        log.info("OTX disabled via --skip-otx")

    roots = load_roots(input_path)
    if not roots:
        log.error("No valid domains found in %s", input_path)
        sys.exit(1)

    out_txt  = Path(args.output)
    out_json = Path(args.json_output)
    out_txt.parent.mkdir(parents=True, exist_ok=True)

    # ── Load local cache ──────────────────────────────────────────────────────
    if args.no_cache:
        cache: Dict[str, DiscoveredEntry] = {}
        log.info("--no-cache: ignoring existing output files")
    else:
        cache = load_cache(out_txt, out_json)

    log.info("Loaded %d root domain(s): %s", len(roots), ", ".join(roots))
    log.info("crt.sh config: %s", _crtsh_cfg)

    # ── Discover ──────────────────────────────────────────────────────────────
    merged = discover(
        roots      = roots,
        threads    = args.threads,
        timeout    = args.timeout,
        skip_crawl = args.skip_crawl,
        cache      = cache,
    )

    # ── Save ──────────────────────────────────────────────────────────────────
    write_txt(merged,  out_txt)
    write_json(merged, out_json)

    alive = sum(1 for e in merged.values() if e.http_alive)
    print(json.dumps({
        "roots":        len(roots),
        "total_urls":   len(merged),
        "http_alive":   alive,
        "cached":       len(cache),
        "new":          len(merged) - len(cache),
        "output_txt":   str(out_txt),
        "output_json":  str(out_json),
    }, indent=2))


if __name__ == "__main__":
    main()
