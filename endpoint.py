### FIXED
# This file contains the code for the endpoint of the server.
# It is used to handle the requests from the client and to send the responses to the client.
# It is also used to handle the data from the database and to send the data to the client.
# It is also used to handle the data from the cache and to send the data to the client.
# It is also used to handle the data from the proxy and to send the data to the client.
# It is also used to handle the data from the gmail and to send the data to the client.
# It is also used to handle the data from the tk and to send the data to the client.
# It is also used to handle the data from the hunt and to send the data to the client.


import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import logging
import platform
import re
import secrets
import sys
import time
import threading
import queue
import random
import string
import json
import uuid
import base64
import html
import os
import socket
from contextlib import asynccontextmanager
from datetime import datetime, timezone

COLOR_SUPPORT = sys.stdout.isatty()
ANSI_RESET = "\033[0m"
ANSI_CYAN = "\033[96m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_DIM = "\033[2m"
ANSI_BOLD = "\033[1m"
ANSI_MAGENTA = "\033[95m"
ANSI_BLUE = "\033[94m"


def apply_color(text, color):
    if COLOR_SUPPORT:
        return f"{color}{text}{ANSI_RESET}"
    return text


def _is_termux():
    # Match joint.py — PREFIX catches Termux when TERMUX_VERSION is unset.
    return bool(os.environ.get("TERMUX_VERSION")) or (
        (os.environ.get("PREFIX") or "").startswith("/data/data/com.termux")
    )


def _env_thread_slots(default):
    """Match joint.py — export JACK_THREADS=N before starting both processes."""
    raw = os.environ.get("JACK_THREADS", "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def render_missing_deps_error(exc):
    """Print before any banner — user must see why the gateway did not start."""
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    print()
    print(apply_color("  ┌─ DEPENDENCY ERROR ─────────────────────────────────────────┐", ANSI_RED))
    print(apply_color("  │  endpoint.py cannot start — required packages are missing. │", ANSI_RED))
    print(apply_color("  └────────────────────────────────────────────────────────────┘", ANSI_RED))
    print()
    print(apply_color(f"  Python: {sys.executable} ({py})", ANSI_DIM))
    print(apply_color(f"  Reason: {exc}", ANSI_YELLOW))
    print()
    if _is_termux():
        print(apply_color("  Termux (Android) — do NOT run only:", ANSI_CYAN))
        print(apply_color("    pip install -r requirements.txt", ANSI_DIM))
        print(apply_color("  That tries to compile pydantic-core and fails.", ANSI_DIM))
        print()
        print(apply_color("  Run instead:", ANSI_GREEN))
        print(apply_color("    bash install-termux.sh", ANSI_CYAN))
        print(apply_color("  Or:", ANSI_DIM))
        print(
            apply_color(
                "    pip install pydantic-core --extra-index-url "
                "https://eutalix.github.io/android-pydantic-core/ --break-system-packages",
                ANSI_CYAN,
            )
        )
        print(apply_color("    pip install -r requirements-termux.txt --break-system-packages", ANSI_CYAN))
    else:
        print(apply_color("  Install:", ANSI_GREEN))
        print(apply_color("    pip install -r requirements.txt", ANSI_CYAN))
        print(apply_color("  Or: pip install fastapi uvicorn requests pydantic", ANSI_DIM))
    print()
    print(apply_color("  Then verify:", ANSI_DIM))
    print(apply_color('    python -c "import fastapi, uvicorn, pydantic; print(\'ok\')"', ANSI_CYAN))
    print()


def _import_server_stack():
    try:
        import pydantic  # noqa: F401
    except ImportError as exc:
        render_missing_deps_error(exc)
        raise SystemExit(1) from exc
    try:
        import pydantic_core  # noqa: F401
    except ImportError as exc:
        render_missing_deps_error(
            ImportError(
                "pydantic_core is not installed (FastAPI needs it). "
                "On Termux use install-termux.sh — see message above."
            )
        )
        raise SystemExit(1) from exc
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError as exc:
        render_missing_deps_error(exc)
        raise SystemExit(1) from exc
    return FastAPI, Request, JSONResponse, uvicorn


FastAPI, Request, JSONResponse, uvicorn = _import_server_stack()

import requests
from requests import post as pp
from requests.adapters import HTTPAdapter

try:
    from vps_proxies import (
        vps_proxy_enabled,
        is_instagram_url,
        proxy_attempts,
        proxy_mark_bad,
        proxy_http_status_retry,
        get_proxy_pool,
    )
except ImportError:
    def vps_proxy_enabled():
        return False

    def is_instagram_url(url):
        return "instagram.com" in (url or "")

    def proxy_attempts(**_kw):
        yield None

    def proxy_mark_bad(_proxies):
        return None

    def proxy_http_status_retry(status):
        return int(status or 0) in (429, 502, 503, 504)

    def get_proxy_pool():
        return None

_VPS_PROXY_TRIES = 12


def _ig_http_post(url, *, data=None, headers=None, timeout=None, cookies=None, params=None, http=None):
    use_proxy = vps_proxy_enabled() and is_instagram_url(url)
    attempts = list(proxy_attempts(proxy_tries=_VPS_PROXY_TRIES)) if use_proxy else [None]
    last_exc = None
    for proxies in attempts:
        try:
            kw = {
                "data": data,
                "headers": headers,
                "timeout": timeout,
                "cookies": cookies,
                "params": params,
            }
            if proxies:
                kw["proxies"] = proxies
            if http is not None:
                resp = http.post(url, **kw)
            else:
                resp = requests.post(url, **kw)
            if proxies and proxy_http_status_retry(getattr(resp, "status_code", 0)):
                proxy_mark_bad(proxies)
                continue
            return resp
        except Exception as exc:
            last_exc = exc
            if proxies:
                proxy_mark_bad(proxies)
            continue
    if last_exc is not None:
        raise last_exc
    return requests.post(
        url,
        data=data,
        headers=headers,
        timeout=timeout,
        cookies=cookies,
        params=params,
    )


def _ig_http_get(url, *, headers=None, timeout=None, cookies=None, params=None, http=None):
    use_proxy = vps_proxy_enabled() and is_instagram_url(url)
    attempts = list(proxy_attempts(proxy_tries=_VPS_PROXY_TRIES)) if use_proxy else [None]
    last_exc = None
    for proxies in attempts:
        try:
            kw = {
                "headers": headers,
                "timeout": timeout,
                "cookies": cookies,
                "params": params,
            }
            if proxies:
                kw["proxies"] = proxies
            if http is not None:
                resp = http.get(url, **kw)
            else:
                resp = requests.get(url, **kw)
            if proxies and proxy_http_status_retry(getattr(resp, "status_code", 0)):
                proxy_mark_bad(proxies)
                continue
            return resp
        except Exception as exc:
            last_exc = exc
            if proxies:
                proxy_mark_bad(proxies)
            continue
    if last_exc is not None:
        raise last_exc
    return requests.get(
        url,
        headers=headers,
        timeout=timeout,
        cookies=cookies,
        params=params,
    )

# ═══ SUPABASE — same creds as joint.py ═══
SUPABASE_URL = "https://pqlchnzcgramceqrsfrn.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBxbGNobnpjZ3JhbWNlcXJzZnJuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkyNTQ4NTcsImV4cCI6MjA5NDgzMDg1N30.enm6Sz8d5o5Fvgn3FsKMf2dLFtOggGL-mhVBDx853BM"

API_PORT = 5001
CLOUD_TIMEOUT = 12
# Gateway profiles — desktop aggressive; Termux light (phone CPU + VPN rotate).
_IS_TERMUX = _is_termux()
if _IS_TERMUX:
    GATEWAY_PROFILE = "termux"
    INSTAGRAM_HTTP_TIMEOUT = 30
    # Buffer fill 3× vs prior Termux tune (48 fillers → 144); watch errors if VPN rotates hard.
    IG_GEN_PARALLEL_WORKERS = 48
    IG_GEN_BUFFER_SIZE = 288
    IG_GEN_BUFFER_FILL_WORKERS = 144
    IG_GEN_BUFFER_LOW_WATER = 120
    IG_GEN_BUFFER_FULL_SLEEP = 0.014
    IG_GEN_FAIL_SLEEP = 0.01
    IG_GEN_FAIL_SLEEP_LOW = 0.004
    IG_GEN_ONCE_INNER_TRIES = 8
    IG_GEN_PREFILL_BATCH = 96
    IG_GEN_FILL_ATTEMPTS = 14
    IG_GEN_SERVE_ATTEMPTS = 12
    IG_GEN_SERVE_INNER_ATTEMPTS = 8
    GEN_IG_MAX_ATTEMPTS = 32
    HUNT_LOOKUP_TIMEOUT = 30
    HUNT_CYCLE_MAX_CONCURRENT = min(_env_thread_slots(32), 32)
    HUNT_CYCLE_LOOKUP_BUDGET = 50.0
    HUNT_GEN_BUDGET = 12.0
    _HUNT_LOOKUP_CONNECT = 4
    IG_HTTP_POOL_SIZE = 216
else:
    GATEWAY_PROFILE = "desktop"
    INSTAGRAM_HTTP_TIMEOUT = 12
    IG_GEN_PARALLEL_WORKERS = 300
    IG_GEN_BUFFER_SIZE = 1920
    IG_GEN_BUFFER_FILL_WORKERS = 360
    IG_GEN_BUFFER_LOW_WATER = 360
    IG_GEN_BUFFER_FULL_SLEEP = 0.002
    IG_GEN_FAIL_SLEEP = 0.0007
    IG_GEN_FAIL_SLEEP_LOW = 0.00025
    IG_GEN_ONCE_INNER_TRIES = 10
    IG_GEN_PREFILL_BATCH = 360
    IG_GEN_FILL_ATTEMPTS = 18
    IG_GEN_SERVE_ATTEMPTS = 20
    IG_GEN_SERVE_INNER_ATTEMPTS = 12
    GEN_IG_MAX_ATTEMPTS = 40
    HUNT_LOOKUP_TIMEOUT = 20
    HUNT_CYCLE_MAX_CONCURRENT = min(_env_thread_slots(40), 40)
    HUNT_CYCLE_LOOKUP_BUDGET = 45.0
    HUNT_GEN_BUDGET = 10.0
    _HUNT_LOOKUP_CONNECT = 3
    IG_HTTP_POOL_SIZE = 960
GMAIL_TL_CACHE_SEC = 300
GMAIL_TL_REFRESH_EARLY_SEC = 60
GMAIL_LOOKUP_MAX_ATTEMPTS = 5
_GMAIL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
_HUNT_GMAIL_MAX_ATTEMPTS = 5 if _IS_TERMUX else 3
TK_CACHE_SEC = 60
IG_GEN_WARM_MINS = ("10",)
IG_GEN_THREAD_POOL_SIZE = IG_GEN_BUFFER_FILL_WORKERS + IG_GEN_PARALLEL_WORKERS + 32
# IG gen: random user_id → PolarisProfilePageContentQuery graphql (sinsta-style).
_IG_GEN_GRAPHQL_DOC_ID = "26672929172408668"
_IG_GEN_USER_ID_MIN = 2_500_000_000
_IG_GEN_USER_ID_MAX = 21_254_029_834
# Single uvicorn worker — multi-worker duplicates buffers and kills pending tasks on exit.
UVICORN_WORKERS = 1

_IG_WEB_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
)
_LSD_TOKEN_RE = re.compile(r'"LSD",\[\],\{"token":"([^"]+)"')
_ig_gen_block_until = 0.0
_ig_lookup_block_until = 0.0
_ig_block_lock = threading.Lock()
# Hunt lookups spam 429 → must not freeze username buffer / graphql gen.
_IG_BLOCK_REMARK_MIN_LEFT = 2.5
_IG_BLOCK_COOLDOWN_GEN = 10 if _IS_TERMUX else 7
_IG_BLOCK_COOLDOWN_LOOKUP = 8 if _IS_TERMUX else 5
HUNT_LOOKUP_MAX_CONCURRENT = 32 if _IS_TERMUX else 40
_gmail_tl_cond = threading.Condition()
_gmail_tl_cache = {"payload": None, "at": 0.0}
_gmail_tl_refreshing = False
_gmail_maintainer_started = False
_tk_cache = {"csrf": None, "lsd": None, "at": 0.0}
_tk_lock = threading.Lock()
_hunt_cycle_sem = asyncio.Semaphore(HUNT_CYCLE_MAX_CONCURRENT)
_hunt_lookup_sem = asyncio.Semaphore(HUNT_LOOKUP_MAX_CONCURRENT)
_ig_gen_serve_sem = asyncio.Semaphore(max(8, HUNT_CYCLE_MAX_CONCURRENT * 2))
_alive_snapshot_lock = threading.Lock()
_alive_snapshot = {"at": 0.0, "payload": None}
_profile_fetch_sem = asyncio.Semaphore(2)
_recovery_sem = asyncio.Semaphore(1 if _IS_TERMUX else 2)
_HUNT_IG_GRAPHQL_DOC_ID = "35299094813070532"
_HUNT_IG_RESET_URL = "https://www.instagram.com/accounts/password/reset/"
_HUNT_IG_GRAPHQL_URL = "https://www.instagram.com/api/graphql"
_HUNT_IG_NO_ACCOUNT_RE = re.compile(
    r"no account found|couldn.?t find|user not found|doesn.?t match",
    re.I,
)
_HUNT_BLOKS_SCAN_MAX = 400000
# Miss bloks bodies are ~41KB; hits are ~400KB+. Stop streaming once miss size is exceeded.
_HUNT_BLOKS_MISS_CEILING = 48000
_HUNT_MOBILE_CHECK_EMAIL_URL = "https://i.instagram.com/api/v1/users/check_email/"
# Competitor-style minimal check_email — old UA, tiny body (~1–3s vs full mobile headers).
_HUNT_CHECK_EMAIL_FAST_UA = (
    "Instagram 166.0.0.30.120 Android (30/11; 1440dpi; 2560x1440; "
    "samsung; SM-G973F; x86_64; tablet; en_US; kirin)"
)
_HUNT_CHECK_EMAIL_FAST_TIMEOUT = (3, 8)
_HUNT_MOBILE_ASSISTED_RECOVERY_URL = (
    "https://i.instagram.com/api/v1/accounts/assisted_account_recovery/"
)
_IG_MOBILE_UA = (
    "Instagram 370.1.0.43.96 Android (34/14; 450dpi; 1080x2207; "
    "samsung; SM-A235F; a23; qcom; en_IN; 704872281)"
)
_IG_MOBILE_APP_ID = "567067343352427"
_PROFILE_WEB_URL = "https://i.instagram.com/api/v1/users/web_profile_info/"
_PROFILE_MEDIA_EDGE_RE = re.compile(
    r'"edge_owner_to_timeline_media"\s*:\s*\{\s*"count"\s*:\s*(\d+)',
    re.I,
)
_PROFILE_MEDIA_COUNT_RE = re.compile(r'"media_count"\s*:\s*(\d+)', re.I)

goodig = 0
badig = 0
sess = requests.session()
session = requests.session()
_ig_http_adapter = HTTPAdapter(
    pool_connections=IG_HTTP_POOL_SIZE,
    pool_maxsize=IG_HTTP_POOL_SIZE,
    max_retries=0,
)
session.mount("https://", _ig_http_adapter)
session.mount("http://", _ig_http_adapter)
_ig_graphql_local = threading.local()
_hunt_http_local = threading.local()


def _get_hunt_http_session():
    """Per-thread keep-alive for ig_lookup + gmail during hunt_cycle."""
    http = getattr(_hunt_http_local, "session", None)
    if http is None:
        http = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=3,
            pool_maxsize=3,
            max_retries=0,
        )
        http.mount("https://", adapter)
        http.mount("http://", adapter)
        _hunt_http_local.session = http
    return http


def _get_hunt_curl_session():
    """curl_cffi for hunt IG/Gmail — Termux only; desktop uses requests (curl+threads crashes)."""
    if not _IS_TERMUX:
        return None
    http = getattr(_hunt_http_local, "curl_session", None)
    if http is None:
        try:
            from curl_cffi import requests as curl_requests
        except ImportError:
            return None
        http = curl_requests.Session(impersonate="chrome131_android")
        _hunt_http_local.curl_session = http
    return http


def _hunt_lookup_timeout():
    return (_HUNT_LOOKUP_CONNECT, HUNT_LOOKUP_TIMEOUT)


def _google_accounts_request(method, url, *, headers, timeout, cookies=None, data=None, params=None):
    """Token/signup calls — Termux uses curl_cffi Android impersonation."""
    if _IS_TERMUX:
        try:
            from curl_cffi import requests as curl_requests
            http = curl_requests.Session(impersonate="chrome131_android")
            fn = http.post if method.upper() == "POST" else http.get
            return fn(
                url,
                headers=headers,
                timeout=timeout,
                cookies=cookies,
                data=data,
                params=params,
            )
        except Exception:
            pass
    fn = requests.post if method.upper() == "POST" else requests.get
    return fn(
        url,
        headers=headers,
        timeout=timeout,
        cookies=cookies,
        data=data,
        params=params,
    )


def _hunt_http_post(url, *, data, headers, timeout, cookies=None, params=None):
    if vps_proxy_enabled() and is_instagram_url(url):
        for proxies in proxy_attempts(proxy_tries=_VPS_PROXY_TRIES):
            curl_http = _get_hunt_curl_session()
            try:
                kw = {
                    "data": data,
                    "headers": headers,
                    "timeout": timeout,
                    "cookies": cookies,
                    "params": params,
                }
                if proxies:
                    kw["proxies"] = proxies
                if curl_http is not None:
                    resp = curl_http.post(url, **kw)
                else:
                    resp = _get_hunt_http_session().post(url, **kw)
                if proxies and proxy_http_status_retry(getattr(resp, "status_code", 0)):
                    proxy_mark_bad(proxies)
                    continue
                return resp
            except Exception:
                if proxies:
                    proxy_mark_bad(proxies)
                continue
        return _get_hunt_http_session().post(
            url,
            data=data,
            headers=headers,
            timeout=timeout,
            cookies=cookies,
            params=params,
        )
    curl_http = _get_hunt_curl_session()
    if curl_http is not None:
        try:
            return curl_http.post(
                url,
                data=data,
                headers=headers,
                timeout=timeout,
                cookies=cookies,
                params=params,
            )
        except Exception:
            pass
    return _get_hunt_http_session().post(
        url,
        data=data,
        headers=headers,
        timeout=timeout,
        cookies=cookies,
        params=params,
    )


def _hunt_http_post_scan(url, *, data, headers, timeout, hit_needle, cookies=None, params=None):
    """Chunked POST — abort download once IG hit/miss/rate-limit is known."""
    hit_b = (hit_needle or "").encode("utf-8", errors="ignore")
    neg_markers = (
        b"no account found",
        b"couldn't find",
        b"user not found",
        b"rate limit",
        b"please try again later",
    )
    pos_markers = (
        b"sent a code to",
        b"sent you an email",
        b"email sent for recovery",
        b"get back into your account",
    )

    def _scan_one(http, proxies=None):
        kw = {
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "cookies": cookies,
            "params": params,
            "stream": True,
        }
        if proxies:
            kw["proxies"] = proxies
        resp = http.post(url, **kw)
        code = int(getattr(resp, "status_code", 0) or 0)
        try:
            if code == 429:
                return code, "rate_limited"
            buf = bytearray()
            stream_fn = getattr(resp, "iter_content", None)
            if callable(stream_fn):
                for chunk in stream_fn(chunk_size=65536):
                    if not chunk:
                        continue
                    buf.extend(chunk)
                    if hit_b and hit_b in buf:
                        return code, "hit"
                    low = bytes(buf).lower()
                    if any(marker in low for marker in pos_markers):
                        return code, "hit"
                    if any(marker in low for marker in neg_markers):
                        if b"rate limit" in low or b"please try again later" in low:
                            return code, "rate_limited"
                        return code, "miss"
                    if len(buf) >= _HUNT_BLOKS_MISS_CEILING and not (
                        hit_b and hit_b in buf
                    ):
                        return code, "miss"
                    if len(buf) > _HUNT_BLOKS_SCAN_MAX:
                        break
            else:
                buf.extend(resp.content or b"")
            low = bytes(buf).lower()
            if hit_b and hit_b in buf:
                return code, "hit"
            if any(marker in low for marker in pos_markers):
                return code, "hit"
            if b"rate limit" in low or b"please try again later" in low:
                return code, "rate_limited"
            return code, "miss"
        finally:
            try:
                resp.close()
            except Exception:
                pass

    attempts = (
        list(proxy_attempts(proxy_tries=_VPS_PROXY_TRIES))
        if vps_proxy_enabled() and is_instagram_url(url)
        else [None]
    )
    # M1 bloks scan: requests only — curl_cffi stream+abort corrupts heap under parallel load.
    clients = [_get_hunt_http_session()]
    for proxies in attempts:
        for http in clients:
            try:
                return _scan_one(http, proxies)
            except Exception:
                if proxies:
                    proxy_mark_bad(proxies)
                continue
    return 0, "error"


def _warm_hunt_lookup_thread():
    """Per-thread TLS warmup — first lookup skips cold-handshake penalty."""
    if getattr(_hunt_http_local, "warmed", False):
        return
    _hunt_http_local.warmed = True
    _hunt_ig_device_ctx()
    try:
        load(force_refresh=False)
    except Exception:
        pass
    try:
        _gmail_token_parts(force_tl=False)
    except Exception:
        pass
    warmup_urls = (
        "https://www.instagram.com/",
        "https://i.instagram.com/",
        "https://accounts.google.com/",
    )
    timeout = (2, 5) if _IS_TERMUX else (2, 4)
    curl_http = _get_hunt_curl_session()
    for url in warmup_urls:
        try:
            if vps_proxy_enabled() and is_instagram_url(url):
                _ig_http_get(url, timeout=timeout)
                continue
            if curl_http is not None:
                curl_http.get(url, timeout=timeout)
            else:
                _get_hunt_http_session().get(url, timeout=timeout)
        except Exception:
            pass


def _preload_hunt_lookup_caches():
    """Background warm — must not block /alive (joint probes this immediately)."""
    _warm_hunt_lookup_thread()
    _start_gmail_token_maintainer()
    try:
        get_TL(force=False)
    except Exception:
        pass
    try:
        _gmail_token_parts(force_tl=False)
    except Exception:
        pass
    try:
        load(force_refresh=False)
    except Exception:
        pass


_hunt_lookup_executor = ThreadPoolExecutor(
    max_workers=HUNT_CYCLE_MAX_CONCURRENT + 20,
    thread_name_prefix="hunt-lookup",
    initializer=_warm_hunt_lookup_thread,
)
_alive_refresh_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="alive")


def _hunt_ig_device_ctx():
    """Reuse per-thread IG device ids — less churn, faster under hunt_cycle load."""
    ctx = getattr(_hunt_http_local, "ig_ctx", None)
    if ctx is None:
        device = str(uuid.uuid4())
        ctx = {
            "device": device,
            "family": str(uuid.uuid4()),
            "android": "android-" + secrets.token_hex(8),
            "session_id": f"UFS-{uuid.uuid4()}-0",
        }
        _hunt_http_local.ig_ctx = ctx
    return ctx


def _get_ig_graphql_session():
    """Per-thread session — safe for parallel ig_gen executor workers."""
    http = getattr(_ig_graphql_local, "session", None)
    if http is None:
        http = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=4,
            pool_maxsize=4,
            max_retries=0,
        )
        http.mount("https://", adapter)
        http.mount("http://", adapter)
        _ig_graphql_local.session = http
    return http
_ig_gen_executor = ThreadPoolExecutor(
    max_workers=IG_GEN_THREAD_POOL_SIZE,
    thread_name_prefix="ig-gen",
)
_recovery_executor = ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="ig-recovery",
)
info = {}

VALID_API_KEYS = {"test123", "freekey"}
GOOGLE_ACCOUNTS_URL = 'https://accounts.google.com'
GOOGLE_ACCOUNTS_DOMAIN = 'accounts.google.com'
REFERRER_HEADER = 'referer'
ORIGIN_HEADER = 'origin'
AUTHORITY_HEADER = 'authority'
CONTENT_TYPE_HEADER = 'Content-Type'
COOKIE_HEADER = 'Cookie'
USER_AGENT_HEADER = 'User-Agent'
CONTENT_TYPE_FORM = 'application/x-www-form-urlencoded; charset=UTF-8'
CONTENT_TYPE_FORM_ALT = 'application/x-www-form-urlencoded;charset=UTF-8'
TOKEN_FILE = "google_token.txt"
attempts = 1

def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"


def gradient_line(text, start, end):
    if not COLOR_SUPPORT or not text:
        return text
    r1, g1, b1 = start
    r2, g2, b2 = end
    out = []
    width = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        t = i / width
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        out.append(f"{rgb(r, g, b)}{ch}")
    return "".join(out) + ANSI_RESET


BANNER_LOGO = [
    "     ██╗███╗   ██╗██████╗  █████╗ ██████╗ ███████╗████████╗ ██████╗ ",
    "     ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔═══██╗",
    "     ██║██╔██╗ ██║██████╔╝███████║██████╔╝█████╗     ██║   ██║   ██║",
    "     ██║██║╚██╗██║██╔═══╝ ██╔══██║██╔══██╗██╔══╝     ██║   ██║   ██║",
    "     ██║██║ ╚████║██║     ██║  ██║██║  ██║███████╗   ██║   ╚██████╔╝",
    "     ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ",
]

BANNER_BADGE = [
    "        ╭──────────────────────────────────────────────╮",
    "        │  ◆  Developed & Maintained by S Crew  ◆      │",
    "        ╰──────────────────────────────────────────────╯",
]


def paint_logo():
    palette = [
        ((0, 255, 255), (0, 140, 255)),
        ((0, 220, 255), (80, 90, 255)),
        ((100, 180, 255), (140, 60, 255)),
        ((160, 120, 255), (200, 40, 255)),
        ((200, 80, 255), (255, 60, 200)),
        ((255, 40, 180), (255, 80, 120)),
    ]
    lines = []
    for idx, row in enumerate(BANNER_LOGO):
        start, end = palette[idx]
        lines.append("  " + gradient_line(row, start, end))
    for row in BANNER_BADGE:
        lines.append(apply_color(row, ANSI_MAGENTA))
    return lines


def _card_inner_w(label_w, value_w):
    return label_w + value_w + 3


def _fit_label(label, label_w):
    label = str(label)
    if len(label) <= label_w:
        return label
    return label[: max(label_w - 1, 1)] + "…"


def paint_info_card(rows, label_w=11, value_w=34):
    inner_w = _card_inner_w(label_w, value_w)
    top = apply_color(f"  ╭{'─' * inner_w}╮", ANSI_CYAN)
    bottom = apply_color(f"  ╰{'─' * inner_w}╯", ANSI_CYAN)
    body = []
    for label, value, color in rows:
        left = f"  │ {_fit_label(label, label_w):<{label_w}}│ "
        right = f"{pad_value(str(value), value_w)}│"
        body.append(apply_color(left, ANSI_DIM) + apply_color(right, color))
    return [top, *body, bottom]


ACTION_BOX_W = 73
ACTION_INNER = 67


def visible_len(text):
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def pad_value(value, width):
    pad = max(width - visible_len(value), 0)
    return f"{value}{' ' * pad}"


def clip_plain(text, max_len):
    plain = re.sub(r"\033\[[0-9;]*m", "", str(text))
    if len(plain) <= max_len:
        return plain
    return plain[: max_len - 1] + "…"


def paint_action_box(title, lines, border_color=ANSI_YELLOW):
    head = f"  ┌─ {title} "
    dashes = max(ACTION_BOX_W - len(head) - 1, 0)
    out = [apply_color(head + "─" * dashes + "┐", border_color)]
    for text, color in lines:
        body = clip_plain(text, ACTION_INNER)
        out.append(apply_color(f"  │  {body:<{ACTION_INNER}}│", color))
    out.append(apply_color(f"  └{'─' * (ACTION_BOX_W - 4)}┘", border_color))
    return out


def render_keyboard_exit():
    print()
    print(gradient_line("  ◆  G A T E W A Y   O F F L I N E  ◆  ", (255, 80, 90), (255, 170, 110)))
    print()
    for line in paint_action_box(
        "GATEWAY STOPPED",
        [
            ("Ctrl+C received — API host is shutting down.", ANSI_YELLOW),
            ("Public endpoint removed from this machine.", ANSI_DIM),
            ("Start again:  python endpoint.py", ANSI_CYAN),
        ],
        ANSI_RED,
    ):
        print(line)
    print(apply_color("  Gateway shutdown complete.\n", ANSI_DIM))


def render_startup_banner(device_hash, public_ip, port, cloud_ok):
    endpoint = f"{public_ip}:{port}" if public_ip else f"unknown:{port}"
    cloud_text = "synced" if cloud_ok else "pending"
    cloud_color = ANSI_GREEN if cloud_ok else ANSI_YELLOW
    host = platform.node() or "local"

    print()
    for line in paint_logo():
        print(line)
    print()

    info_rows = [
        ("Status", "● ONLINE", ANSI_GREEN),
        ("Endpoint", endpoint, ANSI_CYAN),
        ("Device", f"{device_hash[:16]}…", ANSI_CYAN),
        ("Host", host[:34], ANSI_BLUE),
        ("Cloud", cloud_text, cloud_color),
        ("Engine", "FastAPI / Uvicorn", ANSI_MAGENTA),
        ("Profile", f"{GATEWAY_PROFILE} · fill {IG_GEN_BUFFER_FILL_WORKERS}", ANSI_YELLOW if _IS_TERMUX else ANSI_DIM),
    ]
    for line in paint_info_card(info_rows):
        print(line)

    print()
    for line in paint_action_box(
        "NEXT STEP",
        [
            ("API host is live — keep this terminal open.", ANSI_GREEN),
            (
                (
                    "Termux: lighter buffer (48 fillers) — pair with joint.py on same phone."
                    if _IS_TERMUX
                    else "joint.py auto-uses 127.0.0.1 on this PC if public IP is blocked."
                ),
                ANSI_DIM,
            ),
            ("Open a new terminal and run:  python joint.py", ANSI_YELLOW),
        ],
        ANSI_YELLOW,
    ):
        print(line)
    print(apply_color("\n  Gateway running in foreground. Ctrl+C stops API only.\n", ANSI_DIM))


def get_device_hash():
    seed = "|".join([
        platform.node(),
        platform.system(),
        platform.machine(),
        platform.processor(),
        str(uuid.getnode()),
    ])
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def supabase_headers(prefer=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


def fetch_device_record(device_hash):
    url = f"{SUPABASE_URL}/rest/v1/devices"
    try:
        response = requests.get(
            url,
            headers=supabase_headers(),
            params={
                "device_hash": f"eq.{device_hash}",
                "select": "*",
                "limit": "1",
            },
            timeout=CLOUD_TIMEOUT,
        )
        if not response.ok:
            return None, response.text[:200]
        data = response.json()
        if not data:
            return None, None
        return data[0], None
    except Exception as exc:
        return None, str(exc)


def save_api_host_record(device_hash, public_ip, port, api_host):
    now = datetime.now(timezone.utc).isoformat()
    existing, _ = fetch_device_record(device_hash)
    payload = {
        "device_hash": device_hash,
        "api_host": api_host,
        "api_public_ip": public_ip,
        "api_port": port,
        "hostname": platform.node(),
        "display_name": (existing or {}).get("display_name") or f"Op-{device_hash[:8]}",
        "telegram_bot_token": (existing or {}).get("telegram_bot_token") or "",
        "telegram_chat_id": (existing or {}).get("telegram_chat_id") or "",
        "last_seen": now,
    }
    if not existing:
        payload["first_seen"] = now
    url = f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_hash"
    try:
        response = requests.post(
            url,
            headers=supabase_headers("resolution=merge-duplicates,return=representation"),
            json=payload,
            timeout=CLOUD_TIMEOUT,
        )
        if not response.ok:
            return response.text[:200]
        return None
    except Exception as exc:
        return str(exc)


async def fetch_public_ip():
    endpoints = (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    )
    for url in endpoints:
        try:
            response = await asyncio.to_thread(requests.get, url, timeout=8)
            if response.ok:
                candidate = response.text.strip()
                if candidate and not candidate.startswith(("127.", "10.", "192.168.", "172.")):
                    return candidate
                if candidate:
                    return candidate
        except Exception:
            continue
    return None


def suppress_server_logs():
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
        logging.getLogger(name).disabled = True


# ---------------- GENERATE USER AGENT ----------------
def generate_user_agent():
    return "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36"


def _gmail_lookup_user_agent():
    """Termux uses Android UA to match curl_cffi chrome131_android TLS fingerprint."""
    return generate_user_agent() if _IS_TERMUX else _GMAIL_UA


def _ig_response_is_blocked(response):
    ctype = (response.headers.get("content-type") or "").lower()
    if "html" in ctype:
        return True
    text = (response.text or "").lstrip()
    return bool(text) and not text.startswith("{") and not text.startswith("[")


def _ig_body_rate_limited(body):
    """IG returns JSON errors (1675004) when IP is throttled — not HTML."""
    if not isinstance(body, dict):
        return False
    for err in body.get("errors") or []:
        if not isinstance(err, dict):
            continue
        code = err.get("code")
        msg = (err.get("message") or "").lower()
        if code in (1675004, 4) or "rate limit" in msg:
            return True
    return False


def _mark_ig_gen_blocked(cooldown=None):
    """GraphQL username gen — pauses buffer fill + live gen only."""
    global _ig_gen_block_until
    if cooldown is None:
        cooldown = _IG_BLOCK_COOLDOWN_GEN
    with _ig_block_lock:
        now = time.time()
        if _ig_gen_block_until - now > _IG_BLOCK_REMARK_MIN_LEFT:
            return
        _ig_gen_block_until = now + float(cooldown)


def _mark_ig_lookup_blocked(cooldown=None):
    """M3 email lookup 429 — must not stop buffer fillers."""
    global _ig_lookup_block_until
    if cooldown is None:
        cooldown = _IG_BLOCK_COOLDOWN_LOOKUP
    with _ig_block_lock:
        now = time.time()
        if _ig_lookup_block_until - now > _IG_BLOCK_REMARK_MIN_LEFT:
            return
        _ig_lookup_block_until = now + float(cooldown)


def _mark_ig_blocked(cooldown=None):
    _mark_ig_gen_blocked(cooldown=cooldown)


def _ig_in_gen_block_cooldown():
    return time.time() < _ig_gen_block_until


def _ig_in_lookup_block_cooldown():
    return time.time() < _ig_lookup_block_until


def _ig_in_block_cooldown():
    return _ig_in_gen_block_cooldown()


def _fetch_fresh_ig_tokens():
    """Live csrftoken + lsd from instagram.com — stale tk.txt causes empty gen."""
    tok_sess = requests.Session()
    tok_sess.headers["User-Agent"] = _IG_WEB_UA
    try:
        resp = _ig_http_get("https://www.instagram.com/", timeout=12, http=tok_sess)
    except Exception:
        return None, None
    csrf = (tok_sess.cookies.get("csrftoken") or "").strip()
    lsd = ""
    match = _LSD_TOKEN_RE.search(resp.text or "")
    if match:
        lsd = match.group(1).strip()
    if csrf and lsd:
        now = time.time()
        with _tk_lock:
            _tk_cache["csrf"] = csrf
            _tk_cache["lsd"] = lsd
            _tk_cache["at"] = now
        try:
            with open("tk.txt", "w", encoding="utf-8") as handle:
                handle.write(f"{csrf}|{lsd}")
        except OSError:
            pass
        return csrf, lsd
    return None, None


def load(*, force_refresh=False):
    """Cache tk.txt in memory — refresh from IG when missing or stale."""
    if not force_refresh:
        now = time.time()
        with _tk_lock:
            if (
                _tk_cache.get("csrf")
                and _tk_cache.get("lsd")
                and now - float(_tk_cache.get("at") or 0) < TK_CACHE_SEC
            ):
                return _tk_cache["csrf"], _tk_cache["lsd"]
        try:
            with open("tk.txt", "r", encoding="utf-8") as file:
                parts = file.read().strip().split("|")
                if len(parts) == 2:
                    csrf, lsd = parts[0].strip(), parts[1].strip()
                    if csrf and lsd:
                        with _tk_lock:
                            _tk_cache["csrf"] = csrf
                            _tk_cache["lsd"] = lsd
                            _tk_cache["at"] = now
                        return csrf, lsd
        except OSError:
            pass
    fresh = _fetch_fresh_ig_tokens()
    if fresh[0] and fresh[1]:
        return fresh
    return "iOtJRFIg4a1qWbmj6kyFAnl9myM1KL4N", "gBe1PvkGrT-aR_CQpsVxFN"

def _parse_hunt_ig_m2_body(body):
    """M2 GraphQL markers — block/retry response still means account exists."""
    text = (body or "").strip()
    if not text:
        return None, "empty"
    if text.startswith("for (;;);"):
        text = text[9:].strip()
    if "Check your email or phone" in text:
        return False, "No account found"
    if "We sent you an email with a link to get back into your account." in text or "Get link via email" in text:
        return True, "Account exists, email sent for recovery"
    if "Something went wrong, please try again later." in text:
        return False, "Account exists but hit a block, try again later"
    low = text.lower()
    if "rate limit" in low and "something went wrong" not in low:
        return None, "rate_limited"
    return None, None

def _hunt_mobile_headers(ctx, *, client_endpoint, friendly_name):
    return {
        "User-Agent": _IG_MOBILE_UA,
        "accept-language": "en-IN, en-US",
        "Content-Type": "application/x-www-form-urlencoded",
        "x-bloks-version-id": "5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b",
        "x-fb-friendly-name": friendly_name,
        "x-ig-android-id": ctx["android"],
        "x-ig-app-id": _IG_MOBILE_APP_ID,
        "x-ig-app-locale": "en_IN",
        "x-ig-client-endpoint": client_endpoint,
        "x-ig-device-id": ctx["device"],
        "x-ig-family-device-id": ctx["family"],
        "x-ig-timezone-offset": str(datetime.now().astimezone().utcoffset().total_seconds()),
        "x-mid": base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("="),
        "x-pigeon-rawclienttime": str(time.time()),
        "x-pigeon-session-id": ctx["session_id"],
    }


def _parse_mobile_check_email(body):
    """i.instagram.com users/check_email — available:false = on IG."""
    text = body or ""
    low = text.lower()
    if "rate limit" in low or "please wait" in low:
        return None, "rate_limited"
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None, "unparsed"
    if (data.get("status") or "").lower() == "fail":
        msg = (data.get("message") or "").lower()
        if "rate" in msg or "wait" in msg:
            return None, "rate_limited"
        return False, data.get("message") or "No account found"
    if data.get("available") is False:
        return True, "Account exists"
    if (data.get("error_type") or "").lower() == "email_is_taken":
        return True, "Account exists"
    if data.get("allow_shared_email_registration") is True:
        return True, "Account exists"
    if data.get("available") is True:
        return False, "No account found"
    return None, "unparsed"


def _parse_mobile_assisted_recovery(body):
    """assisted_account_recovery — accounts list vs help center."""
    text = body or ""
    low = text.lower()
    if "rate limit" in low or "please wait" in low:
        return None, "rate_limited"
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None, "unparsed"
    action = (data.get("action") or "").lower()
    if action == "show_recovery_accounts_list" and (data.get("accounts") or []):
        return True, "Account exists"
    if action == "show_help_center_link":
        return False, "No account found"
    if (data.get("status") or "").lower() == "fail":
        return None, "rate_limited"
    return None, "unparsed"


def _ig_lookup_mobile_check_email(email):
    ctx = _hunt_ig_device_ctx()
    data = {
        "email": email,
        "android_device_id": ctx["android"],
        "login_nonce_map": "{}",
        "login_nonces": "[]",
        "qe_id": ctx["device"],
        "waterfall_id": str(uuid.uuid4()),
    }
    response = _hunt_http_post(
        _HUNT_MOBILE_CHECK_EMAIL_URL,
        data=data,
        headers=_hunt_mobile_headers(
            ctx,
            client_endpoint="users/check_email",
            friendly_name="IgApi: users/check_email/",
        ),
        timeout=_hunt_lookup_timeout(),
    )
    code = int(getattr(response, "status_code", 0) or 0)
    if code == 429:
        return None, "rate_limited"
    return _parse_mobile_check_email(response.text or "")


def _ig_lookup_mobile_assisted_recovery(email):
    ctx = _hunt_ig_device_ctx()
    data = {
        "query": email,
        "source": "account_recovery",
        "waterfall_id": str(uuid.uuid4()),
    }
    response = _hunt_http_post(
        _HUNT_MOBILE_ASSISTED_RECOVERY_URL,
        data=data,
        headers=_hunt_mobile_headers(
            ctx,
            client_endpoint="accounts/assisted_account_recovery",
            friendly_name="IgApi: accounts/assisted_account_recovery/",
        ),
        timeout=_hunt_lookup_timeout(),
    )
    code = int(getattr(response, "status_code", 0) or 0)
    if code == 429:
        return None, "rate_limited"
    return _parse_mobile_assisted_recovery(response.text or "")


def _ig_lookup_hunt_fast_check_email(email):
    """Minimal check_email POST (T-LNX / xd style) — fastest IG probe on clean IP."""
    try:
        resp = _get_hunt_http_session().post(
            _HUNT_MOBILE_CHECK_EMAIL_URL,
            data={"email": email},
            headers={
                "User-Agent": _HUNT_CHECK_EMAIL_FAST_UA,
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
            },
            timeout=_HUNT_CHECK_EMAIL_FAST_TIMEOUT,
        )
        code = int(getattr(resp, "status_code", 0) or 0)
        if code == 429:
            return None, "rate_limited"
        status, msg = _parse_mobile_check_email(resp.text or "")
        if status is not None:
            return status, msg
        return None, msg or "unparsed"
    except Exception:
        return None, "error"


def ig_lookup_M3_hunt(email):
    """Hunt IG — one mobile check_email; assisted only on 429; GQL if mobile RL."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Empty query"
    if _ig_in_lookup_block_cooldown():
        return False, "rate_limited"
    try:
        status, msg = _ig_lookup_mobile_check_email(email)
        if status is not None:
            return status, msg or ("Account exists" if status else "No account found")
        if msg != "rate_limited":
            return False, msg or "No account found"
        _mark_ig_lookup_blocked(cooldown=_IG_BLOCK_COOLDOWN_LOOKUP)
        status, msg = _ig_lookup_mobile_assisted_recovery(email)
        if status is not None:
            return status, msg or ("Account exists" if status else "No account found")
        gql_status, gql_msg = _ig_lookup_hunt_graphql_hunt(email)
        if gql_status is True:
            return True, gql_msg or "Account exists"
        if gql_status is False and gql_msg != "rate_limited":
            return False, gql_msg or "No account found"
        return False, "rate_limited"
    except Exception as exc:
        return False, str(exc)[:120]


def ig_lookup_M2_hunt(email):
    """Legacy web M2 — kept for /ig_lookup_m2 tool; hunt uses M3 mobile."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Empty query"
    try:
        return ig_lookup_M2(email)
    except Exception as exc:
        return False, str(exc)[:120]


def _ig_lookup_hunt_graphql_hunt(email):
    """Web recovery GraphQL — fast vs M1 bloks (~2s vs 10–30s)."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Empty query"
    try:
        status, msg = ig_lookup_M2_hunt(email)
    except Exception as exc:
        return False, str(exc)[:120]
    if status is True:
        return True, msg or "Account exists"
    if status is False:
        return False, msg or "No account found"
    if msg == "rate_limited":
        return False, "rate_limited"
    return False, msg or "No account found"


def _hunt_ig_lookup_with_fallback(email):
    """Hunt IG — GraphQL first (~2s); M1 bloks only when GraphQL rate-limited."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Empty query"
    try:
        status, msg = _ig_lookup_hunt_graphql_hunt(email)
        if status is True:
            return True, msg or "Account exists"
        if msg != "rate_limited":
            return False, msg or "No account found"
        if _ig_in_lookup_block_cooldown():
            return False, "rate_limited"
        _mark_ig_lookup_blocked(cooldown=_IG_BLOCK_COOLDOWN_LOOKUP)
        m1_status, m1_msg = ig_lookup_M1_hunt(email)
        if m1_status is True:
            return True, m1_msg or "Account exists"
        if m1_msg == "rate_limited":
            return False, "rate_limited"
        return False, m1_msg or msg or "No account found"
    except Exception as exc:
        return False, str(exc)[:120]


def _hunt_lookup_gmail_pair(email):
    """IG + Gmail in one thread hop — gmail uses check_gmail_hunt_cycle retries."""
    try:
        _gmail_token_parts(force_tl=False)
    except Exception:
        pass
    ig_status, ig_msg = _hunt_ig_lookup_with_fallback(email)
    valid = ig_status is True
    hit = False
    gmail_msg = None
    if valid:
        gmail_result = check_gmail_hunt_cycle(email)
        print(gmail_result)
        if isinstance(gmail_result, str):
            gmail_msg = gmail_result
        else:
            gmail_status, gmail_msg = gmail_result
            hit = gmail_status is True
    return valid, hit, ig_msg, gmail_msg


def ig_lookup_M1(email):
    global goodig, badig
    try:
        return _ig_lookup_M1_impl(email, hunt_fast=False)
    except Exception as exc:
        return False, str(exc)[:120]


def ig_lookup_M1_hunt(email):
    """Hunt IG — M1 bloks stream (48KB miss cap) + reused device."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Empty query"
    if _ig_in_lookup_block_cooldown():
        return False, "rate_limited"
    try:
        return _ig_lookup_M1_impl(email, hunt_fast=False, reuse_device=True)
    except Exception as exc:
        return False, str(exc)[:120]


def _parse_hunt_ig_graphql_body(body, query):
    """Return (True/False, msg) or (None, reason) to fall back to bloks."""
    m2_status, m2_msg = _parse_hunt_ig_m2_body(body)
    if m2_status is not None:
        return m2_status, m2_msg
    if m2_msg == "rate_limited":
        return None, "rate_limited"
    text = (body or "").strip()
    if not text:
        return None, "empty"
    if text.startswith("for (;;);"):
        text = text[9:].strip()
    low = text.lower()
    if "rate limit" in low:
        return None, "rate_limited"
    if _HUNT_IG_NO_ACCOUNT_RE.search(text):
        return False, "No account found"
    q = (query or "").strip()
    if q and q in text:
        return True, "Account exists"
    try:
        data = json.loads(text)
        search = (data.get("data") or {}).get("caa_ar_ig_account_search") or {}
        qlow = q.lower()
        if "@" in qlow:
            local, domain = qlow.split("@", 1)
            for cp in search.get("contact_points") or []:
                if not isinstance(cp, dict):
                    continue
                if (cp.get("type") or "").upper() != "EMAIL":
                    continue
                val = (cp.get("value") or cp.get("display") or "").lower()
                if qlow in val or (f"@{domain}" in val and local and val.startswith(local[0])):
                    return True, "Account exists"
        elif search.get("contact_points") or search.get("user") or search.get("username"):
            return True, "Account exists"
    except (ValueError, TypeError, AttributeError):
        pass
    if '"error":' in text and "contact_points" not in text:
        return None, "rate_limited"
    return False, "No account found"


def _ig_lookup_hunt_graphql(query):
    """Fast hunt IG — web GraphQL with full email (user@gmail.com)."""
    query = (query or "").strip().lower()
    if not query:
        return None, "empty"
    csrf, lsd = load(force_refresh=False)
    variables = json.dumps(
        {
            "params": {
                "event_request_id": str(uuid.uuid4()),
                "next_uri": "",
                "search_query": query,
                "waterfall_id": str(uuid.uuid4()),
            }
        },
        separators=(",", ":"),
    )
    payload = {
        "av": "0",
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "8",
        "dpr": "1",
        "__ccg": "GOOD",
        "__comet_req": "7",
        "__crn": "comet.igweb.PolarisCAAIGAccountRecoverySearchRoute",
        "qpl_active_flow_ids": "516759801",
        "fb_api_caller_class": "RelayModern",
        "fb_api_req_friendly_name": "CAAIGAccountSearchViewQuery",
        "server_timestamps": "true",
        "doc_id": _HUNT_IG_GRAPHQL_DOC_ID,
        "variables": variables,
        "jazoest": str(random.randint(20000, 29999)),
        "lsd": lsd,
    }
    headers = {
        "User-Agent": _IG_WEB_UA,
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRFToken": csrf,
        "X-IG-App-ID": "936619743392459",
        "X-FB-Friendly-Name": "CAAIGAccountSearchViewQuery",
        "X-ASBD-ID": "359341",
        "X-FB-LSD": lsd,
        "Origin": "https://www.instagram.com",
        "Referer": _HUNT_IG_RESET_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    response = _hunt_http_post(
        _HUNT_IG_GRAPHQL_URL,
        data=payload,
        headers=headers,
        timeout=_hunt_lookup_timeout(),
    )
    if int(getattr(response, "status_code", 0) or 0) == 429:
        return None, "rate_limited"
    return _parse_hunt_ig_graphql_body(response.text or "", query)


def _ig_lookup_M1_impl(email, *, hunt_fast=False, reuse_device=False):
    url = "https://i.instagram.com/api/v1/bloks/async_action/com.bloks.www.caa.ar.search.async/"
    if hunt_fast or reuse_device:
        ctx = _hunt_ig_device_ctx()
        device = ctx["device"]
        family = ctx["family"]
        android = ctx["android"]
        pigeon_session = ctx["session_id"]
    else:
        device = str(uuid.uuid4())
        family = str(uuid.uuid4())
        android = "android-" + secrets.token_hex(8)
        pigeon_session = f"UFS-{uuid.uuid4()}-0"
    payload = {
      'params': "{\"client_input_params\":{\"aac\":\"{\\\"aac_init_timestamp\\\":"+ str(int(time.time())) +",\\\"aacjid\\\":\\\""+ str(uuid.uuid4()) +"\\\",\\\"aaccs\\\":\\\""+ secrets.token_urlsafe(32) +"\\\"}\",\"flash_call_permissions_status\":{\"READ_PHONE_STATE\":\"PERMANENTLY_DENIED\",\"READ_CALL_LOG\":\"DENIED\",\"ANSWER_PHONE_CALLS\":\"DENIED\"},\"was_headers_prefill_available\":0,\"network_bssid\":null,\"sfdid\":\"\",\"fetched_email_token_list\":{},\"search_query\":\""+ email +"\",\"auth_secure_device_id\":\"\",\"ig_oauth_token\":[],\"cloud_trust_token\":null,\"was_headers_prefill_used\":0,\"sso_accounts_auth_data\":[],\"encrypted_msisdn\":\"\",\"device_network_info\":null,\"text_input_id\":\"akyuf0:61\",\"zero_balance_state\":null,\"android_build_type\":\"release\",\"accounts_list\":[],\"is_oauth_without_permission\":0,\"ig_android_qe_device_id\":\""+ device +"\",\"gms_incoming_call_retriever_eligibility\":\"client_not_supported\",\"search_screen_type\":\"email_or_username\",\"is_whatsapp_installed\":1,\"lois_settings\":{\"lois_token\":\"\"},\"ig_vetted_device_nonce\":null,\"headers_infra_flow_id\":\"\",\"fetched_email_list\":[]},\"server_params\":{\"event_request_id\":\""+ str(uuid.uuid4()) +"\",\"is_from_logged_out\":0,\"layered_homepage_experiment_group\":null,\"device_id\":\""+ android +"\",\"login_surface\":\"login_home\",\"waterfall_id\":\""+ str(uuid.uuid4()) +"\",\"INTERNAL__latency_qpl_instance_id\":6.3987980400102E13,\"is_platform_login\":0,\"context_data\":\"\",\"login_entry_point\":\"logged_out\",\"INTERNAL__latency_qpl_marker_id\":36707139,\"family_device_id\":\""+ family +"\",\"offline_experiment_group\":\"caa_iteration_v3_perf_ig_4\",\"access_flow_version\":\"pre_mt_behavior\",\"is_from_logged_in_switcher\":0,\"qe_device_id\":\""+ device +"\"}}",
      'bk_client_context': "{\"bloks_version\":\"5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b\",\"styles_id\":\"instagram\"}",
      'bloks_versioning_id': "5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b"
    }
    headers = {
      'User-Agent': "Instagram 370.1.0.43.96 Android (34/14; 450dpi; 1080x2207; samsung; SM-A235F; a23; qcom; en_IN; 704872281)",
      'accept-language': "en-IN, en-US",
      'x-bloks-version-id': "5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b",
      'x-fb-friendly-name': "IgApi: bloks/async_action/com.bloks.www.caa.ar.search.async/",
      'x-ig-android-id': android,
      'x-ig-app-id': "567067343352427",
      'x-ig-app-locale': "en_IN",
      'x-ig-client-endpoint': "com.bloks.www.caa.ar.search",
      'x-ig-device-id': device,
      'x-ig-family-device-id': family,
      'x-ig-timezone-offset': str(datetime.now().astimezone().utcoffset().total_seconds()),
      'x-mid': base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip('='),
      'x-pigeon-rawclienttime': str(time.time()),
      'x-pigeon-session-id': pigeon_session,
    }
    if hunt_fast:
        code, kind = _hunt_http_post_scan(
            url,
            data=payload,
            headers=headers,
            timeout=_hunt_lookup_timeout(),
            hit_needle=email,
        )
        if kind == "hit":
            return True, "Account exists"
        if kind == "rate_limited":
            return False, "rate_limited"
        if kind == "miss":
            return False, "No account found"
        return False, "No account found"
    response = _hunt_http_post(
        url, data=payload, headers=headers, timeout=_hunt_lookup_timeout(),
    )
    resp = response.text or ""
    if response.status_code == 429:
        return False, "rate_limited"
    low = resp.lower()
    if "rate limit" in low or "please wait" in low:
        return False, "rate_limited"
    if f"{email}" in resp:
        return True, "Account exists"
    return False, "No account found"


def ig_lookup_M2(email):
    cookies = {
        'csrftoken': 'emU-IV3KQqGoXhI1qJjrGQ',
        'datr': 'BuUKag642s55rnsmRN_YcqyI',
        'ig_did': '019B020F-E14E-436D-B058-F28A1941DCFE',
        'mid': 'agrlBgAEAAG-8qSlB3Bci8eyshI_',
        'dpr': '1.0909090909090908',
        'wd': '1709x924',
    }

    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-FB-Friendly-Name': 'CAAIGAccountSearchViewQuery',
        'X-CSRFToken': 'emU-IV3KQqGoXhI1qJjrGQ',
        'X-IG-App-ID': '936619743392459',
        'X-IG-Max-Touch-Points': '0',
        'X-FB-LSD': 'AdQe6dvzIXZbagGy49WvtiSBSAQ',
        'X-ASBD-ID': '359341',
        'Origin': 'https://www.instagram.com',
        'Connection': 'keep-alive',
        'Referer': 'https://www.instagram.com/accounts/password/reset/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Priority': 'u=0',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
    }

    data = {
        'av': '0',
        '__d': 'www',
        '__user': '0',
        '__a': '1',
        '__req': '1e',
        '__hs': '20591.HYP:instagram_web_pkg.2.1...0',
        'dpr': '1',
        '__ccg': 'EXCELLENT',
        '__rev': '1039692732',
        '__s': 'w7u6pd:wnn185:1w292y',
        '__hsi': '7641171533661006458',
        '__dyn': '7xeUmwlEnwn8K2Wmh0no6u5U4e2C1vzEdEc8co2qwJxS0k24o0B-q7oc81EE2Cwwwqo6ucw5Mx612xO1ywOwv89k2C1FwnE6a0D85m1mzXwae4UaEW2G0AEco5G1HxidU5O3y785C7U620g62Z2oS1TwVwDwHg2ZwrVocobGwmk0zU8oC1IwGw-wlAcwBwUQp1yU426V8aUuwm8bU5q0EoK9x60ma1XwiE884O0XEdoC',
        '__csr': 'gZ0wNQ8ghp2SOOhn5GJllikQHlKRdkWFtbQQXYyj8BSy9Xqd99pcZh5ZFT8hYOb8hWl8IFOh4G-B8WyrGjvTK58C9CoFV8iOkKidUnppHAmGGU_BhpAu9-ivyppGVUxa9LBBKmA9gzmbiGil1649a-VrhEyidAy8gx2AEy8xWEf6dwywDGium2-6bUkUtK7p8epbz9qwxxaUiwBxy2J3E8-2e2K01psw040Pz8mG0geu8g3Hyo0DXw2Xo6oE8U0kDwkE2qo23xnw5RwZw2v80A4wqA9e0Nba9w3C9Uy2e0kS1-gbe1zAUfo18hgx0rja5E3_w3mEbU-01ggw',
        '__hsdp': 'n0_BOtGFB2qI8B8u9hk99aAdwq8S0yFohxGWdDKqaydF10IA49O0xht0vXrxCawdl8w44a9xa0CV42e2q2e07w81mo0cG80DLw6Ew2l80pHw5Bw',
        '__hblp': '06cw8Gm4oa8bodofoqwgpUcUlxx0alzoO0C830xWi1gz830wfC0Feewpo5m56685O581po3PQqU3Hwb60FU16U7K0ju0ia0fGw3t83hxydwn8jwv8665o1EoS0mS0hfwQwr8nBwvE0IS0qG1CAyEy2m0DU9E25w4fwlo20U6K',
        '__sjsp': 'n0_BOtGFB25aNAxi7ykl2iiF3o6ydw8Gm4oqKzpXCyEzokb912sw8kng7-SUpyE3li8112yoiw9Kh0zwCwzw',
        '__comet_req': '7',
        'lsd': 'AdQe6dvzIXZbagGy49WvtiSBSAQ',
        'jazoest': '22395',
        '__spin_r': '1039692732',
        '__spin_b': 'trunk',
        '__spin_t': '1779098886',
        '__crn': 'comet.igweb.PolarisCAAIGAccountRecoverySearchRoute',
        'qpl_active_flow_ids': '516759801',
        'fb_api_caller_class': 'RelayModern',
        'fb_api_req_friendly_name': 'CAAIGAccountSearchViewQuery',
        'server_timestamps': 'true',
        'variables': json.dumps({
            'params': {
                'event_request_id': 'c4b3117e-d1d3-4a9d-b3e4-cfa57a405c9d',
                'next_uri': '',
                'search_query': email,
                'waterfall_id': 'ecf54a6e-8a3a-4c3c-b79b-9be736a0a9a7'
            }
        }),
        'doc_id': '35299094813070532',
        'fb_api_analytics_tags': '["qpl_active_flow_ids=516759801"]',
    }

    response = _hunt_http_post(
        "https://www.instagram.com/api/graphql",
        cookies=cookies,
        headers=headers,
        data=data,
        timeout=_hunt_lookup_timeout(),
    )
    m2_status, m2_msg = _parse_hunt_ig_m2_body(response.text or "")
    if m2_status is True:
        return True, m2_msg or "Account exists"
    if m2_status is False:
        return False, m2_msg or "No account found"
    return False, "Api got dead? if continously same error then contact owner :("


task_queue = queue.Queue()


def _write_gmail_token_atomic(line):
    tmp_path = f"{TOKEN_FILE}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(line)
    os.replace(tmp_path, TOKEN_FILE)


def _gmail_invalidate_token_cache() -> None:
    with _gmail_tl_cond:
        _gmail_tl_cache["at"] = 0.0


def _gmail_tl_cache_fresh() -> bool:
    with _gmail_tl_cond:
        return _gmail_tl_cache_fresh_unlocked()


def _gmail_force_refresh_tl() -> None:
    """Invalidate + fetch new TL — all waiters block until refresh finishes."""
    _gmail_invalidate_token_cache()
    try:
        get_TL(force=True)
    except Exception:
        pass


def _start_gmail_token_maintainer() -> None:
    """Refresh TL in background before expiry — keeps mass hunt gmail stable."""
    global _gmail_maintainer_started
    if _gmail_maintainer_started:
        return
    _gmail_maintainer_started = True

    def _loop() -> None:
        while True:
            time.sleep(max(45, GMAIL_TL_CACHE_SEC - GMAIL_TL_REFRESH_EARLY_SEC))
            try:
                get_TL(force=True)
            except Exception:
                pass

    threading.Thread(target=_loop, name="gmail-tl-maintainer", daemon=True).start()


def get_TL(*, force=False):
    global _gmail_tl_refreshing
    with _gmail_tl_cond:
        if not force and _gmail_tl_cache_fresh_unlocked():
            return
        while _gmail_tl_refreshing:
            _gmail_tl_cond.wait(timeout=28.0)
            if not force and _gmail_tl_cache_fresh_unlocked():
                return
        _gmail_tl_refreshing = True
    try:
        _fetch_gmail_tl_locked(force=force)
    except Exception:
        if not force:
            try:
                _fetch_gmail_tl_locked(force=True)
            except Exception:
                pass
    finally:
        with _gmail_tl_cond:
            _gmail_tl_refreshing = False
            _gmail_tl_cond.notify_all()


def _gmail_tl_cache_fresh_unlocked() -> bool:
    """Caller must hold _gmail_tl_cond."""
    cached = _gmail_tl_cache.get("payload")
    at = float(_gmail_tl_cache.get("at") or 0)
    return isinstance(cached, str) and "//" in cached and time.time() - at < GMAIL_TL_CACHE_SEC


def _fetch_gmail_tl_locked(*, force=False):
    try:
        alphabet = 'azertyuiopmlkjhgfdsqwxcvbn'
        n1 = ''.join(random.choice(alphabet) for _ in range(random.randrange(6, 9)))
        n2 = ''.join(random.choice(alphabet) for _ in range(random.randrange(3, 9)))
        host = ''.join(random.choice(alphabet) for _ in range(random.randrange(15, 30)))
        headers = {
            'accept': '*/*',
            'accept-language': 'ar-IQ,ar;q=0.9,en-IQ;q=0.8,en;q=0.7,en-US;q=0.6',
            CONTENT_TYPE_HEADER: CONTENT_TYPE_FORM_ALT,
            'google-accounts-xsrf': '1',
            USER_AGENT_HEADER: str(generate_user_agent())
        }
        recovery_url = (f"{GOOGLE_ACCOUNTS_URL}/signin/v2/usernamerecovery"
                        "?flowName=GlifWebSignIn&flowEntry=ServiceLogin&hl=en-GB")
        res1 = _google_accounts_request(
            "GET", recovery_url, headers=headers, timeout=HUNT_LOOKUP_TIMEOUT,
        )
        setup_match = re.search(r'data-initial-setup-data="(%.@\.[^"]*)"', res1.text)
        if not setup_match:
            raise ValueError("Unable to find data-initial-setup-data in Google response")
        setup_data = html.unescape(setup_match.group(1))
        tok_match = re.search(
            r'%.@\.null,null,null,null,null,null,null,null,null,"[^"]*",null,null,null,"([^"]*)"',
            setup_data
        )
        if not tok_match:
            raise ValueError("Unable to parse signup token from data-initial-setup-data")
        tok = tok_match.group(1)
        cookies = {'__Host-GAPS': host}
        headers2 = {
            AUTHORITY_HEADER: GOOGLE_ACCOUNTS_DOMAIN,
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            CONTENT_TYPE_HEADER: CONTENT_TYPE_FORM_ALT,
            'google-accounts-xsrf': '1',
            ORIGIN_HEADER: GOOGLE_ACCOUNTS_URL,
            REFERRER_HEADER: ('https://accounts.google.com/signup/v2/createaccount'
                              '?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&theme=mn'),
            USER_AGENT_HEADER: generate_user_agent()
        }
        data = {
            'f.req': f'["{tok}","{n1}","{n2}","{n1}","{n2}",0,0,null,null,"web-glif-signup",0,null,1,[],1]',
            'deviceinfo': ('[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,'
                           'null,0,1,"",null,null,2,2]')
        }
        response = _google_accounts_request(
            "POST",
            f"{GOOGLE_ACCOUNTS_URL}/_/signup/validatepersonaldetails",
            cookies=cookies,
            headers=headers2,
            data=data,
            timeout=HUNT_LOOKUP_TIMEOUT,
        )
        token_line = str(response.text).split('",null,"')[1].split('"')[0]
        host = response.cookies.get_dict()['__Host-GAPS']
        line = f"{token_line}//{host}\n"
        _write_gmail_token_atomic(line)
        with _gmail_tl_cond:
            _gmail_tl_cache["payload"] = line
            _gmail_tl_cache["at"] = time.time()
    except Exception:
        raise


def _gmail_token_parts(*, force_tl: bool = False):
    get_TL(force=force_tl)
    with _gmail_tl_cond:
        cached = _gmail_tl_cache.get("payload")
        at = float(_gmail_tl_cache.get("at") or 0)
        if (
            not force_tl
            and isinstance(cached, str)
            and "//" in cached
            and time.time() - at < GMAIL_TL_CACHE_SEC
        ):
            token_data = cached.strip()
        else:
            try:
                with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                    token_data = f.read().splitlines()[0]
            except (OSError, IndexError):
                return None
    if "//" not in token_data:
        return None
    tl, host = token_data.split("//", 1)
    return tl, host


def _parse_gmail_uar_response(text: str, *, raw_text: str = "") -> tuple[bool, str] | None:
    """Return (free, msg) or None if unparseable."""
    body = text or ""
    if body.startswith(")]}'"):
        body = body[4:]
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, list) and len(item) >= 2 and item[0] == "gf.uar":
                code = item[1]
                message = item[-1] if len(item) >= 5 else ""
                if code == 1:
                    return True, "Gmail account doesn't exist"
                if code == 2:
                    return False, "Gmail account exists"
                if code == 3:
                    return False, "Invalid Gmail username"
                return False, f"Gmail account unknown status {code}: {message}"
    raw = raw_text or text or ""
    if '"gf.uar",1' in raw or '"gf.uar", 1' in raw:
        return True, "Gmail account doesn't exist"
    if '"gf.uar",2' in raw or '"gf.uar", 2' in raw:
        return False, "Gmail account exists"
    if '"gf.uar",3' in raw or '"gf.uar", 3' in raw:
        return False, "Invalid Gmail username"
    return None


def _gmail_lookup_once(email: str, *, force_tl: bool = False, hunt_fast: bool = False) -> tuple[bool, str] | str:
    if "@" in email:
        email = email.split("@")[0]
    if len(email) < 6 or len(email) > 30:
        return False, "Invalid Gmail username length (must be 6-30 characters)"
    parts = _gmail_token_parts(force_tl=force_tl)
    if not parts:
        return "gmail_error -> missing google_token (get_TL failed)"
    tl, host = parts
    cookies = {"__Host-GAPS": host}
    headers = {
        AUTHORITY_HEADER: GOOGLE_ACCOUNTS_DOMAIN,
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.9",
        CONTENT_TYPE_HEADER: CONTENT_TYPE_FORM_ALT,
        "google-accounts-xsrf": "1",
        ORIGIN_HEADER: GOOGLE_ACCOUNTS_URL,
        REFERRER_HEADER: (
            "https://accounts.google.com/signup/v2/createusername?service=mail"
            f"&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&TL={tl}"
        ),
        USER_AGENT_HEADER: _gmail_lookup_user_agent(),
    }
    params = {"TL": tl}
    data = (
        f"continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&ddm=0&flowEntry=SignUp&service=mail&theme=mn"
        f"&f.req=%5B%22TL%3A{tl}%22%2C%22{email}%22%2C0%2C0%2C1%2Cnull%2C0%2C5167%5D"
        "&azt=AFoagUUtRlvV928oS9O7F6eeI4dCO2r1ig%3A1712322460888&cookiesDisabled=false"
        "&deviceinfo=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%22NL%22%2Cnull%2Cnull%2Cnull%2C%22GlifWebSignIn%22"
        "%2Cnull%2C%5B%5D%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2Cnull%2C0%2C1%2C%22%22%2Cnull%2Cnull%2C2%2C2%5D"
        "&gmscoreversion=undefined&flowName=GlifWebSignIn&"
    )
    post_url = f"{GOOGLE_ACCOUNTS_URL}/_/signup/usernameavailability"
    try:
        if hunt_fast:
            response = _hunt_http_post(
                post_url,
                data=data,
                headers=headers,
                timeout=_hunt_lookup_timeout(),
                cookies=cookies,
                params=params,
            )
        else:
            response = _get_hunt_http_session().post(
                post_url,
                params=params,
                cookies=cookies,
                headers=headers,
                data=data,
                timeout=HUNT_LOOKUP_TIMEOUT,
            )
    except requests.RequestException as exc:
        return "gmail_error -> network"
    if response.status_code in (429, 502, 503, 504):
        return "gmail_error -> google_busy"
    text = response.text or ""
    parsed = _parse_gmail_uar_response(text, raw_text=text)
    if parsed is not None:
        return parsed
    return False, "gmail_parse_failed"


def _gmail_lookup_retry_core(email, *, max_attempts, hunt_fast_prefer: bool = True):
    """
    On any parse/network/token error: refresh TL immediately, wait, retry.
    Parallel hunt workers share one refresh — others block until new TL is ready.
    """
    if hunt_fast_prefer:
        strategies = (
            (False, True),
            (True, True),
            (True, False),
            (True, True),
            (True, True),
        )
    else:
        strategies = (
            (False, False),
            (True, False),
            (True, False),
            (True, False),
        )
    strategies = strategies[:max_attempts]
    last_msg = "gmail_parse_failed"
    for attempt, (force_tl, use_fast) in enumerate(strategies):
        if attempt:
            gap = 0.12 * attempt if _IS_TERMUX else 0.08 * attempt
            time.sleep(gap)
        try:
            result = _gmail_lookup_once(email, force_tl=force_tl, hunt_fast=use_fast)
        except Exception as exc:
            last_msg = f"gmail_error -> {exc}"
            if attempt + 1 < len(strategies):
                _gmail_force_refresh_tl()
            continue
        if isinstance(result, str):
            last_msg = result
            if attempt + 1 < len(strategies):
                _gmail_force_refresh_tl()
            continue
        _ok, msg = result
        if msg != "gmail_parse_failed":
            return result
        last_msg = msg
        if attempt + 1 < len(strategies):
            _gmail_force_refresh_tl()
    if last_msg == "gmail_parse_failed":
        return "gmail_error -> token stale or Google blocked this IP"
    return last_msg


def check_gmail_robust(email, *, hunt_fast_prefer: bool = True):
    return _gmail_lookup_retry_core(
        email,
        max_attempts=GMAIL_LOOKUP_MAX_ATTEMPTS,
        hunt_fast_prefer=hunt_fast_prefer,
    )


def check_gmail_hunt_fast(email):
    """Hunt path — mass-stable gmail (shared with /gmail_lookup)."""
    return check_gmail_robust(email, hunt_fast_prefer=True)


def check_gmail_hunt_cycle(email):
    return _gmail_lookup_retry_core(
        email,
        max_attempts=_HUNT_GMAIL_MAX_ATTEMPTS,
        hunt_fast_prefer=True,
    )


def check_gmail(email, *, _retried: bool = False):
    return check_gmail_robust(email, hunt_fast_prefer=not _retried)


def _mobile_profile_headers(csrf=""):
    device_id = str(uuid.uuid4())
    android_id = "android-" + secrets.token_hex(8)
    headers = {
        "X-IG-App-ID": _IG_MOBILE_APP_ID,
        "User-Agent": _IG_MOBILE_UA,
        "Accept": "*/*",
        "Accept-Language": "en-IN, en-US",
        "X-IG-Device-Id": device_id,
        "X-IG-Android-Id": android_id,
        "X-IG-Family-Device-Id": str(uuid.uuid4()),
        "X-IG-Timezone-Offset": str(int(time.timezone)),
        "X-MID": base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("="),
        "X-Pigeon-Session-Id": f"UFS-{uuid.uuid4()}-0",
    }
    if csrf:
        headers["X-CSRFToken"] = csrf
    return headers


def _parse_media_count_from_user(user):
    if not isinstance(user, dict):
        return None
    mc = user.get("media_count")
    if mc is not None and mc != "":
        try:
            return int(mc)
        except (TypeError, ValueError):
            pass
    edge = user.get("edge_owner_to_timeline_media")
    if isinstance(edge, dict) and edge.get("count") is not None:
        try:
            return int(edge.get("count"))
        except (TypeError, ValueError):
            pass
    return None


def _parse_media_count_from_html(text):
    for pattern in (_PROFILE_MEDIA_EDGE_RE, _PROFILE_MEDIA_COUNT_RE):
        match = pattern.search(text or "")
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                continue
    return None


def _apply_profile_user(out, user):
    if not isinstance(user, dict):
        return out
    name = (user.get("full_name") or "").strip()
    if name:
        out["full_name"] = name
    mc = _parse_media_count_from_user(user)
    if mc is not None:
        out["media_count"] = mc
    for key in ("profile_pic_url_hd", "profile_pic_url"):
        url = (user.get(key) or "").strip()
        if url.startswith("http"):
            out[key] = url
            break
    hd = user.get("hd_profile_pic_url_info")
    if isinstance(hd, dict):
        url = (hd.get("url") or "").strip()
        if url.startswith("http"):
            out["profile_pic_url_hd"] = url
            out.setdefault("profile_pic_url", url)
    return out


def _profile_web_profile_request(username, *, csrf="", fresh_session=False):
    headers = _mobile_profile_headers(csrf)
    params = {"username": username}
    url = _PROFILE_WEB_URL
    if fresh_session:
        probe = requests.Session()
        try:
            _ig_http_get(
                "https://www.instagram.com/",
                headers={"User-Agent": _IG_WEB_UA},
                timeout=12,
                http=probe,
            )
            csrf = probe.cookies.get("csrftoken") or csrf
            headers = _mobile_profile_headers(csrf)
            return _ig_http_get(
                url, params=params, headers=headers, timeout=HUNT_LOOKUP_TIMEOUT, http=probe,
            )
        except Exception:
            return None
    try:
        return _ig_http_get(
            url, params=params, headers=headers, timeout=HUNT_LOOKUP_TIMEOUT, http=session,
        )
    except Exception:
        return None


def _profile_curl_request(username):
    """curl_cffi — chrome131_android on Termux (Posts count); chrome131 on desktop."""
    try:
        from curl_cffi import requests as curl_requests
    except ImportError:
        return None
    imp = "chrome131_android" if _is_termux() else "chrome131"
    proxy_kw = {}
    if vps_proxy_enabled():
        proxies = next(iter(proxy_attempts(proxy_tries=1)), None)
        if proxies:
            proxy_kw["proxies"] = proxies
    for label in ((imp,) if _is_termux() else (imp, "chrome131_android", "chrome124")):
        try:
            http = curl_requests.Session(impersonate=label)
            return http.get(
                _PROFILE_WEB_URL,
                params={"username": username},
                headers={
                    "X-IG-App-ID": _IG_MOBILE_APP_ID,
                    "User-Agent": _IG_MOBILE_UA,
                    "Accept-Language": "en-IN, en-US",
                },
                timeout=25,
                **proxy_kw,
            )
        except Exception:
            continue
    return None


def _profile_tls_request(username):
    if _is_termux():
        return None
    try:
        import tls_client
    except Exception:
        return None
    try:
        http = tls_client.Session(
            client_identifier="okhttp4_android_13",
            random_tls_extension_order=True,
        )
        return http.get(
            _PROFILE_WEB_URL,
            params={"username": username},
            headers={
                "X-IG-App-ID": _IG_MOBILE_APP_ID,
                "User-Agent": _IG_MOBILE_UA,
                "Accept-Language": "en-IN, en-US",
            },
            timeout_seconds=25,
        )
    except Exception:
        return None


def fetch_user_profile(username, pk=None):
    """
    Hit-time profile enrich: posts, name, pfp.
    web_profile_info is the only reliable media_count source (graphql hover omits it).
    """
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}
    pk = str(pk or "").strip()
    out = {
        "username": username,
        "full_name": None,
        "media_count": None,
        "profile_pic_url": None,
        "profile_pic_url_hd": None,
    }
    csrf, _lsd = load(force_refresh=False)

    curl_resp = _profile_curl_request(username)
    if curl_resp is not None and curl_resp.status_code == 200:
        user = (curl_resp.json().get("data") or {}).get("user") or {}
        if user:
            _apply_profile_user(out, user)
            if out["media_count"] is not None:
                return out

    tls_resp = _profile_tls_request(username)
    if tls_resp is not None and tls_resp.status_code == 200:
        user = (tls_resp.json().get("data") or {}).get("user") or {}
        if user:
            _apply_profile_user(out, user)
            if out["media_count"] is not None:
                return out

    for attempt in range(5):
        if attempt:
            time.sleep(1.2 + attempt * 0.8)
        if attempt in (2, 4):
            csrf, _lsd = load(force_refresh=True)
        resp = _profile_web_profile_request(
            username,
            csrf=csrf,
            fresh_session=(attempt >= 3),
        )
        if resp is None:
            continue
        if resp.status_code == 429:
            continue
        if resp.ok:
            user = (resp.json().get("data") or {}).get("user") or {}
            if user:
                _apply_profile_user(out, user)
                if out["media_count"] is not None:
                    return out

    if pk:
        try:
            gql_headers = {
                "User-Agent": _IG_WEB_UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "x-bloks-version-id": (
                    "ad0f1f5e41c2d9fcde83dfd68eea4def768b66bc3029c58e846d7c1dda44ba2a"
                ),
                "x-ig-app-id": "936619743392459",
                "x-fb-lsd": _lsd,
                "x-csrftoken": csrf,
                "origin": "https://www.instagram.com",
                "referer": f"https://www.instagram.com/{username}/",
            }
            payload = {
                "lsd": _lsd,
                "variables": json.dumps({"userID": pk, "username": username}),
                "doc_id": "7717269488336001",
            }
            resp = _ig_http_post(
                "https://www.instagram.com/api/graphql",
                headers=gql_headers,
                data=payload,
                timeout=INSTAGRAM_HTTP_TIMEOUT,
                http=session,
            )
            if not _ig_response_is_blocked(resp):
                body = resp.json()
                user = (body.get("data") or {}).get("user") or {}
                _apply_profile_user(out, user)
                if out["media_count"] is not None:
                    return out
        except Exception:
            pass

    try:
        resp = _ig_http_get(
            f"https://www.instagram.com/{username}/",
            headers={
                "User-Agent": _IG_WEB_UA,
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=HUNT_LOOKUP_TIMEOUT,
            http=session,
        )
        if resp.ok and not _ig_response_is_blocked(resp):
            mc = _parse_media_count_from_html(resp.text)
            if mc is not None:
                out["media_count"] = mc
    except Exception:
        pass

    return out


def _ig_gen_random_lsd(length=16):
    alphabet = "azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPMLKJHGFDSQWXCVBN1234567890"
    return "".join(random.choice(alphabet) for _ in range(length))


def _ig_gen_android_user_agent():
    android_ver = random.choice(
        ["23/6.0", "24/7.0", "25/7.1.1", "26/8.0", "27/8.1", "28/9.0"],
    )
    dpi = random.randint(100, 1300)
    w, h = random.randint(200, 2000), random.randint(200, 2000)
    brand = random.choice(
        [
            "SAMSUNG", "HUAWEI", "LGE/lge", "HTC", "ASUS", "ZTE",
            "ONEPLUS", "XIAOMI", "OPPO", "VIVO", "SONY", "REALME",
        ],
    )
    rnd = str(random.randint(_IG_GEN_USER_ID_MIN, _IG_GEN_USER_ID_MAX))
    rnd = str(random.randint(2500000000, 21254029834))
    return (
        f"Instagram 311.0.0.32.118 Android ({android_ver}; {dpi}dpi; {w}x{h}; "
        f"{brand}; SM-T{rnd}; SM-T{rnd}; qcom; en_US; 545986{random.randint(111, 999)})"
    )


def _ig_gen_profile_variables(user_id):
    return json.dumps(
        {
            "enable_integrity_filters": True,
            "id": str(user_id),
            "__relay_internal__pv__PolarisCannesGuardianExperienceEnabledrelayprovider": True,
            "__relay_internal__pv__PolarisCASB976ProfileEnabledrelayprovider": False,
            "__relay_internal__pv__PolarisWebSchoolsEnabledrelayprovider": False,
            "__relay_internal__pv__PolarisRepostsConsumptionEnabledrelayprovider": False,
        },
        separators=(",", ":"),
    )


def _parse_ig_gen_graphql_response(response):
    if response is None:
        return None, "no response"
    status = int(getattr(response, "status_code", 0) or 0)
    if status == 429:
        return None, "instagram rate limited (IP/VPN — wait or rotate)"
    if _ig_response_is_blocked(response):
        return None, "instagram blocked this IP (html response)"
    try:
        body = response.json()
    except ValueError:
        return None, "instagram bad response (not json)"
    if _ig_body_rate_limited(body):
        return None, "instagram rate limited (IP/VPN — wait or rotate)"
    user = (body.get("data") or {}).get("user")
    if not isinstance(user, dict) or not user.get("username"):
        return None, "no user in response"
    return user, ""


def _ig_gen_passes_min_followers(user, min_val):
    followers = user.get("follower_count")
    if followers is None:
        return False, "no follower_count in response"
    if int(followers) < int(min_val):
        return False, f"under {min_val} followers"
    return True, ""


def _gen_ig_graphql_post(min_val, *, retried=False, variant=0):
    """Random user_id → PolarisProfilePageContentQuery graphql (sinsta-style)."""
    if _ig_in_block_cooldown():
        return False, None, None, "instagram rate limited (IP/VPN — wait or rotate)"
    min_val = str(min_val)
    user_id = random.randrange(_IG_GEN_USER_ID_MIN, _IG_GEN_USER_ID_MAX)
    lsd = _ig_gen_random_lsd()
    headers = {
        "accept": "*/*",
        "accept-language": "en,en-US;q=0.9",
        "content-type": "application/x-www-form-urlencoded",
        "dnt": "1",
        "origin": "https://www.instagram.com",
        "priority": "u=1, i",
        "referer": "https://www.instagram.com/cristiano/following/",
        "user-agent": _ig_gen_android_user_agent(),
        "x-fb-friendly-name": "PolarisUserHoverCardContentV2Query",
        "x-fb-lsd": lsd,
    }
    data = {
        "lsd": lsd,
        "fb_api_caller_class": "RelayModern",
        "fb_api_req_friendly_name": "PolarisProfilePageContentQuery",
        "variables": _ig_gen_profile_variables(user_id),
        "server_timestamps": "true",
        "doc_id": _IG_GEN_GRAPHQL_DOC_ID,
    }
    try:
        response = _ig_http_post(
            _HUNT_IG_GRAPHQL_URL,
            data=data,
            headers=headers,
            timeout=INSTAGRAM_HTTP_TIMEOUT,
            http=_get_ig_graphql_session(),
        )
    except Exception as exc:
        return False, None, None, str(exc)[:200]
    user, err = _parse_ig_gen_graphql_response(response)
    if user is None:
        if not retried and err in (
            "instagram rate limited (IP/VPN — wait or rotate)",
            "instagram blocked this IP (html response)",
            "instagram bad response (not json)",
        ):
            _fetch_fresh_ig_tokens()
            return _gen_ig_graphql_post(min_val, retried=True, variant=variant)
        if "rate limited" in err or "blocked" in err:
            _mark_ig_gen_blocked()
        return False, None, None, err or "lookup failed"
    username = user.get("username")
    followers = user.get("follower_count")
    uid = user.get("pk")
    if not username or uid is None or followers is None:
        return False, None, None, "no user in response"
    ok_min, min_msg = _ig_gen_passes_min_followers(user, min_val)
    if not ok_min:
        return False, None, None, min_msg
    if "_" in str(username):
        return False, None, None, "underscore username"
    info = dict(user)
    info["generated_from_user_id"] = str(user_id)
    return (
        True,
        str(username),
        info,
        f"Account found with more than {min_val} followers.",
    )


def gen_ig_once(min_val, stop_event=None):
    """Several quick graphql tries — raises success rate vs one random id."""
    if _ig_in_block_cooldown():
        return False, None, None, "instagram rate limited (IP/VPN — wait or rotate)"
    min_val = str(min_val)
    last_msg = "no match"
    for attempt in range(IG_GEN_ONCE_INNER_TRIES):
        if stop_event is not None and stop_event.is_set():
            return False, None, None, "stopped"
        try:
            status, username, info, msg = _gen_ig_graphql_post(
                min_val, variant=attempt,
            )
        except Exception as exc:
            last_msg = str(exc)[:200]
            continue
        last_msg = msg
        if status and username:
            return True, username, info, msg
    return False, None, None, last_msg


def gen_ig(min_val, stop_event=None, max_attempts=None):
    """Retry until a username is found or cap reached."""
    global email
    min_val = str(min_val)
    cap = max(1, int(max_attempts or GEN_IG_MAX_ATTEMPTS))
    last_msg = "no match"
    for attempt in range(cap):
        if stop_event is not None and stop_event.is_set():
            return False, None, None, "stopped"
        status, username, info, msg = gen_ig_once(min_val, stop_event=stop_event)
        last_msg = msg
        if status and username:
            return True, username, info, msg
        if attempt + 1 < cap:
            time.sleep(0.015)
    return False, None, None, (
        f"Failed after {cap} attempts: {last_msg}"
    )


def _ig_gen_result_tuple(status, username, info_data, response_text):
    """Normalize — callers only treat as success when username is present."""
    username = str(username or "").strip()
    ok = bool(status and username)
    return ok, username if ok else None, info_data, response_text


def _buffer_try_get(min_val):
    min_val = str(min_val)
    buf = _ig_gen_buffers.get(min_val)
    if not buf:
        return None
    try:
        res = buf.get_nowait()
    except asyncio.QueueEmpty:
        return None
    if res and len(res) >= 4 and res[0] and res[1]:
        return res
    return None


def _ig_block_seconds_left() -> float:
    now = time.time()
    gen_left = max(0.0, _ig_gen_block_until - now)
    lookup_left = max(0.0, _ig_lookup_block_until - now)
    return max(gen_left, lookup_left)


def _ig_gen_block_seconds_left() -> float:
    if not _ig_in_gen_block_cooldown():
        return 0.0
    return max(0.0, _ig_gen_block_until - time.time())


def _ig_lookup_block_seconds_left() -> float:
    if not _ig_in_lookup_block_cooldown():
        return 0.0
    return max(0.0, _ig_lookup_block_until - time.time())



# --- IG wbloks contact recovery (inlined for 2-file release) ---
_RESPONSES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "responses")
os.makedirs(_RESPONSES_DIR, exist_ok=True)

WBLOCKS_HTTP_TIMEOUT = 20
BOOTSTRAP_HTTP_TIMEOUT = 15

RECOVERY_URL = "https://www.instagram.com/accounts/password/reset/"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
)

# Session cookies are still needed with the current hardcoded bloks payload.
# Removing them without a full logged-out bootstrap breaks fb_dtsg/lsd matching.
# Hardcoded sessionid is often expired → IG returns 429 on bootstrap. Prefer logged-out;
# bootstrap_recovery_session() falls back automatically when logged-in tokens are missing.
USE_LOGGED_IN_SESSION = False

BASE_COOKIES = {
    "datr": "drueaT-Mec1uOMARZ5giSXbi",
    "ig_did": "01076FE5-57FB-4B7F-A186-50F2047AEE9C",
    "mid": "aZ67dgABAAGBHw-P3_ILGWvl1aRb",
    "ps_l": "1",
    "ps_n": "1",
    "dpr": "2.4000000953674316",
}
LOGGED_IN_COOKIES = {
    "ds_user_id": "56939731259",
    "sessionid": (
        "56939731259%3AzJPg6MVevx6U61%3A0%3A"
        "AYg9Wj7ogENEcHzHm9Im4Fn569nDlukhSk-MSgKqwxw"
    ),
    "rur": (
        '"CLN\\05456939731259\\0541812871654:01ffc82fb81c546526b7299310cb47d23'
        "fbb0d178c7bb68ca255ce2fb9ed7489e494dcb4\""
    ),
}

ARM_CONTEXT_RE = re.compile(r"Ad[A-Za-z0-9_-]{20,}\|arm")
AUTH_METHOD_TOKEN_RE = r"Ad[A-Za-z0-9_-]{20,320}"
AUTH_METHOD_ASYNC_PATTERNS = (
    rf'\\"phone\\",\s*false,\s*false,\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    rf'\\"email\\",\s*false,\s*false,\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    rf'\\"phone\\",\s*(?:true|false),\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    rf'\\"email\\",\s*(?:true|false),\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    rf'\\"password\\",\s*(?:true|false),\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    rf'\\"(?:phone|email|password)\\",\s*(?:true|false),\s*(?:true|false),\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
)
MASKED_EMAIL_RE = re.compile(r"[a-zA-Z0-9]\*+[a-zA-Z0-9]@[a-zA-Z0-9\*\.\-]+")
FULL_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
SENT_CODE_EMAIL_RE = re.compile(
    r"We sent a code to ([a-zA-Z0-9*._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)
MASKED_PHONE_RE = re.compile(r"\+\d{1,3}(?:\s+[\*]+\s*)+\d{2,4}")
AUTH_METHOD_APPID = "com.bloks.www.caa.ar.auth_method"
EMAIL_CONFIRM_APPID = "com.bloks.www.caa.ar.authentication_confirmation"
EMAIL_CONFIRM_ASYNC_APPID = "com.bloks.www.caa.ar.authentication_confirmation.async"
INITIATE_VIEW_APPID = "com.bloks.www.caa.ar.initiate_view"
STEP2_ROUTE_RE = re.compile(
    r'app_id\\",\s*\\"(com\.bloks\.www\.caa\.ar\.(?:auth_method|authentication_confirmation))\\"'
    r',\s*\\"tti_marker_id\\",\s*\d+,\s*\\"screen_id\\",\s*\\"([^\\]+)\\"'
)
STEP4_ROUTE_RE = re.compile(
    r'app_id\\",\s*\\"com\.bloks\.www\.caa\.ar\.initiate_view\\"'
    r',\s*\\"tti_marker_id\\",\s*\d+,\s*\\"screen_id\\",\s*\\"([^\\]+)\\"'
)


def strip_ig_json_prefix(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("for (;;);"):
        return text[9:].strip()
    return text


def extract_arm_context_token(text: str) -> str | None:
    """Pull IG bloks context_data token (Ad...|arm) from wbloks response text."""
    body = strip_ig_json_prefix(text)
    if not body:
        return None
    match = ARM_CONTEXT_RE.search(body)
    return match.group(0) if match else None


def _auth_method_tokens(body: str, method: str) -> list[str]:
    tokens: list[str] = []
    for pattern in (
        rf'\\"{method}\\",\s*false,\s*false,\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
        rf'\\"{method}\\",\s*(?:true|false),\s*\\"({AUTH_METHOD_TOKEN_RE})\\"',
    ):
        for match in re.finditer(pattern, body):
            token = match.group(1)
            if "|arm" not in token:
                tokens.append(token)
    return tokens


def _best_auth_token(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    return min(tokens, key=len)


def extract_auth_method_async_params(text: str) -> str | None:
    """Pull auth_method_async_params token from step2 auth_method response."""
    body = strip_ig_json_prefix(text)
    if not body:
        return None
    for pattern in AUTH_METHOD_ASYNC_PATTERNS:
        match = re.search(pattern, body)
        if not match:
            continue
        token = match.group(1)
        if "|arm" not in token:
            return token
    return None


def extract_auth_method_options(text: str) -> list[tuple[str, str]]:
    """Return auth methods offered on step2, e.g. [('phone', 'Ad...'), ('email', 'Ad...')]."""
    body = strip_ig_json_prefix(text)
    if not body:
        return []
    options: list[tuple[str, str]] = []
    for method in ("email", "phone", "password"):
        token = _best_auth_token(_auth_method_tokens(body, method))
        if token:
            options.append((method, token))
    return options


def pick_step3_auth(
    options: list[tuple[str, str]], response_text: str = ""
) -> tuple[str, str, str]:
    """Choose step3 auth_method, async token, and is_auth_method_rejected."""
    methods = {method: token for method, token in options}
    if "phone" in methods:
        return "phone", methods["phone"], "1"
    if "email" in methods:
        return "email", methods["email"], "0"

    body = strip_ig_json_prefix(response_text)
    if extract_masked_phone(response_text) or "mobile number" in body.lower():
        token = extract_auth_method_async_params(response_text)
        if token:
            return "phone", token, "1"

    if "password" in methods:
        return "password", methods["password"], "0"
    return "phone", "", "1"


def extract_step2_route(text: str) -> tuple[str, str]:
    """Read step1 bloks payload for the next recovery screen."""
    body = strip_ig_json_prefix(text)
    match = STEP2_ROUTE_RE.search(body or "")
    if match:
        return match.group(1), match.group(2)
    return AUTH_METHOD_APPID, "19q6u5:2"


def is_dual_auth_flow(appid: str) -> bool:
    return appid == AUTH_METHOD_APPID


def extract_confirmation_async_context(text: str) -> str | None:
    """Token for Try another way -> authentication_confirmation.async."""
    body = strip_ig_json_prefix(text)
    pos = body.find("authentication_confirmation.async")
    if pos < 0:
        return None
    chunk = body[pos : pos + 12000]
    tokens = [
        t for t in re.findall(r"Ad[A-Za-z0-9_-]{20,512}", chunk)
        if "|arm" not in t
    ]
    return max(tokens, key=len) if tokens else None


def extract_qpl_instance_id(
    text: str, anchor: str = "authentication_confirmation.async"
) -> str | None:
    body = strip_ig_json_prefix(text)
    pos = body.find(anchor)
    if pos < 0:
        return None
    match = re.search(r"i64\.Const,\s*(\d+)", body[pos : pos + 12000])
    return match.group(1) if match else None


def extract_step4_screen_id(text: str) -> str | None:
    body = strip_ig_json_prefix(text)
    match = STEP4_ROUTE_RE.search(body or "")
    return match.group(1) if match else None


def extract_visible_texts(text: str) -> list[str]:
    body = strip_ig_json_prefix(text)
    if not body:
        return []
    seen: set[str] = set()
    visible: list[str] = []
    for raw in re.findall(r'"text":"((?:\\.|[^"\\])*)"', body):
        item = raw
        if "\\u" in item:
            try:
                item = bytes(item, "utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                pass
        item = item.replace("\\u0040", "@").strip()
        if not item or item in seen or item.startswith("(bk."):
            continue
        seen.add(item)
        visible.append(item)
    return visible


def log_masked_contacts(label: str, text: str) -> None:
    masked_email = extract_masked_email(text)
    masked_phone = extract_masked_phone(text)
    print(f"[{label}] masked_email: {masked_email or 'NOT FOUND'}")
    print(f"[{label}] masked_phone: {masked_phone or 'NOT FOUND'}")
    visible = extract_visible_texts(text)
    useful = [
        t for t in visible
        if "@" in t or "*" in t or "email" in t.lower() or "sms" in t.lower()
        or "password" in t.lower() or "choose" in t.lower() or "incorrect" in t.lower()
    ]
    if useful:
        print(f"[{label}] visible:")
        for item in useful:
            print(f"  - {item}")


def _clean_masked_email(value: str) -> str:
    return value.rstrip(".,;:!? ")


def extract_masked_email(text: str) -> str | None:
    body = strip_ig_json_prefix(text).replace("\\u0040", "@")
    if not body:
        return None
    sent_code = SENT_CODE_EMAIL_RE.search(body)
    if sent_code:
        return _clean_masked_email(sent_code.group(1))
    match = MASKED_EMAIL_RE.search(body)
    if match:
        return _clean_masked_email(match.group(0))
    for item in extract_visible_texts(text):
        sent_code = SENT_CODE_EMAIL_RE.search(item)
        if sent_code:
            return _clean_masked_email(sent_code.group(1))
        embedded = MASKED_EMAIL_RE.search(item)
        if embedded:
            return _clean_masked_email(embedded.group(0))
        if "*" in item and "@" in item:
            return _clean_masked_email(item)
        if FULL_EMAIL_RE.fullmatch(item.strip()):
            return item.strip()
    return None


def extract_masked_phone(text: str) -> str | None:
    body = strip_ig_json_prefix(text)
    if not body:
        return None
    match = MASKED_PHONE_RE.search(body)
    if match:
        return match.group(0)
    for item in extract_visible_texts(text):
        if item.startswith("+") and "*" in item:
            return item
    return None


def log_context_token(label: str, token: str | None) -> None:
    if not token:
        print(f"[{label}] context_data token: NOT FOUND")
        return
    print(
        f"[{label}] context_data token: {token[:20]}...{token[-8:]} "
        f"({len(token)} chars)"
    )


def log_auth_method_async_token(label: str, token: str | None) -> None:
    if not token:
        print(f"[{label}] auth_method_async_params: NOT FOUND")
        return
    print(
        f"[{label}] auth_method_async_params: {token[:20]}...{token[-8:]} "
        f"({len(token)} chars)"
    )


def jazoest_from_dtsg(fb_dtsg: str) -> str:
    return str(2 + sum(ord(c) for c in fb_dtsg))


def _bootstrap_pull(use_logged_in: bool, *, http_timeout: int = BOOTSTRAP_HTTP_TIMEOUT) -> dict:
    """Single bootstrap attempt against the password-reset page."""
    sess = requests.Session()
    cookies = BASE_COOKIES.copy()
    if use_logged_in:
        cookies.update(LOGGED_IN_COOKIES)
    sess.cookies.update(cookies)
    resp = _ig_http_get(
        RECOVERY_URL,
        headers={"user-agent": USER_AGENT, "accept-language": "en-US"},
        timeout=http_timeout,
        http=sess,
    )
    html = resp.text or ""
    lsd = (re.search(r'"LSD",\[\],\{"token":"([^"]+)"', html) or [None, ""])[1]
    fb_dtsg = (re.search(r'"dtsg":\{"token":"([^"]+)"', html) or [None, ""])[1]
    rev = (re.search(r'"client_revision":(\d+)', html) or [None, ""])[1]
    hsi = (re.search(r'"hsi":"(\d+)"', html) or [None, ""])[1]
    spin_t = (re.search(r'"__spin_t":(\d+)', html) or [None, ""])[1]
    merged = cookies.copy()
    merged.update(requests.utils.dict_from_cookiejar(sess.cookies))
    return {
        "cookies": merged,
        "lsd": (lsd or "").strip(),
        "fb_dtsg": (fb_dtsg or "").strip(),
        "jazoest": jazoest_from_dtsg(fb_dtsg) if fb_dtsg else "",
        "__rev": rev,
        "__spin_r": rev,
        "__hsi": hsi,
        "__spin_t": spin_t,
        "status_code": resp.status_code,
        "used_logged_in": use_logged_in,
    }


def bootstrap_recovery_session(
    use_logged_in: bool = USE_LOGGED_IN_SESSION,
    *,
    http_timeout: int = BOOTSTRAP_HTTP_TIMEOUT,
) -> dict:
    """Refresh csrftoken + fb_dtsg + lsd; fall back to logged-out if logged-in is stale."""
    boot = _bootstrap_pull(use_logged_in, http_timeout=http_timeout)
    if (not boot["lsd"] or not boot["fb_dtsg"]) and use_logged_in:
        boot = _bootstrap_pull(False, http_timeout=http_timeout)
        boot["fallback_logged_out"] = True
    if boot.get("status_code") == 429:
        boot["rate_limited"] = True
    return boot


def apply_session_tokens(data: dict, boot: dict) -> None:
    for key in ("fb_dtsg", "lsd", "jazoest", "__rev", "__spin_r", "__hsi", "__spin_t"):
        value = boot.get(key)
        if value:
            data[key] = value


def check_ig_response(label: str, text: str) -> bool:
    body = strip_ig_json_prefix(text)
    if "session expired" in body.lower():
        print(f"[{label}] IG session expired in response")
    if '"error":' not in body:
        return True
    summary = re.search(r'"errorSummary":"([^"]+)"', body)
    print(f"[{label}] IG error: {summary.group(1) if summary else body[:120]}")
    return False


def run_recovery(
    username: str,
    *,
    verbose: bool = False,
    http_timeout: int = WBLOCKS_HTTP_TIMEOUT,
    write_responses: bool = True,
) -> dict:
    """Run the 4-step IG recovery flow and return masked contacts."""
    started = time.perf_counter()
    contacts = {"email": None, "phone": None}

    def merge(text: str) -> None:
        email = extract_masked_email(text)
        phone = extract_masked_phone(text)
        if email:
            contacts["email"] = email
        if phone:
            contacts["phone"] = phone

    boot = bootstrap_recovery_session(http_timeout=http_timeout)
    if verbose:
        print(
            "[bootstrap] session ready:"
            f" logged_in={boot.get('used_logged_in')}"
            f" fallback={boot.get('fallback_logged_out')}"
            f" status={boot.get('status_code')}"
            f" csrftoken={bool(boot['cookies'].get('csrftoken'))}"
            f" lsd={bool(boot['lsd'])}"
            f" fb_dtsg={bool(boot['fb_dtsg'])}"
        )

    if boot.get("rate_limited") or not boot.get("lsd") or not boot.get("fb_dtsg"):
        err = "rate_limited" if boot.get("rate_limited") or boot.get("status_code") == 429 else "session_bootstrap_failed"
        return {
            "ok": False,
            "username": username,
            "flow": "unknown",
            "email": None,
            "phone": None,
            "error": err,
            "response_time_ms": round((time.perf_counter() - started) * 1000),
        }

    cookies = {**boot["cookies"], "wd": "450x1231"}
    headers = {
        "accept": "*/*",
        "accept-language": "en-US",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "origin": "https://www.instagram.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": RECOVERY_URL,
        "sec-ch-prefers-color-scheme": "dark",
        "sec-ch-ua": '"Chromium";v="127", "Not)A;Brand";v="99", "Microsoft Edge Simulate";v="127", "Lemur";v="127"',
        "sec-ch-ua-full-version-list": '"Chromium";v="127.0.6533.144", "Not)A;Brand";v="99.0.0.0", "Microsoft Edge Simulate";v="127.0.6533.144", "Lemur";v="127.0.6533.144"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-model": '"V2249"',
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": USER_AGENT,
        "x-fb-lsd": boot["lsd"],
    }

    params = {
        "appid": "com.bloks.www.caa.ar.search.async",
        "type": "action",
        "__bkv": "487c52f1e99f6fe3faee06af68ac70f38b5a53f74509a278bba9db63a261bc12",
    }

    data = {
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "j",
        "__hs": "20617.HYP:instagram_web_pkg.2.1...0",
        "dpr": "3",
        "__ccg": "GOOD",
        "__rev": "1041417520",
        "__s": "1sndd2:lncbw1:xx4sk7",
        "__hsi": "7650768943143544687",
        "__dyn": "7xeUjG1mwt8K2Wmh0no6u5U4e0yoW3q32360CEbo1nEhw2nVE4W0qa0FE2awt81s8hwGwQwoEcE7O2l0Fwqo31w9O0H8jwae4UaEW2G0AEco5G0zK5o4q0HU1IEGdwtU662O0Lo6-3u2WE15E6O1FwlAcwnJ6goK1sAwHxW1ow8q0EoK9x60ma1XwqU1eUdo",
        "__csr": "hA4Ivf92fnlEDTnlvt7p5mRF_P39bj-KFD-UK9BHC-jIxHFoGj8UXx2ch4Upxi6Zx62OE-8aGVAhUSfByqgZ16qaAUlF6CByFUZ4UC8z9byrzEsyE8qwsU4Nxu5Ea98K3eEkDy9E4a9-mU4K3y4oO2K4Elwlo6iE3KxC5E05q602DK00ReXyU3Mw0Lva04GqzU0yK0cAy43G0L81EFnw7eohDS09Ag1ySEjglO0YDo0hzzo5p00h4E0Ny03qS0eiCg",
        "__hsdp": "gN2sAehsWpwidhk8Bm4O1-Q9wC-1NwaiEc84O06wFo04m605PU9U1eE0lNg12o",
        "__hblp": "0hU1_awMzE4C0SUhwRwd63a3C0OE6W0kK3C1WwrU1fE0Jy0z808WqU14U1gE1Vo1vodU3Lw3ao9U1eKq0cvw4Jw4qg2Bzo5m1Qw9u0vzw",
        "__sjsp": "gN2sAehsWpwidh7d55m4O1-Q9wC-1NwaiEc8",
        "__comet_req": "7",
        "fb_dtsg": "NAfymb2QzhE0qJt5HmdklBo1XrG460g0sEGawhllKvoA5S2OSuPH2sA:17865145036029998:1779424198",
        "jazoest": "26257",
        "lsd": "VPpBvZBNDdErkCT1Jbn2T3",
        "__spin_r": "1041417520",
        "__spin_b": "trunk",
        "__spin_t": "1781333457",
        "__crn": "comet.igweb.PolarisWebBloksAccountRecoveryRoute",
        "params": '{"params":"{\\"server_params\\":{\\"event_request_id\\":\\"5c2d5ee9-f0f2-4c44-8e89-612a38e875b2\\",\\"INTERNAL__latency_qpl_marker_id\\":36707139,\\"INTERNAL__latency_qpl_instance_id\\":\\"217380720300109\\",\\"device_id\\":\\"aZ67dgABAAGBHw-P3_ILGWvl1aRb\\",\\"family_device_id\\":null,\\"waterfall_id\\":null,\\"offline_experiment_group\\":null,\\"layered_homepage_experiment_group\\":null,\\"is_platform_login\\":0,\\"is_from_logged_in_switcher\\":0,\\"is_from_logged_out\\":0,\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"unknown\\",\\"context_data\\":\\"AdBQTjHuBAMk8-R968o5JMQWYgV4QPZHKf-As029YpJ8rk2nxmXp9psDta8ax-c1Kt_MNvWHOS8NLW3aoxu28q6VXjLb1CD-MoY5bO4Vg7ZV_LpppM5Ofm94CXKRqAm981Aq9cBJwMUst2EIV6PRsenxqHdTAOZtg2dAOQVOur_2p3f2S-KncvFHFUVtRTjmIzbHwQzGQd3UeN8JTMcoahKE3cZMQu0t8XRx1r_9OUk3x9mSCwKuBJ2YY4MkNCotvnVYvUOJ68SGaCRl9VHRbe1XG7Wv3NqwtLbF-D0982Cgz3evLuQ7D9BL3ncsfDJwYNt_UE2qA1SLLBdxZQ3YeGikksoD5iomy9NM3l9R4o9Ybxmso13v6nofG_L_RYHT4wZ4m1WMYN9cfexavfMwh3oUUd65VYtSlwrYYlOYH6O0ro0UKeQ|arm\\"},\\"client_input_params\\":{\\"zero_balance_state\\":null,\\"search_query\\":\\"'
        + username
        + '\\",\\"fetched_email_list\\":[],\\"fetched_email_token_list\\":{},\\"sso_accounts_auth_data\\":[],\\"sfdid\\":\\"\\",\\"text_input_id\\":\\"zy88df:105\\",\\"encrypted_msisdn\\":\\"\\",\\"headers_infra_flow_id\\":\\"\\",\\"was_headers_prefill_available\\":0,\\"was_headers_prefill_used\\":0,\\"ig_oauth_token\\":[],\\"android_build_type\\":\\"\\",\\"is_whatsapp_installed\\":0,\\"device_network_info\\":null,\\"accounts_list\\":[],\\"is_oauth_without_permission\\":0,\\"search_screen_type\\":\\"email_or_username\\",\\"ig_vetted_device_nonce\\":\\"\\",\\"gms_incoming_call_retriever_eligibility\\":\\"client_not_supported\\",\\"auth_secure_device_id\\":\\"\\",\\"blocked_uids\\":[],\\"cloud_trust_token\\":null,\\"network_bssid\\":null,\\"lois_settings\\":{\\"lois_token\\":\\"\\"},\\"aac\\":\\"\\"}}"}',
    }

    apply_session_tokens(data, boot)
    response = _ig_http_post(
        "https://www.instagram.com/async/wbloks/fetch/",
        cookies=cookies,
        params=params,
        headers=headers,
        data=data,
        timeout=http_timeout,
    )
    if write_responses:
        with open(os.path.join(_RESPONSES_DIR, "1.html"), "w") as f:
            f.write(response.text)
    if verbose:
        check_ig_response("step1/search", response.text)

    body1 = strip_ig_json_prefix(response.text)
    if not body1 or body1.startswith("<!DOCTYPE") or '"error":' in body1:
        err = "rate_limited" if response.status_code == 429 else "search_failed"
        return {
            "ok": False,
            "username": username,
            "flow": "unknown",
            "email": None,
            "phone": None,
            "error": err,
            "response_time_ms": round((time.perf_counter() - started) * 1000),
        }

    context_token = extract_arm_context_token(response.text)
    if verbose:
        log_context_token("step1/search", context_token)
    if not context_token:
        return {
            "ok": False,
            "username": username,
            "flow": "unknown",
            "email": None,
            "phone": None,
            "error": "search_failed",
            "response_time_ms": round((time.perf_counter() - started) * 1000),
        }
    step2_appid, step2_screen_id = extract_step2_route(response.text)
    flow = "dual_auth" if is_dual_auth_flow(step2_appid) else "email_confirmation"
    if verbose:
        print(f"[step1/search] next_step: {step2_appid} screen_id={step2_screen_id}")

    cookies = {**boot["cookies"], "wd": "450x908"}
    params = {
        "appid": step2_appid,
        "type": "app",
        "__bkv": "487c52f1e99f6fe3faee06af68ac70f38b5a53f74509a278bba9db63a261bc12",
    }
    data = {
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "h",
        "__hs": "20617.HYP:instagram_web_pkg.2.1...0",
        "dpr": "3",
        "__ccg": "GOOD",
        "__rev": "1041417520",
        "__s": "xndytq:2om9fa:zax0fu",
        "__hsi": "7650778362067551766",
        "__dyn": "7xeUjG1mwt8K2Wmh0no6u5U4e0yoW3q32360CEbo1nEhw2nVE4W0qa0FE2awt81s8hwGwQwoEcE7O2l0Fwqo31w9O0H8jwae4UaEW2G0AEco5G0zK5o4q0HU1IEGdwtU662O0Lo6-3u2WE15E6O1FwlAcwnJ6goK1sAwHxW1ow8q0EoK9x60ma1XwqU1eUdo",
        "__csr": "hA4Ivf92fnlEDTnlvt7p5mRF_P39bj-KFD-UK9BHC-jIxHFoGj8UXx2ch4Upxi6Zx62OE-8aGVAhUSfByqgZ16qaAUlF6CByFUZ4UC8z9byrzEsyE8qwsU4Nxu5Ea98K3eEkDy9E4a9-mU4K3y4oO2K4Elwlo6iE3KxC5E05q602DK00ReXyU3Mw0Lva04GqzU0yK0cAy43G0L81EFnw7eohDS09Ag1ySEjglO0YDo0hzzo5p00h4E0Ny03qS0eiCg",
        "__hsdp": "gN2sAehsWpwidhk8Bm4O1-Q9wC-1NwaiEc84O06wFo04m605PU9U1eE0lNg12o",
        "__hblp": "0hU1_awMzE4C0SUhwRwd63a3C0OE6W0kK3C1WwrU1fE0Jy0z808WqU14U1gE1Vo1vodU3Lw3ao9U1eKq0cvw4Jw4qg2Bzo5m1Qw9u0vzw",
        "__sjsp": "gN2sAehsWpwidh7d55m4O1-Q9wC-1NwaiEc8",
        "__comet_req": "7",
        "fb_dtsg": "NAfwgBQ5L6qN3fDL2pmmdD7GfBSHPperppqQ9KLczLmR5vmafOLQB0w:17865145036029998:1779424198",
        "jazoest": "26298",
        "lsd": "l9h56dXX4RkIO7nYnFO28K",
        "__spin_r": "1041417520",
        "__spin_b": "trunk",
        "__spin_t": "1781335650",
        "__crn": "comet.igweb.PolarisWebBloksAccountRecoveryRoute",
        "params": (
            '{"params":"{\\"server_params\\":{\\"device_id\\":\\"aZ67dgABAAGBHw-P3_ILGWvl1aRb\\",'
            '\\"is_platform_login\\":0,\\"is_from_logged_out\\":0,'
            '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
            '\\"login_entry_point\\":\\"account_recovery\\",\\"context_data\\":\\"{context_data}\\",'
            '\\"back_nav_action\\":\\"BACK\\",\\"INTERNAL_INFRA_screen_id\\":\\"{screen_id}\\"},'
            '\\"client_input_params\\":{\\"lois_settings\\":{\\"lois_token\\":\\"\\"},'
            '\\"zero_balance_state\\":\\"\\",\\"aac\\":\\"\\"}}"}'
        )
        .replace("{context_data}", context_token or "")
        .replace("{screen_id}", step2_screen_id or "19q6u5:2"),
    }

    apply_session_tokens(data, boot)
    response = _ig_http_post(
        "https://www.instagram.com/async/wbloks/fetch/",
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
        timeout=http_timeout,
    )
    if write_responses:
        with open(os.path.join(_RESPONSES_DIR, "2.html"), "w") as f:
            f.write(response.text)
    if verbose:
        check_ig_response("step2", response.text)

    context_token = extract_arm_context_token(response.text) or context_token
    step2_arm_context = context_token
    step2_label = "auth_method" if is_dual_auth_flow(step2_appid) else "authentication_confirmation"
    merge(response.text)
    if verbose:
        log_context_token("step2", context_token)
        log_masked_contacts(f"step2/{step2_label}", response.text)

    if is_dual_auth_flow(step2_appid):
        auth_options = extract_auth_method_options(response.text)
        step3_auth_method, auth_method_async_token, step3_auth_rejected = pick_step3_auth(
            auth_options, response.text
        )
        if not auth_method_async_token:
            auth_method_async_token = extract_auth_method_async_params(response.text)
        step3_appid = "com.bloks.www.caa.ar.auth_method.async"
        step3_context = context_token or ""
        step3_params = (
            '{"params":"{\\"server_params\\":{\\"device_id\\":\\"aZ67dgABAAGBHw-P3_ILGWvl1aRb\\",'
            '\\"auth_method\\":\\"{auth_method}\\",\\"is_auth_method_rejected\\":{is_auth_method_rejected},'
            '\\"auth_method_async_params\\":\\"{auth_method_async_params}\\",\\"context_data\\":\\"{context_data}\\",'
            '\\"INTERNAL__latency_qpl_marker_id\\":36707139,'
            '\\"INTERNAL__latency_qpl_instance_id\\":\\"7694035200197\\",'
            '\\"family_device_id\\":null,\\"waterfall_id\\":null,'
            '\\"offline_experiment_group\\":null,\\"layered_homepage_experiment_group\\":null,'
            '\\"is_platform_login\\":0,\\"is_from_logged_in_switcher\\":0,\\"is_from_logged_out\\":0,'
            '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
            '\\"login_entry_point\\":\\"account_recovery\\"},'
            '\\"client_input_params\\":{\\"zero_balance_state\\":\\"\\",\\"android_build_type\\":\\"\\",'
            '\\"cloud_trust_token\\":null,\\"network_bssid\\":null,'
            '\\"lois_settings\\":{\\"lois_token\\":\\"\\"},\\"aac\\":\\"\\"}}"}'
        )
        step3_params = (
            step3_params.replace("{auth_method}", step3_auth_method or "phone")
            .replace("{is_auth_method_rejected}", step3_auth_rejected or "1")
            .replace("{auth_method_async_params}", auth_method_async_token or "")
            .replace("{context_data}", step3_context)
        )
        step3_label = "auth_method_async"
    else:
        step3_appid = EMAIL_CONFIRM_ASYNC_APPID
        step3_context = step2_arm_context or context_token or ""
        step3_qpl_instance = extract_qpl_instance_id(response.text) or "7694035200197"
        step3_params = (
            '{"params":"{\\"server_params\\":{\\"device_id\\":\\"aZ67dgABAAGBHw-P3_ILGWvl1aRb\\",'
            '\\"event_request_id\\":\\"{event_request_id}\\",'
            '\\"is_auth_method_rejected\\":1,\\"context_data\\":\\"{context_data}\\",'
            '\\"INTERNAL__latency_qpl_marker_id\\":36707139,'
            '\\"INTERNAL__latency_qpl_instance_id\\":\\"{qpl_instance_id}\\",'
            '\\"family_device_id\\":null,\\"waterfall_id\\":null,'
            '\\"offline_experiment_group\\":null,\\"layered_homepage_experiment_group\\":null,'
            '\\"is_platform_login\\":0,\\"is_from_logged_in_switcher\\":0,\\"is_from_logged_out\\":0,'
            '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
            '\\"login_entry_point\\":\\"account_recovery\\"},'
            '\\"client_input_params\\":{\\"zero_balance_state\\":\\"\\",\\"android_build_type\\":\\"\\",'
            '\\"cloud_trust_token\\":null,\\"network_bssid\\":null,'
            '\\"lois_settings\\":{\\"lois_token\\":\\"\\"},\\"aac\\":\\"\\"}}"}'
            .replace("{event_request_id}", str(uuid.uuid4()))
            .replace("{qpl_instance_id}", step3_qpl_instance)
            .replace("{context_data}", step3_context)
        )
        step3_label = "authentication_confirmation.async"

    params = {
        "appid": step3_appid,
        "type": "action",
        "__bkv": "487c52f1e99f6fe3faee06af68ac70f38b5a53f74509a278bba9db63a261bc12",
    }
    data = {
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "k",
        "__hs": "20617.HYP:instagram_web_pkg.2.1...0",
        "dpr": "3",
        "__ccg": "GOOD",
        "__rev": "1041417520",
        "__s": "xndytq:2om9fa:zax0fu",
        "__hsi": "7650778362067551766",
        "__dyn": "7xeUjG1mwt8K2Wmh0no6u5U4e0yoW3q32360CEbo1nEhw2nVE4W0qa0FE2awt81s8hwGwQwoEcE7O2l0Fwqo31w9O0H8jwae4UaEW2G0AEco5G0zK5o4q0HU1IEGdwtU662O0Lo6-3u2WE15E6O1FwlAcwnJ6goK1sAwHxW1ow8q0EoK9x60ma1XwqU1eUdo",
        "__csr": "hA4Ivf92fnlEDTnlvt7p5mRF_P39bj-KFD-UK9BHC-jIxHFoGj8UXx2ch4Upxi6Zx62OE-8aGVAhUSfByqgZ16qaAUlF6CByFUZ4UC8z9byrzEsyE8qwsU4Nxu5Ea98K3eEkDy9E4a9-mU4K3y4oO2K4Elwlo6iE3KxC5E05q602DK00ReXyU3Mw0Lva04GqzU0yK0cAy43G0L81EFnw7eohDS09Ag1ySEjglO0YDo0hzzo5p00h4E0Ny03qS0eiCg",
        "__hsdp": "gN2sAehsWpwidhk8Bm4O1-Q9wC-1NwaiEc84O06wFo04m605PU9U1eE0lNg12o",
        "__hblp": "0hU1_awMzE4C0SUhwRwd63a3C0OE6W0kK3C1WwrU1fE0Jy0z808WqU14U1gE1Vo1vodU3Lw3ao9U1eKq0cvw4Jw4qg2Bzo5m1Qw9u0vzw",
        "__sjsp": "gN2sAehsWpwidh7d55m4O1-Q9wC-1NwaiEc8",
        "__comet_req": "7",
        "fb_dtsg": "NAfwgBQ5L6qN3fDL2pmmdD7GfBSHPperppqQ9KLczLmR5vmafOLQB0w:17865145036029998:1779424198",
        "jazoest": "26298",
        "lsd": "l9h56dXX4RkIO7nYnFO28K",
        "__spin_r": "1041417520",
        "__spin_b": "trunk",
        "__spin_t": "1781335650",
        "__crn": "comet.igweb.PolarisWebBloksAccountRecoveryRoute",
        "params": step3_params,
    }

    apply_session_tokens(data, boot)
    response = _ig_http_post(
        "https://www.instagram.com/async/wbloks/fetch/",
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
        timeout=http_timeout,
    )
    if write_responses:
        with open(os.path.join(_RESPONSES_DIR, "3.html"), "w") as f:
            f.write(response.text)
    if verbose:
        check_ig_response(f"step3/{step3_label}", response.text)
        log_context_token(f"step3/{step3_label}", extract_arm_context_token(response.text))
        log_masked_contacts(f"step3/{step3_label}", response.text)

    context_token = extract_arm_context_token(response.text) or context_token
    step4_screen_id = extract_step4_screen_id(response.text) or "19w3pw:2"
    step4_context = context_token or step2_arm_context

    params = {
        "appid": INITIATE_VIEW_APPID,
        "type": "app",
        "__bkv": "487c52f1e99f6fe3faee06af68ac70f38b5a53f74509a278bba9db63a261bc12",
    }
    data = {
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": "l",
        "__hs": "20617.HYP:instagram_web_pkg.2.1...0",
        "dpr": "3",
        "__ccg": "GOOD",
        "__rev": "1041417520",
        "__s": "xndytq:2om9fa:zax0fu",
        "__hsi": "7650778362067551766",
        "__dyn": "7xeUjG1mwt8K2Wmh0no6u5U4e0yoW3q32360CEbo1nEhw2nVE4W0qa0FE2awt81s8hwGwQwoEcE7O2l0Fwqo31w9O0H8jwae4UaEW2G0AEco5G0zK5o4q0HU1IEGdwtU662O0Lo6-3u2WE15E6O1FwlAcwnJ6goK1sAwHxW1ow8q0EoK9x60ma1XwqU1eUdo",
        "__csr": "hA4Ivf92fnlEDTnlvt7p5mRF_P39bj-KFD-UK9BHC-jIxHFoGj8UXx2ch4Upxi6Zx62OE-8aGVAhUSfByqgZ16qaAUlF6CByFUZ4UC8z9byrzEsyE8qwsU4Nxu5Ea98K3eEkDy9E4a9-mU4K3y4oO2K4Elwlo6iE3KxC5E05q602DK00ReXyU3Mw0Lva04GqzU0yK0cAy43G0L81EFnw7eohDS09Ag1ySEjglO0YDo0hzzo5p00h4E0Ny03qS0eiCg",
        "__hsdp": "gN2sAehsWpwidhk8Bm4O1-Q9wC-1NwaiEc84O06wFo04m605PU9U1eE0lNg12o",
        "__hblp": "0hU1_awMzE4C0SUhwRwd63a3C0OE6W0kK3C1WwrU1fE0Jy0z808WqU14U1gE1Vo1vodU3Lw3ao9U1eKq0cvw4Jw4qg2Bzo5m1Qw9u0vzw",
        "__sjsp": "gN2sAehsWpwidh7d55m4O1-Q9wC-1NwaiEc8",
        "__comet_req": "7",
        "fb_dtsg": "NAfwgBQ5L6qN3fDL2pmmdD7GfBSHPperppqQ9KLczLmR5vmafOLQB0w:17865145036029998:1779424198",
        "jazoest": "26298",
        "lsd": "l9h56dXX4RkIO7nYnFO28K",
        "__spin_r": "1041417520",
        "__spin_b": "trunk",
        "__spin_t": "1781335650",
        "__crn": "comet.igweb.PolarisWebBloksAccountRecoveryRoute",
        "params": (
            '{"params":"{\\"server_params\\":{\\"device_id\\":\\"aZ67dgABAAGBHw-P3_ILGWvl1aRb\\",'
            '\\"is_platform_login\\":0,\\"is_from_logged_out\\":0,'
            '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
            '\\"login_entry_point\\":\\"account_recovery\\",\\"context_data\\":\\"{context_data}\\",'
            '\\"back_nav_action\\":\\"BACK\\",\\"INTERNAL_INFRA_screen_id\\":\\"{screen_id}\\"},'
            '\\"client_input_params\\":{\\"lois_settings\\":{\\"lois_token\\":\\"\\"},'
            '\\"machine_id\\":\\"\\",\\"zero_balance_state\\":\\"\\",\\"aac\\":\\"\\"}}"}'
            .replace("{context_data}", step4_context or "")
            .replace("{screen_id}", step4_screen_id)
        ),
    }

    apply_session_tokens(data, boot)
    response = _ig_http_post(
        "https://www.instagram.com/async/wbloks/fetch/",
        params=params,
        cookies=cookies,
        headers=headers,
        data=data,
        timeout=http_timeout,
    )
    if write_responses:
        with open(os.path.join(_RESPONSES_DIR, "4.html"), "w") as f:
            f.write(response.text)
    merge(response.text)
    if verbose:
        check_ig_response("step4/initiate_view", response.text)
        log_context_token("step4/initiate_view", extract_arm_context_token(response.text))
        log_masked_contacts("step4/initiate_view", response.text)

    ok = bool(contacts["email"] or contacts["phone"])
    result = {
        "ok": ok,
        "username": username,
        "flow": flow,
        "email": contacts["email"],
        "phone": contacts["phone"],
        "response_time_ms": round((time.perf_counter() - started) * 1000),
    }
    if not ok:
        result["error"] = "no_contacts_found"
    return result


RECOVERY_RETRY_ATTEMPTS = 5
RECOVERY_RETRY_SLEEP_SEC = 3.0
RECOVERY_RETRYABLE_ERRORS = frozenset({
    "session_bootstrap_failed",
    "rate_limited",
    "invalid_response",
    "network_error",
})


def run_recovery_with_retries(username: str, *, verbose: bool = False) -> dict:
    """Run recovery with pauses — same path api.py and joint hit enrich use."""
    started = time.perf_counter()
    last: dict | None = None

    for attempt in range(1, RECOVERY_RETRY_ATTEMPTS + 1):
        try:
            result = run_recovery(username, verbose=verbose)
        except requests.RequestException as exc:
            result = {
                "ok": False,
                "username": username,
                "flow": "unknown",
                "email": None,
                "phone": None,
                "error": "network_error",
                "detail": str(exc)[:160],
                "attempt": attempt,
            }
        last = result
        if result.get("ok"):
            if attempt > 1:
                result["retries"] = attempt - 1
            result["response_time_ms"] = round((time.perf_counter() - started) * 1000)
            return result
        err = (result.get("error") or "").strip()
        if attempt >= RECOVERY_RETRY_ATTEMPTS or err not in RECOVERY_RETRYABLE_ERRORS:
            break
        if verbose:
            print(
                f"[retry] attempt {attempt}/{RECOVERY_RETRY_ATTEMPTS} failed ({err}) — "
                f"sleep {RECOVERY_RETRY_SLEEP_SEC * attempt:.0f}s",
                file=sys.stderr,
            )
        time.sleep(RECOVERY_RETRY_SLEEP_SEC * attempt)

    if last is None:
        last = {
            "ok": False,
            "username": username,
            "flow": "unknown",
            "email": None,
            "phone": None,
            "error": "unknown",
        }
    if attempt > 1:
        last["retries"] = attempt - 1
    last["response_time_ms"] = round((time.perf_counter() - started) * 1000)
    return last


# --- end wbloks ---
def _run_ig_recovery(username: str) -> dict:
    """Wbloks contact recovery — inlined below."""
    return run_recovery_with_retries(username)


def _hunt_cycle_meta(min_val: str) -> dict:
    return {
        "buffer_depth": _buffer_depth_for(str(min_val)),
        "ig_block_sec": round(_ig_block_seconds_left(), 1),
    }


def _buffer_depth_for(min_val: str) -> int:
    buf = _ig_gen_buffers.get(str(min_val))
    if not buf:
        return 0
    try:
        return int(buf.qsize())
    except Exception:
        return 0


async def _buffer_try_get_throttled(min_val: str):
    """Serve buffered usernames — slight delay when queue is deep (avoids IG shock)."""
    hit = _buffer_try_get(min_val)
    if not hit:
        return None
    depth = _buffer_depth_for(min_val)
    if depth <= IG_GEN_BUFFER_LOW_WATER:
        if depth > 120:
            await asyncio.sleep(0.012)
        elif depth > 40:
            await asyncio.sleep(0.005)
    return hit


async def _ig_gen_acquire(min_val: str):
    """
    /ig_gen and hunters: try buffer, then live gen with many attempts.
    Never returns success without a username string.
    """
    min_val = str(min_val)
    await _ensure_ig_gen_buffer(min_val)

    hit = await _buffer_try_get_throttled(min_val)
    if hit:
        return hit

    if _ig_in_gen_block_cooldown():
        deadline = _ig_gen_block_until
        while time.time() < deadline:
            hit = await _buffer_try_get_throttled(min_val)
            if hit:
                return hit
            await asyncio.sleep(min(0.4, max(0.05, deadline - time.time())))
        return False, None, None, "instagram rate limited (IP/VPN — wait or rotate)"

    last = (False, None, None, "no result")
    serve_workers = IG_GEN_PARALLEL_WORKERS
    if _IS_TERMUX:
        serve_workers = min(IG_GEN_PARALLEL_WORKERS, 20)
    else:
        serve_workers = min(IG_GEN_PARALLEL_WORKERS, 12)
    if _ig_in_block_cooldown() or _ig_in_gen_block_cooldown():
        serve_workers = min(serve_workers, 4)
    try:
        burst = await _ig_gen_parallel_first(min_val, workers=serve_workers)
        if burst[0] and burst[1]:
            return burst
        last = burst
    except Exception as exc:
        last = (False, None, None, str(exc)[:200])

    for attempt in range(min(IG_GEN_SERVE_ATTEMPTS, 6)):
        hit = await _buffer_try_get_throttled(min_val)
        if hit:
            return hit
        loop = asyncio.get_running_loop()
        last = await loop.run_in_executor(
            _ig_gen_executor,
            partial(gen_ig, min_val, None, IG_GEN_SERVE_INNER_ATTEMPTS),
        )
        if last[0] and last[1]:
            return last
        if attempt + 1 < IG_GEN_SERVE_ATTEMPTS:
            await asyncio.sleep(0.012)
    return last


_ig_gen_lock = asyncio.Lock()
_ig_gen_inflight = None
_ig_gen_inflight_min = None
_ig_gen_buffers = {}
_ig_gen_buffer_tasks = {}
_ig_gen_prefill_tasks = []


async def _ig_gen_parallel_first(min_val: str, *, workers=None):
    """
    Parallel batch for empty-buffer hunter fallback only (not buffer fill).
    """
    stop_event = threading.Event()
    n_workers = max(1, int(workers or IG_GEN_PARALLEL_WORKERS))

    loop = asyncio.get_running_loop()

    def _runner():
        return gen_ig_once(min_val, stop_event=stop_event)

    tasks = [
        asyncio.create_task(loop.run_in_executor(_ig_gen_executor, _runner))
        for _ in range(n_workers)
    ]

    try:
        pending = set(tasks)
        last_result = None
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                try:
                    status, username, info_data, response_text = await t
                except asyncio.CancelledError:
                    continue
                except Exception as exc:
                    last_result = (False, None, None, str(exc)[:200])
                    continue
                last_result = (status, username, info_data, response_text)
                if status and username:
                    stop_event.set()
                    for p in list(pending):
                        p.cancel()
                    if pending:
                        await asyncio.gather(*pending, return_exceptions=True)
                    return status, username, info_data, response_text
        if last_result is not None:
            return last_result
        return False, None, None, "No result"
    finally:
        stop_event.set()
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _ig_gen_once_in_pool(min_val: str):
    """Run gen_ig_once on dedicated pool — not capped by default asyncio thread limit."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _ig_gen_executor,
        partial(gen_ig_once, str(min_val)),
    )


async def _ig_gen_buffer_loop(min_val: str):
    """
    Maintain ready usernames for /ig_gen.
    Many fillers × fast gen_ig_once (not heavy gen_ig loops) = high buffer throughput.
    """
    min_val = str(min_val)
    buf = _ig_gen_buffers.setdefault(
        min_val, asyncio.Queue(maxsize=max(1, int(IG_GEN_BUFFER_SIZE))),
    )
    while True:
        if _ig_in_gen_block_cooldown():
            await asyncio.sleep(min(1.5, max(0.25, _ig_gen_block_seconds_left())))
            continue
        depth = buf.qsize()
        if buf.full():
            sleep_s = 1.0 if depth >= int(IG_GEN_BUFFER_SIZE * 0.95) else IG_GEN_BUFFER_FULL_SLEEP
            await asyncio.sleep(sleep_s)
            continue
        try:
            res = await _ig_gen_once_in_pool(min_val)
        except Exception as exc:
            res = (False, None, None, str(exc)[:200])
        if res and len(res) >= 4 and res[0] and res[1]:
            try:
                buf.put_nowait(res)
            except asyncio.QueueFull:
                pass
            continue
        if depth < IG_GEN_BUFFER_LOW_WATER:
            await asyncio.sleep(IG_GEN_FAIL_SLEEP_LOW)
        else:
            await asyncio.sleep(IG_GEN_FAIL_SLEEP)


async def _ig_gen_prefill_buffer(min_val: str):
    """Boot + background: burst-fill queue toward low-water so /ig_gen is instant early."""
    min_val = str(min_val)
    await _ensure_ig_gen_buffer(min_val)
    buf = _ig_gen_buffers.get(min_val)
    if not buf:
        return
    target = min(int(IG_GEN_BUFFER_LOW_WATER), int(IG_GEN_BUFFER_SIZE))
    while buf.qsize() < target:
        batch = min(
            target - buf.qsize(),
            int(IG_GEN_PREFILL_BATCH),
            int(IG_GEN_BUFFER_SIZE) - buf.qsize(),
        )
        if batch <= 0:
            break
        tasks = [
            asyncio.create_task(_ig_gen_once_in_pool(min_val))
            for _ in range(batch)
        ]
        for task in asyncio.as_completed(tasks):
            try:
                res = await task
            except Exception:
                continue
            if res and len(res) >= 4 and res[0] and res[1] and not buf.full():
                try:
                    buf.put_nowait(res)
                except asyncio.QueueFull:
                    break
        if buf.qsize() >= target:
            break
        await asyncio.sleep(IG_GEN_FAIL_SLEEP_LOW)


async def _ig_gen_from_buffer_or_generate(min_val: str):
    """Backward-compatible alias — always prefer username-bearing result."""
    return await _ig_gen_acquire(min_val)


async def _ensure_ig_gen_buffer(min_val: str):
    min_val = str(min_val)
    async with _ig_gen_lock:
        tasks = _ig_gen_buffer_tasks.get(min_val) or []
        # Back-compat: older value might be a single task
        if not isinstance(tasks, list):
            tasks = [tasks]
        tasks = [t for t in tasks if t and not t.done()]
        target = max(1, int(IG_GEN_BUFFER_FILL_WORKERS))
        while len(tasks) < target:
            tasks.append(asyncio.create_task(_ig_gen_buffer_loop(min_val)))
        _ig_gen_buffer_tasks[min_val] = tasks


async def _shutdown_ig_gen_service():
    """Cancel buffer + inflight tasks so shutdown does not leave pending to_thread()."""
    global _ig_gen_inflight, _ig_gen_inflight_min
    pending = []
    if _ig_gen_inflight and not _ig_gen_inflight.done():
        pending.append(_ig_gen_inflight)
    for task_list in list(_ig_gen_buffer_tasks.values()):
        if isinstance(task_list, list):
            pending.extend(t for t in task_list if t and not t.done())
    pending.extend(t for t in _ig_gen_prefill_tasks if t and not t.done())
    _ig_gen_prefill_tasks.clear()
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    _ig_gen_buffer_tasks.clear()
    _ig_gen_inflight = None
    _ig_gen_inflight_min = None
    _ig_gen_executor.shutdown(wait=False, cancel_futures=True)


async def _background_gateway_warm():
    """Warm caches/buffers after server is already accepting /alive."""
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(_hunt_lookup_executor, _preload_hunt_lookup_caches)
    except Exception:
        pass
    for part in IG_GEN_WARM_MINS:
        part = str(part).strip()
        if not part:
            continue
        try:
            await _ensure_ig_gen_buffer(part)
            prefill = asyncio.create_task(_ig_gen_prefill_buffer(part))
            _ig_gen_prefill_tasks.append(prefill)
        except Exception:
            pass


@asynccontextmanager
async def _app_lifespan(_app):
    loop = asyncio.get_running_loop()
    loop.set_default_executor(_ig_gen_executor)
    _refresh_alive_snapshot()
    boot_task = asyncio.create_task(_background_gateway_warm())
    alive_task = asyncio.create_task(_alive_refresh_loop())
    yield
    alive_task.cancel()
    if not boot_task.done():
        boot_task.cancel()
        await asyncio.gather(boot_task, alive_task, return_exceptions=True)
    await _shutdown_ig_gen_service()


app = FastAPI(lifespan=_app_lifespan)


# ---------------- API ----------------

@app.get("/alive")
async def alive():
    with _alive_snapshot_lock:
        snap = _alive_snapshot.get("payload")
    if snap:
        return snap
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_alive_refresh_executor, _refresh_alive_snapshot)


def _build_alive_payload():
    buffer_depth = {}
    for min_val, buf in _ig_gen_buffers.items():
        try:
            buffer_depth[str(min_val)] = buf.qsize()
        except Exception:
            buffer_depth[str(min_val)] = 0
    pool = get_proxy_pool()
    proxy_count = len(pool) if pool else 0
    return {
        "alive": True,
        "service": "inpareto-gateway",
        "port": API_PORT,
        "ig_block_sec": round(_ig_block_seconds_left(), 1),
        "vps_proxies": vps_proxy_enabled(),
        "proxy_pool": proxy_count,
        "speed": {
            "profile": GATEWAY_PROFILE,
            "termux": _IS_TERMUX,
            "ig_gen_parallel": IG_GEN_PARALLEL_WORKERS,
            "ig_gen_buffer": IG_GEN_BUFFER_SIZE,
            "buffer_fill_workers": IG_GEN_BUFFER_FILL_WORKERS,
            "buffer_low_water": IG_GEN_BUFFER_LOW_WATER,
            "buffer_depth": buffer_depth,
            "ig_thread_pool": IG_GEN_THREAD_POOL_SIZE,
            "ig_http_pool": IG_HTTP_POOL_SIZE,
            "uvicorn_workers": UVICORN_WORKERS,
        },
    }


def _refresh_alive_snapshot():
    payload = _build_alive_payload()
    with _alive_snapshot_lock:
        _alive_snapshot["payload"] = payload
        _alive_snapshot["at"] = time.time()
    return payload


async def _alive_refresh_loop():
    """Keep /alive instant — never scan buffers on the hot probe path."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            await loop.run_in_executor(_alive_refresh_executor, _refresh_alive_snapshot)
        except Exception:
            pass
        await asyncio.sleep(2.0)


@app.get("/ig_profile")
async def ig_profile(request: Request):
    """Hit enrich: actual posts/name/pfp via web_profile_info (+ fallbacks)."""
    username = request.query_params.get("username")
    pk = request.query_params.get("pk")
    if not username:
        return JSONResponse({"error": "'username' parameter is required."}, status_code=403)
    async with _profile_fetch_sem:
        data = await asyncio.to_thread(fetch_user_profile, username, pk)
    return data


@app.get("/ig_gen")
async def ig_gen(request: Request):
    min_val = request.query_params.get("min")
    if not min_val:
        return JSONResponse({"error": "'min' parameter is required."}, status_code=403)
    async with _ig_gen_serve_sem:
        try:
            status, username, info_data, response_text = await asyncio.wait_for(
                _ig_gen_acquire(str(min_val)),
                timeout=float(HUNT_GEN_BUDGET),
            )
        except asyncio.TimeoutError:
            status, username, info_data, response_text = (
                False, None, None, "gen_timeout",
            )
        except Exception as exc:
            status, username, info_data, response_text = False, None, None, str(exc)[:200]
        status, username, info_data, response_text = _ig_gen_result_tuple(
            status, username, info_data, response_text,
        )
        return {
            "status": status,
            "username": username,
            "response": response_text,
            "info": info_data,
        }


@app.get("/hunt_cycle")
async def hunt_cycle(request: Request):
    """Single HTTP hop for joint workers: ig_gen + ig_lookup_m3 + gmail_lookup."""
    min_val = request.query_params.get("min")
    if not min_val:
        return JSONResponse({"error": "'min' parameter is required."}, status_code=403)
    meta = _hunt_cycle_meta(min_val)
    try:
        async with _ig_gen_serve_sem:
            status, username, info_data, gen_msg = await asyncio.wait_for(
                _ig_gen_acquire(str(min_val)),
                timeout=float(HUNT_GEN_BUDGET),
            )
        status, username, info_data, gen_msg = _ig_gen_result_tuple(
            status, username, info_data, gen_msg,
        )
    except asyncio.TimeoutError:
        return {
            "gen_ok": False,
            "username": None,
            "info": None,
            "valid": False,
            "hit": False,
            "error": "gen_timeout",
            **meta,
        }
    except Exception as exc:
        return {
            "gen_ok": False,
            "username": None,
            "info": None,
            "valid": False,
            "hit": False,
            "error": str(exc)[:200],
            **meta,
        }
    if not status or not username:
        return {
            "gen_ok": False,
            "username": None,
            "info": info_data,
            "valid": False,
            "hit": False,
            "response": gen_msg,
            **meta,
        }
    if len(str(username)) < 6:
        return {
            "gen_ok": True,
            "username": username,
            "info": info_data,
            "valid": False,
            "hit": False,
            "response": gen_msg,
            "skip": "username_too_short",
            **meta,
        }
    email = f"{username}@gmail.com"
    loop = asyncio.get_running_loop()
    try:
        async with _hunt_lookup_sem:
            valid, hit, ig_msg, gmail_msg = await asyncio.wait_for(
                loop.run_in_executor(
                    _hunt_lookup_executor,
                    _hunt_lookup_gmail_pair,
                    email,
                ),
                timeout=float(HUNT_CYCLE_LOOKUP_BUDGET),
            )
    except asyncio.TimeoutError:
        return {
            "gen_ok": True,
            "username": username,
            "info": info_data,
            "valid": False,
            "hit": False,
            "ig_response": "lookup_timeout",
            "gmail_response": "lookup_timeout",
            "gen_response": gen_msg,
            "error": "lookup_timeout",
            **_hunt_cycle_meta(min_val),
        }
    return {
        "gen_ok": True,
        "username": username,
        "info": info_data,
        "valid": valid,
        "hit": hit,
        "ig_response": ig_msg,
        "gmail_response": gmail_msg,
        "gen_response": gen_msg,
        **_hunt_cycle_meta(min_val),
    }


@app.get("/ig_lookup_m1")
async def api_check(request: Request):
    email = request.query_params.get("email")
    status, response_text = await asyncio.to_thread(ig_lookup_M1_hunt, email)
    return {
        "status": status,
        "email": email,
        "response": response_text,
        "method": "bloks_ar_search",
    }


@app.get("/ig_lookup_m3")
async def api_check_m3(request: Request):
    email = request.query_params.get("email")
    status, response_text = await asyncio.to_thread(ig_lookup_M3_hunt, email)
    return {
        "status": status,
        "email": email,
        "response": response_text,
        "method": "mobile_check_email",
    }


@app.get("/ig_lookup_m2")
async def api_check2(request: Request):
    email = request.query_params.get("email")
    status, response_text = await asyncio.to_thread(ig_lookup_M2, email)
    return {
        "status": status,
        "email": email,
        "response": response_text,
    }


@app.get("/ig_recovery")
async def ig_recovery(request: Request):
    """Hit enrich: masked email/phone — identical engine to api.py."""
    username = (request.query_params.get("username") or "").strip().lstrip("@")
    if not username:
        return JSONResponse({"error": "'username' parameter is required."}, status_code=403)
    ig_block_left = round(_ig_block_seconds_left(), 1)
    loop = asyncio.get_running_loop()
    async with _recovery_sem:
        try:
            result = await loop.run_in_executor(
                _recovery_executor, _run_ig_recovery, username,
            )
        except Exception as exc:
            return {
                "ok": False,
                "username": username,
                "flow": "unknown",
                "email": None,
                "phone": None,
                "error": "network_error",
                "detail": str(exc)[:160],
                "ig_block_sec": ig_block_left,
            }
    if isinstance(result, dict):
        result["ig_block_sec"] = ig_block_left
    return result


@app.get("/gmail_lookup")
async def api_gmail(request: Request):
    email = request.query_params.get("email")
    try:
        task = await asyncio.to_thread(check_gmail, email)
    except Exception as exc:
        return {"status": False, "email": email, "response": str(exc)[:200]}
    if isinstance(task, str):
        return {"status": False, "email": email, "response": task}
    status, response_text = task
    return {
        "status": status,
        "email": email,
        "response": response_text,
    }


def _port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
        return False
    except OSError:
        return True


def _uvicorn_log_level():
    return "error" if _is_termux() else "critical"


def main():
    """
    Start the gateway.

    Important: uvicorn manages its own event loop. Do not call uvicorn.run()
    from inside asyncio.run()/an already-running event loop.
    """
    suppress_server_logs()
    if _port_in_use(API_PORT):
        print()
        print(apply_color("  ┌─ PORT IN USE ──────────────────────────────────────────────┐", ANSI_RED))
        print(apply_color(f"  │  Port {API_PORT} is already taken on this device.          │", ANSI_RED))
        print(apply_color("  │  Stop the other endpoint.py / uvicorn process first.       │", ANSI_RED))
        print(apply_color("  └────────────────────────────────────────────────────────────┘", ANSI_RED))
        print()
        raise SystemExit(1)
    device_hash = get_device_hash()
    public_ip = asyncio.run(fetch_public_ip())
    api_host = f"{public_ip}:{API_PORT}" if public_ip else f":{API_PORT}"
    cloud_err = save_api_host_record(device_hash, public_ip or "", API_PORT, api_host)
    render_startup_banner(device_hash, public_ip, API_PORT, cloud_err is None)
    log_level = _uvicorn_log_level()
    print(apply_color(f"  Listening on http://127.0.0.1:{API_PORT}  (log level: {log_level})\n", ANSI_DIM))
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=API_PORT,
            log_level=log_level,
            access_log=False,
        )
    except OSError as exc:
        print(apply_color(f"\n  [ENDPOINT] Could not bind port {API_PORT}: {exc}\n", ANSI_RED))
        raise SystemExit(1) from exc
    print(apply_color("\n  [ENDPOINT] Server stopped unexpectedly (port closed).\n", ANSI_RED))
    raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        render_keyboard_exit()
    except Exception as exc:
        import traceback
        print(apply_color("\n  [ENDPOINT ERROR]\n", ANSI_RED))
        traceback.print_exc()
        if _is_termux():
            print(apply_color("  Termux fix: bash install-termux.sh\n", ANSI_CYAN))
        else:
            print(apply_color("  Fix: pip install -r requirements.txt\n", ANSI_DIM))
        raise SystemExit(1) from exc
