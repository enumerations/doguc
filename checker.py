#!/usr/bin/env python3
"""
Discord unique-username availability checker.

POST https://discord.com/api/v9/unique-username/username-attempt-unauthed
Body: {"username": "..."}  — tokenless.

ProxyScrape Regular Residential (rp.scrapegw.com):
  rotating (défaut) — username nu → nouvelle IP à chaque requête
  sticky            — user-session-{id}-lifetime-{minutes} → IP tenue N minutes

Un 429 ne bloque jamais le checker entier : on change d'IP / de tunnel et on
retry ce username. Resume : available.txt + taken.txt (errors.txt = log de run).
"""

from __future__ import annotations

import asyncio
import os
import random
import re
import secrets
import signal
import socket
import sys
import time
import tomllib
from collections import deque
from dataclasses import dataclass, field
from typing import Mapping, Optional
from urllib.parse import quote

import aiohttp
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# =============================================================================
# Configuration (loaded from config.toml)
# =============================================================================

CONFIG_FILE = "config.toml"


@dataclass(frozen=True)
class Config:
    use_gateway: bool
    gateway_mode: str
    gateway_host: str
    gateway_port: int
    gateway_user: str
    gateway_pass: str
    gateway_username_template: str
    gateway_session_lifetime: int
    gateway_sessions: int
    gateway_provider: str
    unique_session_per_request: bool
    proxies_file: str
    usernames_file: str
    available_file: str
    taken_file: str
    errors_file: str
    max_concurrent: int
    workers: int
    base_delay: float
    low_remaining_threshold: int
    proactive_slowdown_factor: float
    max_429_before_cooldown: int
    dead_after_failures: int
    dead_cooldown_seconds: float
    max_inflight_per_ip: int
    huge_retry_after: float
    invalid_request_window: float
    invalid_request_limit: int
    max_retries: int
    request_timeout: float
    connect_timeout: float
    keepalive_timeout: float
    force_close: bool
    retry_backoff_base: float
    retry_backoff_cap: float
    flush_every: int
    ui_refresh_hz: float
    debug: bool
    debug_show_ip: bool


def _resolve_path(base_dir: str, path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(base_dir, path))


def _config_path() -> str:
    env = os.environ.get("CHECKER_CONFIG")
    if env:
        return os.path.abspath(env)
    here = os.path.dirname(os.path.abspath(__file__))
    beside_script = os.path.join(here, CONFIG_FILE)
    if os.path.isfile(beside_script):
        return beside_script
    return os.path.abspath(CONFIG_FILE)


def load_config(path: Optional[str] = None) -> Config:
    path = path or _config_path()
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Copy or create {CONFIG_FILE} next to checker.py."
        )
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    base = os.path.dirname(os.path.abspath(path))
    gw = raw.get("gateway", {})
    files = raw.get("files", {})
    perf = raw.get("performance", {})
    rl = raw.get("rate_limit", {})
    cf = raw.get("cloudflare", {})
    dbg = raw.get("debug", {})

    try:
        max_concurrent = int(perf["max_concurrent"])
        mode = str(gw.get("mode", "rotating")).strip().lower()
        if mode not in ("rotating", "sticky"):
            raise ValueError(f"gateway.mode must be 'rotating' or 'sticky', got {mode!r}")
        return Config(
            use_gateway=bool(gw["enabled"]),
            gateway_mode=mode,
            gateway_host=str(gw["host"]),
            gateway_port=int(gw["port"]),
            gateway_user=str(gw["user"]),
            gateway_pass=str(gw["password"]),
            gateway_username_template=str(
                gw.get("username_template", "{user}-session-{session}-lifetime-{lifetime}")
            ),
            gateway_session_lifetime=int(gw.get("session_lifetime_minutes", 10)),
            gateway_sessions=max(1, int(gw.get("sessions", max_concurrent))),
            gateway_provider=str(gw.get("provider", "auto")).strip().lower(),
            unique_session_per_request=bool(gw.get("unique_session_per_request", False)),
            proxies_file=_resolve_path(base, str(files["proxies"])),
            usernames_file=_resolve_path(base, str(files["usernames"])),
            available_file=_resolve_path(base, str(files["available"])),
            taken_file=_resolve_path(base, str(files["taken"])),
            errors_file=_resolve_path(base, str(files.get("errors", "errors.txt"))),
            max_concurrent=max_concurrent,
            workers=int(perf["workers"]),
            base_delay=float(perf.get("base_delay", 0.0)),
            request_timeout=float(perf["request_timeout"]),
            connect_timeout=float(perf["connect_timeout"]),
            keepalive_timeout=float(perf.get("keepalive_timeout", 30.0)),
            force_close=bool(perf.get("force_close", False)),
            ui_refresh_hz=float(perf["ui_refresh_hz"]),
            max_retries=int(perf["max_retries"]),
            retry_backoff_base=float(perf.get("retry_backoff_base", 0.05)),
            retry_backoff_cap=float(perf.get("retry_backoff_cap", 1.5)),
            flush_every=max(1, int(perf.get("flush_every", 50))),
            low_remaining_threshold=int(rl["low_remaining_threshold"]),
            proactive_slowdown_factor=float(rl.get("slowdown_factor", 1.5)),
            max_429_before_cooldown=int(rl.get("max_429_before_cooldown", 3)),
            dead_after_failures=int(rl.get("dead_after_failures", 8)),
            dead_cooldown_seconds=float(rl.get("dead_cooldown_seconds", 30.0)),
            max_inflight_per_ip=max(1, int(rl.get("max_inflight_per_ip", 1))),
            huge_retry_after=float(rl.get("huge_retry_after", 30.0)),
            invalid_request_window=float(cf["window_seconds"]),
            invalid_request_limit=int(cf["limit"]),
            debug=bool(dbg.get("enabled", False)),
            debug_show_ip=bool(dbg.get("show_exit_ip", True)),
        )
    except KeyError as exc:
        raise ValueError(f"Missing key in {path}: {exc}") from exc


try:
    cfg = load_config()
except (FileNotFoundError, ValueError, tomllib.TOMLDecodeError) as exc:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1) from exc

USE_GATEWAY = cfg.use_gateway
GATEWAY_MODE = cfg.gateway_mode
GATEWAY_HOST = cfg.gateway_host
GATEWAY_PORT = cfg.gateway_port
GATEWAY_USER = cfg.gateway_user
GATEWAY_PASS = cfg.gateway_pass
GATEWAY_USERNAME_TEMPLATE = cfg.gateway_username_template
GATEWAY_SESSION_LIFETIME = cfg.gateway_session_lifetime
GATEWAY_SESSIONS = cfg.gateway_sessions
GATEWAY_PROVIDER = cfg.gateway_provider
UNIQUE_SESSION_PER_REQUEST = cfg.unique_session_per_request
PROXIES_FILE = cfg.proxies_file
USERNAMES_FILE = cfg.usernames_file
AVAILABLE_FILE = cfg.available_file
TAKEN_FILE = cfg.taken_file
ERRORS_FILE = cfg.errors_file
MAX_CONCURRENT = cfg.max_concurrent
WORKERS = cfg.workers
BASE_DELAY = cfg.base_delay
LOW_REMAINING_THRESHOLD = cfg.low_remaining_threshold
PROACTIVE_SLOWDOWN_FACTOR = cfg.proactive_slowdown_factor
MAX_429_BEFORE_COOLDOWN = cfg.max_429_before_cooldown
DEAD_AFTER_FAILURES = cfg.dead_after_failures
DEAD_COOLDOWN_SECONDS = cfg.dead_cooldown_seconds
MAX_INFLIGHT_PER_IP = cfg.max_inflight_per_ip
HUGE_RETRY_AFTER = cfg.huge_retry_after
INVALID_REQUEST_WINDOW = cfg.invalid_request_window
INVALID_REQUEST_LIMIT = cfg.invalid_request_limit
MAX_RETRIES = cfg.max_retries
REQUEST_TIMEOUT = cfg.request_timeout
CONNECT_TIMEOUT = cfg.connect_timeout
KEEPALIVE_TIMEOUT = cfg.keepalive_timeout
FORCE_CLOSE = cfg.force_close
RETRY_BACKOFF_BASE = cfg.retry_backoff_base
RETRY_BACKOFF_CAP = cfg.retry_backoff_cap
FLUSH_EVERY = cfg.flush_every
UI_REFRESH_HZ = cfg.ui_refresh_hz
DEBUG = cfg.debug
DEBUG_SHOW_IP = cfg.debug_show_ip

# =============================================================================
# Constants
# =============================================================================

API_URL = "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
# Echo de l'IP de sortie à travers le proxy (debug seulement).
IP_ECHO_URL = "https://api.ipify.org"

# Discord unique usernames: lowercase alphanumeric + . _ ; 2–32 chars; no "..".
USERNAME_RE = re.compile(r"^[a-z0-9._]{2,32}$")
_EXIT_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")

REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://discord.com",
    "Referer": "https://discord.com/register",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

console = Console()


# =============================================================================
# Username validation
# =============================================================================


def is_valid_username(username: str) -> bool:
    """Strict Discord unique-username rules. Invalid names are never sent to the API."""
    if not USERNAME_RE.fullmatch(username):
        return False
    if ".." in username:
        return False
    if username.startswith(".") or username.endswith("."):
        return False
    return True


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def jittered_backoff(attempt: int) -> float:
    """Full jitter: uniform(0, min(cap, base * 2^attempt)). Used for network errors only."""
    if attempt <= 0:
        return 0.0
    ceiling = min(RETRY_BACKOFF_CAP, RETRY_BACKOFF_BASE * (2 ** attempt))
    return random.uniform(0.0, ceiling)


# =============================================================================
# Rate-limit + Cloudflare invalid-request tracking (per proxy / IP)
# =============================================================================


class InvalidRequestTracker:
    """Sliding-window counter for Cloudflare-counted invalid responses.

    Counts 401, 403, and 429 except scope=shared (Discord documents those as
    not counting toward the 10k / 10 min Cloudflare invalid budget).
    """

    def __init__(self, window: float = INVALID_REQUEST_WINDOW, limit: int = INVALID_REQUEST_LIMIT) -> None:
        self.window = window
        self.limit = limit
        self._ts: deque[float] = deque()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()

    def record(self) -> None:
        now = time.monotonic()
        self._prune(now)
        self._ts.append(now)

    def count(self) -> int:
        self._prune(time.monotonic())
        return len(self._ts)

    def is_quarantined(self) -> bool:
        return self.count() >= self.limit

    def wait_seconds(self) -> float:
        """Seconds until the oldest invalid expires out of the window, if quarantined."""
        self._prune(time.monotonic())
        if len(self._ts) < self.limit:
            return 0.0
        return max(0.0, self._ts[0] + self.window - time.monotonic())


class ProxyRateLimiter:
    """Per-proxy limiter driven exclusively by Discord rate-limit headers."""

    def __init__(self) -> None:
        self.remaining: Optional[int] = None
        self.limit: Optional[int] = None
        self.reset_after: Optional[float] = None
        self.bucket: Optional[str] = None
        self.cooldown_until: float = 0.0
        self.last_global: bool = False
        self.last_scope: str = ""
        self._lock = asyncio.Lock()

    def is_cooling(self) -> bool:
        return self.cooldown_until > time.monotonic()

    def wait_seconds(self) -> float:
        now = time.monotonic()
        if self.cooldown_until > now:
            return self.cooldown_until - now
        return 0.0

    def apply_cooldown(self, seconds: float, is_global: bool = False) -> None:
        seconds = max(0.0, float(seconds))
        self.cooldown_until = max(self.cooldown_until, time.monotonic() + seconds)
        self.last_global = is_global
        if is_global:
            self.remaining = 0

    def update_from_headers(self, headers: Mapping[str, str]) -> None:
        get = headers.get

        remaining = get("X-RateLimit-Remaining")
        reset_after = get("X-RateLimit-Reset-After")
        limit = get("X-RateLimit-Limit")
        bucket = get("X-RateLimit-Bucket")

        try:
            if remaining is not None:
                self.remaining = int(remaining)
        except (TypeError, ValueError):
            pass
        try:
            if reset_after is not None:
                self.reset_after = float(reset_after)
        except (TypeError, ValueError):
            pass
        try:
            if limit is not None:
                self.limit = int(limit)
        except (TypeError, ValueError):
            pass
        if bucket:
            self.bucket = str(bucket)

        # Exhausted bucket: cool down until Discord says the window resets.
        if self.remaining is not None and self.remaining <= 0 and self.reset_after:
            self.apply_cooldown(self.reset_after, is_global=False)

    async def try_acquire(self) -> bool:
        """Take one token if this IP can fire now. Never waits — caller switches IP."""
        async with self._lock:
            now = time.monotonic()
            if self.cooldown_until > now:
                return False
            if self.remaining is not None and self.remaining <= LOW_REMAINING_THRESHOLD:
                return False
            if self.remaining is not None:
                self.remaining = max(0, self.remaining - 1)
            return True


# =============================================================================
# Proxy manager
# =============================================================================


@dataclass
class Proxy:
    url: str
    display: str
    session_id: str = ""
    in_flight: int = 0
    consecutive_429: int = 0
    consecutive_failures: int = 0
    dead_until: float = 0.0
    limiter: ProxyRateLimiter = field(default_factory=ProxyRateLimiter)
    invalid: InvalidRequestTracker = field(default_factory=InvalidRequestTracker)

    def status(self) -> str:
        if self.dead_until > time.monotonic():
            return "dead"
        if self.invalid.is_quarantined():
            return "quarantine"
        if self.limiter.is_cooling():
            return "cooldown"
        return "ok"

    def is_spent(self) -> bool:
        """True when this exit IP must not be reused (dead, cooldown, empty bucket, CF)."""
        if self.dead_until > time.monotonic():
            return True
        if self.invalid.is_quarantined():
            return True
        if self.limiter.is_cooling():
            return True
        if self.limiter.remaining is not None and self.limiter.remaining <= LOW_REMAINING_THRESHOLD:
            return True
        return False

    def wait_seconds(self) -> float:
        now = time.monotonic()
        dead_wait = max(0.0, self.dead_until - now) if self.dead_until > now else 0.0
        return max(self.limiter.wait_seconds(), self.invalid.wait_seconds(), dead_wait)

    def mark_dead(self, seconds: float) -> None:
        """Temporarily remove this proxy from rotation. Does not affect other proxies."""
        self.dead_until = max(self.dead_until, time.monotonic() + max(0.0, seconds))

    def record_success(self) -> None:
        self.consecutive_429 = 0
        self.consecutive_failures = 0

    def record_429(self, retry_after: float) -> None:
        self.consecutive_429 += 1
        self.consecutive_failures = 0
        # Extra cooldown if this IP is getting hammered — other workers keep going.
        if self.consecutive_429 >= MAX_429_BEFORE_COOLDOWN:
            extra = max(retry_after, 1.0) * self.consecutive_429
            self.mark_dead(min(extra, DEAD_COOLDOWN_SECONDS))

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= DEAD_AFTER_FAILURES:
            self.mark_dead(DEAD_COOLDOWN_SECONDS)
            self.consecutive_failures = 0


def _mask_proxy_url(url: str) -> str:
    """Hide credentials in the live UI."""
    if "@" in url:
        creds, host = url.rsplit("@", 1)
        scheme = ""
        if "://" in creds:
            scheme, creds = creds.split("://", 1)
            scheme += "://"
        if ":" in creds:
            user = creds.split(":", 1)[0]
            return f"{scheme}{user}:***@{host}"
        return f"{scheme}***@{host}"
    return url


def parse_proxy_line(line: str) -> Optional[str]:
    """Accept host:port, user:pass@host:port, host:port:user:pass, or a full URL."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        return line
    if "@" in line:
        return f"http://{line}"
    parts = line.split(":")
    if len(parts) == 2:
        return f"http://{line}"
    if len(parts) == 4:
        host, port, user, password = parts
        user_q = quote(user, safe="")
        pass_q = quote(password, safe="")
        return f"http://{user_q}:{pass_q}@{host}:{port}"
    return None


def load_proxy_list(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Proxy list not found: {path}")
    urls: list[str] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            url = parse_proxy_line(raw)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    if not urls:
        raise RuntimeError(f"No valid proxies in {path}")
    return urls


class ProxyManager:
    """Acquire an exit IP without ever stalling the whole checker on one 429.

    Modes
    -----
    rotating : pool de sessid (keep-alive). Même IP jusqu'au 429, puis CE slot
               est remplacé. unique_session_per_request=true → IP à chaque req.
    sticky   : identique, lifetime provider plus long.
    list     : proxies.txt. Round-robin + cooldown / mort temporaire par ligne.
    """

    def __init__(
        self,
        proxies: list[Proxy],
        *,
        mode: str,
        factory=None,
        rotating_url: str = "",
        rotating_display: str = "",
    ) -> None:
        self.proxies = proxies
        self.mode = mode  # rotating | sticky | list
        self._factory = factory
        self._rotating_url = rotating_url
        self._rotating_display = rotating_display
        self._rr = 0
        self._lock = asyncio.Lock()
        self.rotations = 0

    @property
    def can_replace(self) -> bool:
        """True si un slot spent peut être remplacé par une nouvelle session (nouvelle IP)."""
        return self._factory is not None

    def release(self, proxy: Proxy) -> None:
        proxy.in_flight = max(0, proxy.in_flight - 1)

    def _replace_at(self, idx: int) -> Proxy:
        old = self.proxies[idx]
        _exit_ip_cache.pop(old.url, None)
        new = self._factory()
        self.proxies[idx] = new
        self.rotations += 1
        return new

    def _drop_unlocked(self, proxy: Proxy) -> Optional[Proxy]:
        """Throw away this session and put a fresh one in the same slot."""
        if not self.can_replace:
            return None
        try:
            idx = self.proxies.index(proxy)
        except ValueError:
            return None
        return self._replace_at(idx)

    def _sweep_unlocked(self) -> None:
        """Replace every spent slot so a 429 never lingers in the pool."""
        if not self.can_replace:
            return
        for i, proxy in enumerate(list(self.proxies)):
            if proxy.is_spent():
                self._replace_at(i)

    async def drop(self, proxy: Proxy) -> None:
        """429 / IP brûlée : jeter CE slot, les autres workers gardent leur IP."""
        if not self.can_replace:
            return
        async with self._lock:
            self._drop_unlocked(proxy)

    def _new_rotating_handle(self) -> Proxy:
        # Uniquement si unique_session_per_request : nouvelle IP à chaque acquire.
        session_id = secrets.token_hex(8)
        user = _rotating_session_user(session_id)
        url = _gateway_auth_url(user)
        self.rotations += 1
        return Proxy(
            url=url,
            display=_mask_proxy_url(url),
            session_id=session_id,
            in_flight=1,
        )

    async def acquire(self) -> Proxy:
        """Return a live IP. Never sleeps on another request's Retry-After."""
        # Nouvelle IP à chaque requête (opt-in). Sinon : pool sticky jusqu'au 429.
        if self.mode == "rotating" and UNIQUE_SESSION_PER_REQUEST:
            return self._new_rotating_handle()

        while True:
            wait = 0.02
            async with self._lock:
                self._sweep_unlocked()
                n = len(self.proxies)
                for _ in range(n):
                    proxy = self.proxies[self._rr % n]
                    self._rr += 1
                    if proxy.is_spent():
                        if self.can_replace:
                            proxy = self._drop_unlocked(proxy) or proxy
                        else:
                            continue
                    if proxy.is_spent():
                        continue
                    if proxy.in_flight >= MAX_INFLIGHT_PER_IP:
                        continue
                    if await proxy.limiter.try_acquire():
                        proxy.in_flight += 1
                        return proxy

                waits = [p.wait_seconds() for p in self.proxies]
                positive = [w for w in waits if w > 0]
                wait = min(positive) if positive else 0.05

            await asyncio.sleep(min(max(wait, 0.02), 0.5))


def _detect_provider() -> str:
    explicit = GATEWAY_PROVIDER
    if explicit in ("dataimpulse", "proxyscrape"):
        return explicit
    host = GATEWAY_HOST.lower()
    if "dataimpulse" in host:
        return "dataimpulse"
    if "scrapegw" in host or "proxyscrape" in host:
        return "proxyscrape"
    return "generic"


PROVIDER = _detect_provider() if USE_GATEWAY else "generic"


def _gateway_auth_url(username: str) -> str:
    # Garder ; _ . - pour la syntaxe DataImpulse / ProxyScrape (sessid, session-id).
    user_q = quote(username, safe="_;.-")
    pass_q = quote(GATEWAY_PASS, safe="")
    return f"http://{user_q}:{pass_q}@{GATEWAY_HOST}:{GATEWAY_PORT}"


def _dataimpulse_session_user(session_id: str) -> str:
    """DataImpulse: login__sessid.ID  (ou ;sessid.ID si le login a déjà des params)."""
    base = GATEWAY_USER
    # Évite un sessid en double si le user dashboard en contient déjà un.
    base = re.sub(r";?sessid\.[^;]*", "", base, flags=re.IGNORECASE)
    base = re.sub(r";?sid\.[^;]*", "", base, flags=re.IGNORECASE)
    if "__" in base:
        return f"{base};sessid.{session_id}"
    return f"{base}__sessid.{session_id}"


def _rotating_session_user(session_id: str) -> str:
    """Identité unique → nouvelle IP, et URL proxy unique → aiohttp ne recycle pas le tunnel."""
    if PROVIDER == "dataimpulse":
        return _dataimpulse_session_user(session_id)
    if PROVIDER == "proxyscrape":
        return f"{GATEWAY_USER}-session-{session_id}-lifetime-1"
    return GATEWAY_USERNAME_TEMPLATE.format(
        user=GATEWAY_USER,
        session=session_id,
        lifetime=1,
    )


def _sticky_proxy() -> Proxy:
    session_id = secrets.token_hex(6)
    if PROVIDER == "dataimpulse":
        username = _dataimpulse_session_user(session_id)
    else:
        username = GATEWAY_USERNAME_TEMPLATE.format(
            user=GATEWAY_USER,
            session=session_id,
            lifetime=GATEWAY_SESSION_LIFETIME,
        )
    url = _gateway_auth_url(username)
    return Proxy(url=url, display=_mask_proxy_url(url), session_id=session_id)


def build_proxy_manager() -> ProxyManager:
    if USE_GATEWAY and GATEWAY_MODE == "rotating" and UNIQUE_SESSION_PER_REQUEST:
        url = _gateway_auth_url(GATEWAY_USER)
        handle = Proxy(url=url, display=_mask_proxy_url(url))
        return ProxyManager(
            [handle],
            mode="rotating",
            rotating_url=url,
            rotating_display=handle.display,
        )
    if USE_GATEWAY:
        # rotating / sticky : pool de sessid. 429 → ce slot est remplacé, les autres gardent leur IP.
        slots = max(1, GATEWAY_SESSIONS)
        if GATEWAY_MODE == "rotating":
            slots = max(slots, MAX_CONCURRENT)
        return ProxyManager(
            [_sticky_proxy() for _ in range(slots)],
            mode=GATEWAY_MODE,
            factory=_sticky_proxy,
        )
    return ProxyManager(
        [Proxy(url=u, display=_mask_proxy_url(u)) for u in load_proxy_list(PROXIES_FILE)],
        mode="list",
    )


# =============================================================================
# Persistent hit / taken / error store (resume-safe)
# =============================================================================


def _load_username_set(path: str) -> set[str]:
    names: set[str] = set()
    if not os.path.isfile(path):
        return names
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            name = normalize_username(raw)
            if name and not name.startswith("#"):
                names.add(name)
    return names


class ResultStore:
    """Append-only available/taken/errors. Buffered flush — fsync only on close.

    Resume skips available.txt + taken.txt. errors.txt is a run log: those
    names are retried on the next launch.
    """

    def __init__(self, available_path: str, taken_path: str, errors_path: str) -> None:
        self.available_path = available_path
        self.taken_path = taken_path
        self.errors_path = errors_path
        self.available = _load_username_set(available_path)
        self.taken = _load_username_set(taken_path)
        self._lock = asyncio.Lock()
        self._available_fp = open(available_path, "a", encoding="utf-8")
        self._taken_fp = open(taken_path, "a", encoding="utf-8")
        self._errors_fp = open(errors_path, "a", encoding="utf-8")
        self._dirty = 0

    def already_checked(self, username: str) -> bool:
        return username in self.available or username in self.taken

    def _maybe_flush(self) -> None:
        self._dirty += 1
        if self._dirty >= FLUSH_EVERY:
            self._flush()

    def _flush(self) -> None:
        for fp in (self._available_fp, self._taken_fp, self._errors_fp):
            fp.flush()
        self._dirty = 0

    async def save(self, username: str, taken: bool) -> bool:
        """Persist one result. Returns False if it was already stored."""
        async with self._lock:
            if self.already_checked(username):
                return False
            if taken:
                self.taken.add(username)
                self._taken_fp.write(username + "\n")
            else:
                self.available.add(username)
                self._available_fp.write(username + "\n")
            self._maybe_flush()
            return True

    async def save_error(self, username: str) -> None:
        async with self._lock:
            self._errors_fp.write(username + "\n")
            self._maybe_flush()

    def close(self) -> None:
        for fp in (self._available_fp, self._taken_fp, self._errors_fp):
            try:
                fp.flush()
                os.fsync(fp.fileno())
            except OSError:
                pass
            fp.close()


# =============================================================================
# Stats (single-threaded asyncio: no extra locks needed)
# =============================================================================


@dataclass
class Stats:
    total: int = 0
    skipped_resume: int = 0
    invalid_format: int = 0
    available: int = 0
    taken: int = 0
    errors: int = 0
    abandoned: int = 0
    rate_limits: int = 0
    retries: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _hits: deque[float] = field(default_factory=deque)

    def record_ok(self) -> None:
        now = time.monotonic()
        self._hits.append(now)
        cutoff = now - 5.0
        while self._hits and self._hits[0] < cutoff:
            self._hits.popleft()

    @property
    def checked(self) -> int:
        return self.available + self.taken

    @property
    def rps(self) -> float:
        now = time.monotonic()
        cutoff = now - 5.0
        while self._hits and self._hits[0] < cutoff:
            self._hits.popleft()
        window = min(5.0, max(now - self.started_at, 0.001))
        return len(self._hits) / window

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at


# =============================================================================
# Username file loading
# =============================================================================


def load_usernames(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Username list not found: {path}")
    ordered: list[str] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            name = normalize_username(raw)
            if not name or name.startswith("#"):
                continue
            if name in seen:
                continue
            seen.add(name)
            ordered.append(name)
    return ordered


# =============================================================================
# HTTP helpers
# =============================================================================


def _header_float(headers, name: str) -> Optional[float]:
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _close_tunnel(resp: aiohttp.ClientResponse) -> None:
    """Drop the CONNECT tunnel so the next request gets a new exit IP."""
    conn = resp.connection
    if conn is not None and not conn.closed:
        conn.close()


async def parse_retry_after(resp: aiohttp.ClientResponse) -> float:
    """Discord JSON retry_after is the real bucket. Huge CF Retry-After = IP burned."""
    header_val = _header_float(resp.headers, "Retry-After")
    body: dict = {}
    try:
        body = await resp.json(content_type=None)
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    json_val = body.get("retry_after")
    try:
        json_val = float(json_val) if json_val is not None else None
    except (TypeError, ValueError):
        json_val = None

    reset_val = _header_float(resp.headers, "X-RateLimit-Reset-After")

    # Le JSON Discord (secondes, float) est la source de vérité.
    if json_val is not None and json_val >= 0:
        return json_val
    for candidate in (reset_val, header_val):
        if candidate is not None and 0 <= candidate <= HUGE_RETRY_AFTER:
            return candidate
    # Header Cloudflare énorme : on le remonte pour les logs, le worker ne sleep pas dessus.
    if header_val is not None and header_val >= 0:
        return header_val
    return 1.0


def is_cloudflare_invalid(status: int, scope: str) -> bool:
    """401/403 always count. 429 counts unless Discord marks the scope as shared."""
    if status in (401, 403):
        return True
    if status == 429:
        return scope.lower() != "shared"
    return False


# =============================================================================
# Debug: username + exit IP per request
# =============================================================================

# Cache IP par URL de proxy (sticky/list : même session = même IP).
# Jamais utilisé en rotating : chaque CONNECT peut changer d'IP.
_exit_ip_cache: dict[str, str] = {}
_exit_ip_lock = asyncio.Lock()


def debug_log(username: str, ip: str, status: str, detail: str) -> None:
    """Print above the Live UI. Safe to call from workers."""
    console.log(
        f"[magenta]debug[/]  user=[bold white]{username}[/]  "
        f"ip=[cyan]{ip}[/]  {status}  {detail}"
    )


async def resolve_exit_ip(
    session: aiohttp.ClientSession,
    proxy: Proxy,
    *,
    cache: bool,
) -> str:
    """Public IP seen through this proxy. Separate CONNECT from Discord in rotating."""
    if cache:
        async with _exit_ip_lock:
            cached = _exit_ip_cache.get(proxy.url)
        if cached:
            return cached
    try:
        async with session.get(
            IP_ECHO_URL,
            proxy=proxy.url,
            timeout=aiohttp.ClientTimeout(total=min(4.0, REQUEST_TIMEOUT), connect=min(3.0, CONNECT_TIMEOUT)),
            headers={"Accept": "text/plain", "User-Agent": REQUEST_HEADERS["User-Agent"]},
        ) as resp:
            raw = (await resp.text()).strip()
    except Exception:
        return "?"
    ip = raw.split()[0] if raw else ""
    if not ip or not _EXIT_IP_RE.fullmatch(ip):
        return "?"
    if cache:
        async with _exit_ip_lock:
            _exit_ip_cache[proxy.url] = ip
    return ip


# =============================================================================
# Live UI
# =============================================================================


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _bar(done: int, total: int, width: int = 42) -> Text:
    pct = 1.0 if total <= 0 else min(1.0, done / total)
    filled = int(round(width * pct))
    text = Text()
    text.append("━" * filled, style="cyan")
    text.append("━" * (width - filled), style="dim")
    text.append(f"  {pct:6.1%}")
    return text


def _mode_label(pool: ProxyManager) -> str:
    if pool.mode == "rotating" and UNIQUE_SESSION_PER_REQUEST:
        return f"[green]Rotating[/] · {PROVIDER} · {MAX_CONCURRENT} conc · IP/req"
    if pool.mode in ("rotating", "sticky"):
        return (
            f"[green]Reuse until 429[/] · {PROVIDER} · {len(pool.proxies)} IPs · "
            f"[cyan]{pool.rotations}[/] rotations"
        )
    return f"List ({len(pool.proxies)} proxies)"


def render_ui(stats: Stats, pool: ProxyManager) -> Group:
    elapsed = stats.elapsed
    rps = stats.rps
    remaining = max(0, stats.total - stats.checked)
    eta = remaining / rps if rps > 0 else 0.0

    cooling = sum(1 for p in pool.proxies if p.status() == "cooldown")
    quarantined = sum(1 for p in pool.proxies if p.status() == "quarantine")
    dead = sum(1 for p in pool.proxies if p.status() == "dead")
    ok = len(pool.proxies) - cooling - quarantined - dead

    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold dim", justify="right")
    info.add_column()
    info.add_column(style="bold dim", justify="right")
    info.add_column()

    info.add_row("Progress", _bar(stats.checked, stats.total), "Elapsed", _fmt_duration(elapsed))
    info.add_row(
        "Checked",
        f"[bold]{stats.checked}[/] / {stats.total}",
        "ETA",
        _fmt_duration(eta) if rps > 0 else "—",
    )
    info.add_row(
        "Speed",
        f"[bold cyan]{rps:.1f}[/] req/s",
        "Mode",
        _mode_label(pool),
    )
    info.add_row(
        "Available",
        f"[bold green]{stats.available}[/]",
        "Taken",
        f"[bold yellow]{stats.taken}[/]",
    )
    info.add_row(
        "Rate limits",
        f"[bold magenta]{stats.rate_limits}[/]  429",
        "Errors",
        f"[bold red]{stats.errors}[/]  abandoned {stats.abandoned}",
    )
    info.add_row(
        "Retries",
        str(stats.retries),
        "IPs",
        (
            f"[dim]IP/req · {pool.rotations} sessions[/]"
            if UNIQUE_SESSION_PER_REQUEST
            else f"[green]{ok} ok[/]  [yellow]{cooling} cd[/]  [red]{dead} dead[/]  [cyan]{pool.rotations} rot[/]"
        ),
    )
    if stats.skipped_resume or stats.invalid_format:
        info.add_row(
            "Resumed skip",
            str(stats.skipped_resume),
            "Invalid names",
            str(stats.invalid_format),
        )

    panels = [Panel(info, title="[bold]Discord Username Checker[/]", border_style="cyan")]

    if not UNIQUE_SESSION_PER_REQUEST:
        proxy_table = Table(
            title="IPs (même session jusqu'au 429 → ce slot seulement est remplacé)",
            expand=True,
            show_lines=False,
            pad_edge=False,
        )
        proxy_table.add_column("Proxy", style="cyan", overflow="fold")
        proxy_table.add_column("Remaining", justify="right")
        proxy_table.add_column("Limit", justify="right")
        proxy_table.add_column("Reset-After", justify="right")
        proxy_table.add_column("Bucket", overflow="ellipsis")
        proxy_table.add_column("Invalid/10m", justify="right")
        proxy_table.add_column("Status", justify="center")

        shown = pool.proxies if len(pool.proxies) <= 10 else (
            sorted(pool.proxies, key=lambda p: p.wait_seconds(), reverse=True)[:10]
        )
        for p in shown:
            st = p.status()
            st_style = {
                "ok": "green",
                "cooldown": "yellow",
                "quarantine": "red",
                "dead": "red",
            }[st]
            rem = "—" if p.limiter.remaining is None else str(p.limiter.remaining)
            lim = "—" if p.limiter.limit is None else str(p.limiter.limit)
            rst = "—" if p.limiter.reset_after is None else f"{p.limiter.reset_after:.2f}s"
            extra = ""
            if st == "cooldown":
                extra = f" {p.limiter.wait_seconds():.1f}s"
            elif st == "quarantine":
                extra = f" {p.invalid.wait_seconds():.0f}s"
            elif st == "dead":
                extra = f" {p.wait_seconds():.1f}s"
            scope = p.limiter.last_scope
            if p.limiter.last_global:
                extra += " global"
            elif scope:
                extra += f" {scope}"
            proxy_table.add_row(
                p.display,
                rem,
                lim,
                rst,
                p.limiter.bucket or "—",
                f"{p.invalid.count()}/{INVALID_REQUEST_LIMIT}",
                f"[{st_style}]{st}{extra}[/]",
            )
        panels.append(Panel(proxy_table, border_style="blue"))

    if UNIQUE_SESSION_PER_REQUEST:
        footer = Text(
            "Nouvelle IP à chaque requête · 429 = tunnel jeté · "
            "Ctrl+C sauve available.txt / taken.txt / errors.txt",
            style="dim",
        )
    else:
        footer = Text(
            "Même IP jusqu'au 429 · keep-alive · 429 → nouvelle session sur CE slot seulement · "
            "Ctrl+C sauve available.txt / taken.txt / errors.txt",
            style="dim",
        )
    panels.append(footer)
    return Group(*panels)


# =============================================================================
# Workers
# =============================================================================


async def check_one(
    session: aiohttp.ClientSession,
    proxy: Proxy,
    username: str,
) -> tuple[int, Optional[bool], str, float]:
    """Return (status, taken|None, scope, retry_after). taken is only set on HTTP 200."""
    retry_after = 0.0
    # Keep-alive = même IP. On ne ferme le tunnel que si on veut une nouvelle IP tout de suite.
    close_on_success = UNIQUE_SESSION_PER_REQUEST
    async with session.post(
        API_URL,
        json={"username": username},
        proxy=proxy.url,
        headers=REQUEST_HEADERS,
    ) as resp:
        proxy.limiter.update_from_headers(resp.headers)
        scope = str(resp.headers.get("X-RateLimit-Scope") or "")
        proxy.limiter.last_scope = scope

        if resp.status == 200:
            try:
                data = await resp.json(content_type=None)
            except Exception:
                if close_on_success:
                    _close_tunnel(resp)
                return resp.status, None, scope, retry_after
            taken = data.get("taken") if isinstance(data, dict) else None
            if close_on_success:
                _close_tunnel(resp)
            if isinstance(taken, bool):
                return resp.status, taken, scope, retry_after
            return resp.status, None, scope, retry_after

        if resp.status == 429:
            is_global = str(resp.headers.get("X-RateLimit-Global") or "").lower() == "true"
            retry_after = await parse_retry_after(resp)
            proxy.limiter.apply_cooldown(retry_after, is_global=is_global)
            proxy.limiter.last_global = is_global
            # IP épuisée : fermer le tunnel, le pool remplace ce sessid.
            _close_tunnel(resp)
            return resp.status, None, scope, retry_after

        _close_tunnel(resp)
        return resp.status, None, scope, retry_after


async def worker(
    _worker_id: int,
    queue: asyncio.Queue[tuple[str, int, str]],
    session: aiohttp.ClientSession,
    pool: ProxyManager,
    store: ResultStore,
    stats: Stats,
    sem: asyncio.Semaphore,
    stop: asyncio.Event,
) -> None:
    while not stop.is_set():
        try:
            username, attempts, last_err = await asyncio.wait_for(queue.get(), timeout=0.25)
        except asyncio.TimeoutError:
            continue

        # Backoff réseau sur CE username seulement — les autres workers continuent.
        if last_err == "net" and attempts > 0:
            delay = jittered_backoff(attempts)
            if delay > 0:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay)
                    await queue.put((username, attempts, last_err))
                    queue.task_done()
                    break
                except asyncio.TimeoutError:
                    pass

        proxy = None
        try:
            if stop.is_set():
                await queue.put((username, attempts, last_err))
                break

            proxy = await pool.acquire()
            if BASE_DELAY > 0:
                await asyncio.sleep(BASE_DELAY)

            async with sem:
                if stop.is_set():
                    await queue.put((username, attempts, last_err))
                    break
                exit_ip = "-"
                try:
                    if DEBUG and DEBUG_SHOW_IP:
                        exit_ip = await resolve_exit_ip(
                            session,
                            proxy,
                            cache=not UNIQUE_SESSION_PER_REQUEST,
                        )
                    status, taken, scope, retry_after = await check_one(session, proxy, username)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    if DEBUG:
                        debug_log(
                            username,
                            exit_ip,
                            "[red]ERR[/]",
                            f"{type(exc).__name__}  try={attempts + 1}/{MAX_RETRIES}",
                        )
                    stats.errors += 1
                    stats.retries += 1
                    if pool.can_replace:
                        await pool.drop(proxy)
                    elif pool.mode == "list":
                        proxy.record_failure()
                        proxy.limiter.apply_cooldown(1.0)
                    if attempts + 1 < MAX_RETRIES and not stop.is_set():
                        await queue.put((username, attempts + 1, "net"))
                    else:
                        stats.abandoned += 1
                        await store.save_error(username)
                    continue

            if is_cloudflare_invalid(status, scope):
                proxy.invalid.record()

            if pool.can_replace and (proxy.is_spent() or status in (401, 403, 429)):
                await pool.drop(proxy)

            if taken is not None:
                wrote = await store.save(username, taken)
                if wrote:
                    if taken:
                        stats.taken += 1
                    else:
                        stats.available += 1
                proxy.record_success()
                stats.record_ok()
                if DEBUG:
                    result = "[yellow]taken[/]" if taken else "[green]available[/]"
                    debug_log(username, exit_ip, f"[green]{status}[/]", result)
                continue

            if status == 429:
                stats.rate_limits += 1
                stats.retries += 1
                if pool.mode == "list":
                    proxy.record_429(retry_after)
                if DEBUG:
                    burned = retry_after >= HUGE_RETRY_AFTER
                    debug_log(
                        username,
                        exit_ip,
                        "[magenta]429[/]",
                        (
                            f"IP burned retry_after={retry_after:.0f}s → new session  "
                            f"try={attempts + 1}/{MAX_RETRIES}"
                            if burned
                            else f"retry_after={retry_after:.2f}s → new IP  try={attempts + 1}/{MAX_RETRIES}"
                        ),
                    )
                # Retry immédiat : nouvelle IP (rotating) / autre slot (sticky/list).
                # On ne sleep PAS Retry-After ici — ça bloquerait ce worker pour rien.
                if attempts + 1 < MAX_RETRIES and not stop.is_set():
                    await queue.put((username, attempts + 1, "429"))
                else:
                    stats.abandoned += 1
                    await store.save_error(username)
                continue

            stats.errors += 1
            if DEBUG:
                debug_log(
                    username,
                    exit_ip,
                    f"[red]{status}[/]",
                    f"try={attempts + 1}/{MAX_RETRIES}",
                )
            if status in (401, 403):
                if pool.mode == "list":
                    proxy.limiter.apply_cooldown(proxy.limiter.reset_after or 1.0)
                    proxy.record_failure()
                if attempts + 1 < MAX_RETRIES and not stop.is_set():
                    stats.retries += 1
                    await queue.put((username, attempts + 1, "net"))
                else:
                    stats.abandoned += 1
                    await store.save_error(username)
                continue
            if attempts + 1 < MAX_RETRIES and not stop.is_set():
                stats.retries += 1
                await queue.put((username, attempts + 1, "net"))
            else:
                stats.abandoned += 1
                await store.save_error(username)
        finally:
            if proxy is not None:
                if pool.can_replace and proxy.is_spent():
                    await pool.drop(proxy)
                pool.release(proxy)
            queue.task_done()


# =============================================================================
# Main
# =============================================================================


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> None:
    def _request_stop() -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda *_: _request_stop())


async def async_main() -> int:
    try:
        pool = build_proxy_manager()
    except (FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    try:
        all_names = load_usernames(USERNAMES_FILE)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    store = ResultStore(AVAILABLE_FILE, TAKEN_FILE, ERRORS_FILE)
    stats = Stats()
    pending: list[str] = []
    for name in all_names:
        if not is_valid_username(name):
            stats.invalid_format += 1
            continue
        if store.already_checked(name):
            stats.skipped_resume += 1
            continue
        pending.append(name)

    stats.total = len(pending)
    console.print(
        f"[dim]Loaded {len(all_names)} usernames · "
        f"{stats.skipped_resume} already checked · "
        f"{stats.invalid_format} invalid · "
        f"{stats.total} to check · "
        f"{len(store.available)} available / {len(store.taken)} taken on disk · "
        f"mode={pool.mode} provider={PROVIDER} unique_session={UNIQUE_SESSION_PER_REQUEST}[/]"
    )
    if DEBUG:
        console.print(
            "[magenta]Debug ON[/] — chaque requête affiche "
            f"[bold]username[/] + {'[bold]IP de sortie[/]' if DEBUG_SHOW_IP else 'sans IP'} "
            "[dim](remettre debug.enabled = false pour le RPS max)[/]"
        )

    if stats.total == 0:
        console.print("[green]Nothing to check. All valid usernames are already in available.txt or taken.txt.[/]")
        store.close()
        return 0

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop, stop)

    queue: asyncio.Queue[tuple[str, int, str]] = asyncio.Queue()
    for name in pending:
        queue.put_nowait((name, 0, ""))

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT)
    connector = aiohttp.TCPConnector(
        limit=MAX_CONCURRENT,
        limit_per_host=MAX_CONCURRENT,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=FORCE_CLOSE,
        keepalive_timeout=KEEPALIVE_TIMEOUT,
        family=socket.AF_INET,
    )

    worker_count = max(1, min(WORKERS, stats.total, MAX_CONCURRENT * 2))
    worker_tasks: list[asyncio.Task] = []

    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=REQUEST_HEADERS,
        ) as session:
            for i in range(worker_count):
                worker_tasks.append(
                    asyncio.create_task(
                        worker(i, queue, session, pool, store, stats, sem, stop),
                        name=f"worker-{i}",
                    )
                )

            async def _join_or_stop() -> None:
                join = asyncio.create_task(queue.join())
                stop_wait = asyncio.create_task(stop.wait())
                done, _ = await asyncio.wait(
                    {join, stop_wait},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_wait in done:
                    join.cancel()
                else:
                    stop_wait.cancel()
                    stop.set()

            with Live(
                render_ui(stats, pool),
                console=console,
                refresh_per_second=UI_REFRESH_HZ,
                transient=False,
            ) as live:
                ui_task_stop = asyncio.Event()

                async def _ui_loop() -> None:
                    while not ui_task_stop.is_set():
                        live.update(render_ui(stats, pool))
                        try:
                            await asyncio.wait_for(ui_task_stop.wait(), timeout=1 / UI_REFRESH_HZ)
                        except asyncio.TimeoutError:
                            continue
                    live.update(render_ui(stats, pool))

                ui_task = asyncio.create_task(_ui_loop())
                try:
                    await _join_or_stop()
                finally:
                    ui_task_stop.set()
                    await ui_task
    finally:
        stop.set()
        for t in worker_tasks:
            t.cancel()
        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)
        store.close()

    console.print()
    console.print(
        Panel(
            f"[green]Available: {stats.available}[/]  "
            f"[yellow]Taken: {stats.taken}[/]  "
            f"[magenta]429: {stats.rate_limits}[/]  "
            f"[red]Errors: {stats.errors}[/]  abandoned {stats.abandoned}\n"
            f"Elapsed {_fmt_duration(stats.elapsed)}  ·  "
            f"avg {stats.checked / max(stats.elapsed, 0.001):.1f} req/s\n"
            f"[dim]Progress saved to {AVAILABLE_FILE}, {TAKEN_FILE} and {ERRORS_FILE}. "
            f"Re-run to resume remaining usernames.[/]",
            title="Run complete" if stats.checked >= stats.total else "Run paused",
            border_style="green" if stats.checked >= stats.total else "yellow",
        )
    )
    return 0


def main() -> None:
    try:
        raise SystemExit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — progress is on disk.[/]")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
