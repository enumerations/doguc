#!/usr/bin/env python3

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
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote

import aiohttp
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

CONFIG_FILE = "config.toml"
API_URL = "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
IP_ECHO_URL = "https://api.ipify.org"
RPS_WINDOW = 5.0
USERNAME_RE = re.compile(r"^[a-z0-9._]{2,32}$")
_EXIT_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_GATEWAY_USER_RE = re.compile(r"^[^\s@\x00-\x1f]{1,256}$")

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

Job = tuple[str, int, str]
console = Console()

@dataclass(frozen=True)
class Config:
    use_gateway: bool
    gateway_host: str
    gateway_port: int
    gateway_user: str
    gateway_pass: str
    gateway_username_template: str
    gateway_sessions: int
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
    max_429_before_cooldown: int
    dead_after_failures: int
    dead_cooldown_seconds: float
    max_inflight_per_ip: int
    error_burst_limit: int
    error_burst_window: float
    error_burst_quiet: float
    error_burst_probes: int
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
    here = os.path.dirname(os.path.abspath(__file__))
    beside_script = os.path.join(here, CONFIG_FILE)
    if os.path.isfile(beside_script):
        return beside_script
    return os.path.abspath(CONFIG_FILE)


def _read_toml(path: str) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _is_gateway_host(host: str) -> bool:
    if _IPV4_RE.fullmatch(host):
        return all(0 <= int(part) <= 255 for part in host.split("."))
    return bool(_HOSTNAME_RE.fullmatch(host))


def _parse_gateway_port(port_raw: str) -> int:
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ValueError(f"gateway.port must be an integer between 1 and 65535, got {port_raw!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"gateway.port must be an integer between 1 and 65535, got {port_raw!r}")
    return port


def _validate_username_template(template: str) -> None:
    if not template.strip():
        raise ValueError("gateway.username_template must be a non-empty pattern.")
    if "{user}" not in template or "{session}" not in template:
        raise ValueError("gateway.username_template must include {user} and {session}.")
    try:
        rendered = template.format(user="u", session="s", lifetime=1)
    except (KeyError, ValueError, IndexError) as exc:
        raise ValueError(f"gateway.username_template is invalid: {exc}") from exc
    if not rendered.strip():
        raise ValueError("gateway.username_template produced an empty username.")


def _validate_gateway_config(
    host: str,
    user: str,
    password: str,
    username_template: str,
) -> None:
    if not _is_gateway_host(host):
        raise ValueError("gateway.host must be a hostname or IPv4 address.")
    if not _GATEWAY_USER_RE.fullmatch(user):
        raise ValueError("gateway.user must be a non-empty username without spaces or '@'.")
    if not password or len(password) > 256 or any(ch in password for ch in "\n\r\0"):
        raise ValueError("gateway.password must be a non-empty password.")
    _validate_username_template(username_template)


def load_config(path: str | None = None) -> Config:
    path = path or _config_path()
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            f"Copy or create {CONFIG_FILE} next to checker.py."
        )
    raw = _read_toml(path)

    base = os.path.dirname(os.path.abspath(path))
    gw = raw.get("gateway", {})
    files = raw.get("files", {})
    perf = raw.get("performance", {})
    rl = raw.get("rate_limit", {})
    pause = raw.get("pause", {})
    cf = raw.get("cloudflare", {})
    dbg = raw.get("debug", {})

    try:
        max_concurrent = int(perf["max_concurrent"])
        use_gateway = bool(gw["enabled"])
        gateway_host = str(gw.get("host") or "").strip()
        port_raw = str(gw.get("port") or "").strip()
        gateway_user = str(gw.get("user") or "").strip()
        gateway_pass = str(gw.get("password") or "").strip()
        gateway_username_template = str(
            gw.get("username_template", "{user}-session-{session}-lifetime-{lifetime}")
        )
        if use_gateway:
            gateway_port = _parse_gateway_port(port_raw)
            _validate_gateway_config(
                gateway_host,
                gateway_user,
                gateway_pass,
                gateway_username_template,
            )
        else:
            try:
                gateway_port = int(port_raw) if port_raw else 0
            except ValueError as exc:
                raise ValueError(f"gateway.port must be an integer, got {port_raw!r}") from exc
        return Config(
            use_gateway=use_gateway,
            gateway_host=gateway_host,
            gateway_port=gateway_port,
            gateway_user=gateway_user,
            gateway_pass=gateway_pass,
            gateway_username_template=gateway_username_template,
            gateway_sessions=max(1, int(gw.get("sessions", max_concurrent))),
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
            max_429_before_cooldown=int(rl.get("max_429_before_cooldown", 3)),
            dead_after_failures=int(rl.get("dead_after_failures", 8)),
            dead_cooldown_seconds=float(rl.get("dead_cooldown_seconds", 30.0)),
            max_inflight_per_ip=max(1, int(rl.get("max_inflight_per_ip", 1))),
            error_burst_limit=max(1, int(pause.get("error_limit", 250))),
            error_burst_window=float(pause.get("window_seconds", 4.0)),
            error_burst_quiet=float(pause.get("quiet_seconds", pause.get("pause_seconds", 8.0))),
            error_burst_probes=max(1, int(pause.get("probes", 8))),
            invalid_request_window=float(cf["window_seconds"]),
            invalid_request_limit=int(cf["limit"]),
            debug=bool(dbg.get("enabled", False)),
            debug_show_ip=bool(dbg.get("show_exit_ip", True)),
        )
    except KeyError as exc:
        raise ValueError(f"Missing key in {path}: {exc}") from exc

def is_valid_username(username: str) -> bool:
    if not USERNAME_RE.fullmatch(username):
        return False
    if ".." in username:
        return False
    if username.startswith(".") or username.endswith("."):
        return False
    return True


def normalize_username(raw: str) -> str:
    return raw.strip().lower()


def _iter_usernames(path: str) -> Iterator[str]:
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            name = normalize_username(raw)
            if name and not name.startswith("#"):
                yield name


def _load_username_set(path: str) -> set[str]:
    if not os.path.isfile(path):
        return set()
    return set(_iter_usernames(path))


def load_usernames(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Username list not found: {path}")
    ordered: list[str] = []
    seen: set[str] = set()
    for name in _iter_usernames(path):
        if name in seen:
            continue
        seen.add(name)
        ordered.append(name)
    return ordered

def jittered_backoff(attempt: int, cfg: Config) -> float:
    if attempt <= 0:
        return 0.0
    ceiling = min(cfg.retry_backoff_cap, cfg.retry_backoff_base * (2 ** attempt))
    return random.uniform(0.0, ceiling)


def _header_float(headers: Mapping[str, str], name: str) -> float | None:
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _header_int(headers: Mapping[str, str], name: str) -> int | None:
    raw = headers.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None

class InvalidRequestTracker:

    def __init__(self, window: float, limit: int) -> None:
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

    def is_quarantined(self) -> bool:
        self._prune(time.monotonic())
        return len(self._ts) >= self.limit

    def wait_seconds(self) -> float:
        self._prune(time.monotonic())
        if len(self._ts) < self.limit:
            return 0.0
        return max(0.0, self._ts[0] + self.window - time.monotonic())


class ProxyRateLimiter:

    def __init__(self) -> None:
        self.remaining: int | None = None
        self.reset_after: float | None = None
        self.cooldown_until: float = 0.0
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
        if is_global:
            self.remaining = 0

    def update_from_headers(self, headers: Mapping[str, str]) -> None:
        remaining = _header_int(headers, "X-RateLimit-Remaining")
        if remaining is not None:
            self.remaining = remaining
        reset_after = _header_float(headers, "X-RateLimit-Reset-After")
        if reset_after is not None:
            self.reset_after = reset_after

    async def try_acquire(self, low_remaining_threshold: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            if self.cooldown_until > now:
                return False
            if self.remaining is not None and self.remaining <= low_remaining_threshold:
                return False
            if self.remaining is not None:
                self.remaining = max(0, self.remaining - 1)
            return True


@dataclass
class Proxy:
    url: str
    cfg: Config
    in_flight: int = 0
    consecutive_429: int = 0
    consecutive_failures: int = 0
    dead_until: float = 0.0
    force_replace: bool = False
    limiter: ProxyRateLimiter = field(default_factory=ProxyRateLimiter)
    invalid: InvalidRequestTracker = field(init=False)

    def __post_init__(self) -> None:
        self.invalid = InvalidRequestTracker(
            self.cfg.invalid_request_window,
            self.cfg.invalid_request_limit,
        )

    def is_spent(self) -> bool:
        if self.dead_until > time.monotonic():
            return True
        if self.invalid.is_quarantined():
            return True
        if self.limiter.is_cooling():
            return True
        if (
            self.limiter.remaining is not None
            and self.limiter.remaining <= self.cfg.low_remaining_threshold
        ):
            return True
        return False

    def needs_replace(self) -> bool:
        if self.force_replace:
            return True
        if self.dead_until > time.monotonic():
            return True
        if self.invalid.is_quarantined():
            return True
        if (
            self.limiter.remaining is not None
            and self.limiter.remaining <= self.cfg.low_remaining_threshold
        ):
            return True
        return False

    def retire(self) -> None:
        self.force_replace = True

    def wait_seconds(self) -> float:
        now = time.monotonic()
        dead_wait = max(0.0, self.dead_until - now) if self.dead_until > now else 0.0
        return max(self.limiter.wait_seconds(), self.invalid.wait_seconds(), dead_wait)

    def mark_dead(self, seconds: float) -> None:
        self.dead_until = max(self.dead_until, time.monotonic() + max(0.0, seconds))

    def record_success(self) -> None:
        self.consecutive_429 = 0
        self.consecutive_failures = 0

    def record_429(self, retry_after: float) -> None:
        self.consecutive_429 += 1
        self.consecutive_failures = 0
        if self.consecutive_429 >= self.cfg.max_429_before_cooldown:
            extra = max(retry_after, 1.0) * self.consecutive_429
            self.mark_dead(min(extra, self.cfg.dead_cooldown_seconds))

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.cfg.dead_after_failures:
            self.mark_dead(self.cfg.dead_cooldown_seconds)
            self.consecutive_failures = 0


def parse_proxy_line(line: str) -> str | None:
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


class ExitIpCache:

    def __init__(self) -> None:
        self._ips: dict[str, str] = {}
        self._lock = asyncio.Lock()

    def forget(self, url: str) -> None:
        self._ips.pop(url, None)

    async def get(self, url: str) -> str | None:
        async with self._lock:
            return self._ips.get(url)

    async def put(self, url: str, ip: str) -> None:
        async with self._lock:
            self._ips[url] = ip


def _gateway_auth_url(cfg: Config, username: str) -> str:
    user_q = quote(username, safe="_;.-")
    pass_q = quote(cfg.gateway_pass, safe="")
    return f"http://{user_q}:{pass_q}@{cfg.gateway_host}:{cfg.gateway_port}"


def _rotating_session_user(cfg: Config, session_id: str) -> str:
    return cfg.gateway_username_template.format(
        user=cfg.gateway_user,
        session=session_id,
        lifetime=1,
    )


def _gateway_proxy(cfg: Config) -> Proxy:
    session_id = secrets.token_hex(6)
    username = _rotating_session_user(cfg, session_id)
    return Proxy(url=_gateway_auth_url(cfg, username), cfg=cfg)


class BurstPause:

    def __init__(self, limit: int, window: float, quiet: float, probes: int) -> None:
        self.limit = limit
        self.window = window
        self.quiet = quiet
        self.probes = probes
        self._ts: deque[float] = deque()
        self._open = False
        self._last_error = 0.0
        self._probe_inflight = 0

    def remaining(self) -> float:
        if not self._open:
            return 0.0
        left = max(0.0, self._last_error + self.quiet - time.monotonic())
        if left <= 0:
            self._close()
            return 0.0
        return left

    @property
    def paused(self) -> bool:
        return self.remaining() > 0

    def _close(self) -> None:
        self._open = False
        self._ts.clear()

    def record(self) -> None:
        now = time.monotonic()
        self._last_error = now
        if self._open:
            return
        cutoff = now - self.window
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()
        self._ts.append(now)
        if len(self._ts) >= self.limit:
            self._open = True
            self._ts.clear()

    def release_slot(self, is_probe: bool) -> None:
        if is_probe:
            self._probe_inflight = max(0, self._probe_inflight - 1)

    async def acquire_slot(self, stop: asyncio.Event) -> bool:
        """Wait while paused, unless this worker is allowed to probe. True = probe."""
        while not stop.is_set():
            if not self._open:
                return False
            if self.remaining() <= 0:
                return False
            if self._probe_inflight < self.probes:
                self._probe_inflight += 1
                return True
            try:
                await asyncio.wait_for(stop.wait(), timeout=min(0.25, self.remaining() or 0.25))
            except asyncio.TimeoutError:
                continue
        return False


class ProxyManager:

    def __init__(
        self,
        proxies: list[Proxy],
        *,
        cfg: Config,
        mode: str,
        factory: Callable[[], Proxy] | None = None,
    ) -> None:
        self.proxies = proxies
        self.cfg = cfg
        self.mode = mode
        self._factory = factory
        self._rr = 0
        self._lock = asyncio.Lock()
        self.rotations = 0
        self.exit_ips = ExitIpCache()
        self.burst = BurstPause(
            cfg.error_burst_limit,
            cfg.error_burst_window,
            cfg.error_burst_quiet,
            cfg.error_burst_probes,
        )

    @property
    def can_replace(self) -> bool:
        return self._factory is not None

    def release(self, proxy: Proxy) -> None:
        proxy.in_flight = max(0, proxy.in_flight - 1)

    def _replace_at(self, idx: int) -> Proxy:
        if self._factory is None:
            raise RuntimeError("replace requires a proxy factory")
        old = self.proxies[idx]
        self.exit_ips.forget(old.url)
        new = self._factory()
        self.proxies[idx] = new
        self.rotations += 1
        return new

    def _drop_unlocked(self, proxy: Proxy) -> Proxy | None:
        if not self.can_replace:
            return None
        try:
            idx = self.proxies.index(proxy)
        except ValueError:
            return None
        return self._replace_at(idx)

    def _sweep_unlocked(self) -> None:
        if not self.can_replace:
            return
        for i, proxy in enumerate(list(self.proxies)):
            if proxy.needs_replace():
                self._replace_at(i)

    async def drop(self, proxy: Proxy) -> None:
        if not self.can_replace:
            return
        async with self._lock:
            self._drop_unlocked(proxy)

    def _new_rotating_handle(self) -> Proxy:
        session_id = secrets.token_hex(8)
        url = _gateway_auth_url(self.cfg, _rotating_session_user(self.cfg, session_id))
        self.rotations += 1
        return Proxy(url=url, cfg=self.cfg, in_flight=1)

    async def acquire(self) -> Proxy:
        if self.mode == "rotating" and self.cfg.unique_session_per_request:
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
                        if self.can_replace and proxy.needs_replace():
                            proxy = self._drop_unlocked(proxy) or proxy
                        else:
                            continue
                    if proxy.is_spent():
                        continue
                    if proxy.in_flight >= self.cfg.max_inflight_per_ip:
                        continue
                    if await proxy.limiter.try_acquire(self.cfg.low_remaining_threshold):
                        proxy.in_flight += 1
                        return proxy

                waits = [p.wait_seconds() for p in self.proxies]
                positive = [w for w in waits if w > 0]
                wait = min(positive) if positive else 0.05

            await asyncio.sleep(min(max(wait, 0.02), 0.5))


def build_proxy_manager(cfg: Config) -> ProxyManager:
    if cfg.use_gateway and cfg.unique_session_per_request:
        handle = Proxy(url=_gateway_auth_url(cfg, cfg.gateway_user), cfg=cfg)
        return ProxyManager([handle], cfg=cfg, mode="rotating")
    if cfg.use_gateway:
        slots = max(1, cfg.gateway_sessions, cfg.max_concurrent)
        return ProxyManager(
            [_gateway_proxy(cfg) for _ in range(slots)],
            cfg=cfg,
            mode="rotating",
            factory=lambda: _gateway_proxy(cfg),
        )
    return ProxyManager(
        [Proxy(url=url, cfg=cfg) for url in load_proxy_list(cfg.proxies_file)],
        cfg=cfg,
        mode="list",
    )

class ResultStore:

    def __init__(
        self,
        available_path: str,
        taken_path: str,
        errors_path: str,
        flush_every: int,
    ) -> None:
        self.available = _load_username_set(available_path)
        self.taken = _load_username_set(taken_path)
        self._flush_every = flush_every
        self._lock = asyncio.Lock()
        self._available_fp = open(available_path, "a", encoding="utf-8")
        self._taken_fp = open(taken_path, "a", encoding="utf-8")
        self._errors_fp = open(errors_path, "a", encoding="utf-8")
        self._dirty = 0

    def already_checked(self, username: str) -> bool:
        return username in self.available or username in self.taken

    def _maybe_flush(self) -> None:
        self._dirty += 1
        if self._dirty >= self._flush_every:
            self._flush()

    def _flush(self) -> None:
        for fp in (self._available_fp, self._taken_fp, self._errors_fp):
            fp.flush()
        self._dirty = 0

    async def save(self, username: str, taken: bool) -> bool:
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
    started_at: float = field(default_factory=time.monotonic)
    _hits: deque[float] = field(default_factory=deque)

    def _prune_hits(self, now: float) -> None:
        cutoff = now - RPS_WINDOW
        while self._hits and self._hits[0] < cutoff:
            self._hits.popleft()

    def record_ok(self) -> None:
        now = time.monotonic()
        self._hits.append(now)
        self._prune_hits(now)

    @property
    def checked(self) -> int:
        return self.available + self.taken

    @property
    def rps(self) -> float:
        now = time.monotonic()
        self._prune_hits(now)
        window = min(RPS_WINDOW, max(now - self.started_at, 0.001))
        return len(self._hits) / window

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at


def select_pending(names: list[str], store: ResultStore, stats: Stats) -> list[str]:
    pending: list[str] = []
    for name in names:
        if not is_valid_username(name):
            stats.invalid_format += 1
            continue
        if store.already_checked(name):
            stats.skipped_resume += 1
            continue
        pending.append(name)
    return pending


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckResult:
    status: int
    taken: bool | None
    scope: str


def _close_tunnel(resp: aiohttp.ClientResponse) -> None:
    conn = resp.connection
    if conn is not None and not conn.closed:
        conn.close()


def is_cloudflare_invalid(status: int, scope: str) -> bool:
    if status in (401, 403):
        return True
    if status == 429:
        return scope.lower() != "shared"
    return False


def debug_log(username: str, ip: str, status: str, detail: str) -> None:
    console.log(
        f"[magenta]debug[/]  user=[bold white]{username}[/]  "
        f"ip=[cyan]{ip}[/]  {status}  {detail}"
    )


def _try_label(attempts: int, max_retries: int) -> str:
    return f"try={attempts + 1}/{max_retries}"


async def resolve_exit_ip(
    session: aiohttp.ClientSession,
    proxy: Proxy,
    cache: ExitIpCache,
    *,
    use_cache: bool,
) -> str:
    if use_cache:
        cached = await cache.get(proxy.url)
        if cached:
            return cached
    try:
        async with session.get(
            IP_ECHO_URL,
            proxy=proxy.url,
            timeout=aiohttp.ClientTimeout(
                total=min(4.0, proxy.cfg.request_timeout),
                connect=min(3.0, proxy.cfg.connect_timeout),
            ),
            headers={"Accept": "text/plain", "User-Agent": REQUEST_HEADERS["User-Agent"]},
        ) as resp:
            raw = (await resp.text()).strip()
    except Exception:
        return "?"
    ip = raw.split()[0] if raw else ""
    if not ip or not _EXIT_IP_RE.fullmatch(ip):
        return "?"
    if use_cache:
        await cache.put(proxy.url, ip)
    return ip


async def check_one(
    session: aiohttp.ClientSession,
    proxy: Proxy,
    username: str,
) -> CheckResult:
    close_tunnel = False
    close_on_success = proxy.cfg.unique_session_per_request
    async with session.post(
        API_URL,
        json={"username": username},
        proxy=proxy.url,
        headers=REQUEST_HEADERS,
    ) as resp:
        try:
            proxy.limiter.update_from_headers(resp.headers)
            scope = str(resp.headers.get("X-RateLimit-Scope") or "")

            if resp.status == 200:
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    close_tunnel = close_on_success
                    return CheckResult(resp.status, None, scope)
                taken = data.get("taken") if isinstance(data, dict) else None
                close_tunnel = close_on_success
                if isinstance(taken, bool):
                    return CheckResult(resp.status, taken, scope)
                return CheckResult(resp.status, None, scope)

            if resp.status == 429:
                close_tunnel = True
                return CheckResult(resp.status, None, scope)

            close_tunnel = True
            return CheckResult(resp.status, None, scope)
        finally:
            if close_tunnel:
                _close_tunnel(resp)


def _build_connector(cfg: Config) -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(
        limit=cfg.max_concurrent,
        limit_per_host=cfg.max_concurrent,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=cfg.force_close,
        keepalive_timeout=cfg.keepalive_timeout,
        family=socket.AF_INET,
    )


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _fmt_int(n: int) -> str:
    return f"{n:,}"


def _bar(done: int, total: int, width: int = 46) -> Text:
    pct = 1.0 if total <= 0 else min(1.0, done / total)
    filled = int(round(width * pct))
    text = Text()
    text.append("━" * filled, style="cyan")
    text.append("━" * (width - filled), style="dim")
    text.append(f"  {pct:5.1%}")
    return text


def _mode_label(pool: ProxyManager) -> str:
    if pool.mode == "rotating" and pool.cfg.unique_session_per_request:
        return "rotating · IP/req"
    if pool.mode == "rotating":
        return "rotating · reuse"
    return f"list · {len(pool.proxies)} proxies"


def render_ui(stats: Stats, pool: ProxyManager) -> Panel:
    rps = stats.rps
    remaining = max(0, stats.total - stats.checked)
    eta = remaining / rps if rps > 0 else 0.0

    progress = Table.grid(padding=(0, 3), expand=True)
    progress.add_column(style="dim", justify="right", min_width=9)
    progress.add_column(ratio=1)
    progress.add_row("progress", _bar(stats.checked, stats.total))

    metrics = Table.grid(padding=(0, 3), expand=True)
    metrics.add_column(style="dim", justify="right", min_width=9)
    metrics.add_column(ratio=1)
    metrics.add_column(style="dim", justify="right")
    metrics.add_column(ratio=1)

    metrics.add_row(
        "checked",
        f"[bold]{_fmt_int(stats.checked)}[/] / {_fmt_int(stats.total)}",
        "speed",
        f"[bold cyan]{rps:.1f}[/] req/s",
    )
    metrics.add_row(
        "available",
        f"[bold green]{_fmt_int(stats.available)}[/]",
        "taken",
        f"[bold yellow]{_fmt_int(stats.taken)}[/]",
    )
    limits = f"[magenta]{_fmt_int(stats.rate_limits)}[/]"
    if stats.errors:
        limits += f"  [red]{_fmt_int(stats.errors)} err[/]"
    metrics.add_row(
        "eta",
        _fmt_duration(eta) if rps > 0 else "—",
        "429",
        limits,
    )
    metrics.add_row(
        "mode",
        _mode_label(pool),
        "rotations",
        f"[cyan]{_fmt_int(pool.rotations)}[/]",
    )
    metrics.add_row(
        "invalid",
        f"[pink3]{_fmt_int(stats.invalid_format)}[/]",
    )

    left = pool.burst.remaining()
    if left > 0:
        subtitle = f"[yellow]paused {_fmt_duration(left)}[/]"
    else:
        subtitle = f"[dim]{_fmt_duration(stats.elapsed)}[/]"

    return Panel(
        Group(progress, Text(), metrics),
        title="[bold]doguc[/]",
        subtitle=subtitle,
        subtitle_align="right",
        border_style="cyan",
        padding=(1, 1),
    )


def render_summary(stats: Stats, cfg: Config) -> Panel:
    complete = stats.checked >= stats.total
    return Panel(
        f"[green]Available: {stats.available}[/]  "
        f"[yellow]Taken: {stats.taken}[/]  "
        f"[magenta]429: {stats.rate_limits}[/]  "
        f"[red]Errors: {stats.errors}[/]  abandoned {stats.abandoned}\n"
        f"Elapsed {_fmt_duration(stats.elapsed)}  ·  "
        f"avg {stats.checked / max(stats.elapsed, 0.001):.1f} req/s\n"
        f"[dim]Progress saved to {cfg.available_file}, {cfg.taken_file} and {cfg.errors_file}. "
        f"Re-run to resume remaining usernames.[/]",
        title="Run complete" if complete else "Run paused",
        border_style="green" if complete else "yellow",
    )

@dataclass
class RunContext:
    cfg: Config
    queue: asyncio.Queue[Job]
    session: aiohttp.ClientSession
    pool: ProxyManager
    store: ResultStore
    stats: Stats
    sem: asyncio.Semaphore
    stop: asyncio.Event


async def _requeue_or_abandon(ctx: RunContext, username: str, attempts: int, err_kind: str) -> None:
    if attempts + 1 < ctx.cfg.max_retries and not ctx.stop.is_set():
        await ctx.queue.put((username, attempts + 1, err_kind))
        return
    ctx.stats.abandoned += 1
    await ctx.store.save_error(username)


async def _on_transport_error(
    ctx: RunContext,
    proxy: Proxy,
    username: str,
    attempts: int,
    exit_ip: str,
    exc: BaseException,
) -> None:
    if ctx.cfg.debug:
        debug_log(
            username,
            exit_ip,
            "[red]ERR[/]",
            f"{type(exc).__name__}  {_try_label(attempts, ctx.cfg.max_retries)}",
        )
    ctx.stats.errors += 1
    ctx.pool.burst.record()
    proxy.retire()
    if ctx.pool.can_replace:
        await ctx.pool.drop(proxy)
    elif ctx.pool.mode == "list":
        proxy.record_failure()
        proxy.limiter.apply_cooldown(1.0)
    await _requeue_or_abandon(ctx, username, attempts, "net")


async def _on_hit(
    ctx: RunContext,
    proxy: Proxy,
    username: str,
    taken: bool,
    status: int,
    exit_ip: str,
) -> None:
    wrote = await ctx.store.save(username, taken)
    if wrote:
        if taken:
            ctx.stats.taken += 1
        else:
            ctx.stats.available += 1
    proxy.record_success()
    ctx.stats.record_ok()
    if ctx.cfg.debug:
        result = "[yellow]taken[/]" if taken else "[green]available[/]"
        debug_log(username, exit_ip, f"[green]{status}[/]", result)


async def _on_rate_limit(
    ctx: RunContext,
    proxy: Proxy,
    username: str,
    attempts: int,
    exit_ip: str,
) -> None:
    ctx.stats.rate_limits += 1
    if ctx.pool.mode == "list":
        proxy.record_429(1.0)
    if ctx.cfg.debug:
        debug_log(
            username,
            exit_ip,
            "[magenta]429[/]",
            f"new IP  {_try_label(attempts, ctx.cfg.max_retries)}",
        )
    await _requeue_or_abandon(ctx, username, attempts, "429")


async def _on_http_error(
    ctx: RunContext,
    proxy: Proxy,
    username: str,
    attempts: int,
    exit_ip: str,
    status: int,
) -> None:
    ctx.stats.errors += 1
    if ctx.cfg.debug:
        debug_log(
            username,
            exit_ip,
            f"[red]{status}[/]",
            _try_label(attempts, ctx.cfg.max_retries),
        )
    if status in (401, 403) and ctx.pool.mode == "list":
        proxy.limiter.apply_cooldown(proxy.limiter.reset_after or 1.0)
        proxy.record_failure()
    if attempts + 1 < ctx.cfg.max_retries and not ctx.stop.is_set():
        await ctx.queue.put((username, attempts + 1, "net"))
        return
    ctx.stats.abandoned += 1
    await ctx.store.save_error(username)


async def _backoff_net_retry(ctx: RunContext, username: str, attempts: int, last_err: str) -> bool:
    """Sleep with jitter after a network error. True = stop requested, job requeued."""
    if last_err != "net" or attempts <= 0:
        return False
    delay = jittered_backoff(attempts, ctx.cfg)
    if delay <= 0:
        return False
    try:
        await asyncio.wait_for(ctx.stop.wait(), timeout=delay)
        await ctx.queue.put((username, attempts, last_err))
        ctx.queue.task_done()
        return True
    except asyncio.TimeoutError:
        return False


async def _release_proxy(pool: ProxyManager, proxy: Proxy | None) -> None:
    if proxy is None:
        return
    if pool.can_replace and proxy.needs_replace():
        await pool.drop(proxy)
    pool.release(proxy)


async def worker(ctx: RunContext) -> None:
    while not ctx.stop.is_set():
        try:
            username, attempts, last_err = await asyncio.wait_for(ctx.queue.get(), timeout=0.25)
        except asyncio.TimeoutError:
            continue

        if await _backoff_net_retry(ctx, username, attempts, last_err):
            break

        is_probe = False
        proxy = None
        try:
            is_probe = await ctx.pool.burst.acquire_slot(ctx.stop)
            if ctx.stop.is_set():
                await ctx.queue.put((username, attempts, last_err))
                break

            proxy = await ctx.pool.acquire()
            if ctx.cfg.base_delay > 0:
                await asyncio.sleep(ctx.cfg.base_delay)

            async with ctx.sem:
                if ctx.stop.is_set():
                    await ctx.queue.put((username, attempts, last_err))
                    break
                exit_ip = "-"
                try:
                    if ctx.cfg.debug and ctx.cfg.debug_show_ip:
                        exit_ip = await resolve_exit_ip(
                            ctx.session,
                            proxy,
                            ctx.pool.exit_ips,
                            use_cache=not ctx.cfg.unique_session_per_request,
                        )
                    result = await check_one(ctx.session, proxy, username)
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    await _on_transport_error(ctx, proxy, username, attempts, exit_ip, exc)
                    continue

            if is_cloudflare_invalid(result.status, result.scope):
                proxy.invalid.record()

            if result.status in (401, 403, 429):
                proxy.retire()
            if ctx.pool.can_replace and proxy.needs_replace():
                await ctx.pool.drop(proxy)

            if result.taken is not None:
                await _on_hit(ctx, proxy, username, result.taken, result.status, exit_ip)
                continue

            if result.status == 429:
                await _on_rate_limit(ctx, proxy, username, attempts, exit_ip)
                continue

            await _on_http_error(ctx, proxy, username, attempts, exit_ip, result.status)
        finally:
            ctx.pool.burst.release_slot(is_probe)
            await _release_proxy(ctx.pool, proxy)
            ctx.queue.task_done()


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, stop: asyncio.Event) -> None:
    def _request_stop() -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda *_: _request_stop())


async def _wait_queue_or_stop(queue: asyncio.Queue[Job], stop: asyncio.Event) -> None:
    join = asyncio.create_task(queue.join())
    stop_wait = asyncio.create_task(stop.wait())
    done, pending = await asyncio.wait(
        {join, stop_wait},
        return_when=asyncio.FIRST_COMPLETED,
    )
    if stop_wait not in done:
        stop.set()
    for task in pending:
        task.cancel()

async def async_main(cfg: Config) -> int:
    try:
        pool = build_proxy_manager(cfg)
    except (FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    try:
        all_names = load_usernames(cfg.usernames_file)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    store = ResultStore(cfg.available_file, cfg.taken_file, cfg.errors_file, cfg.flush_every)
    stats = Stats()
    pending = select_pending(all_names, store, stats)
    stats.total = len(pending)
    console.print(
        f"[dim]Loaded {len(all_names)} usernames · "
        f"{stats.skipped_resume} already checked · "
        f"{stats.invalid_format} invalid · "
        f"{stats.total} to check · "
        f"{len(store.available)} available / {len(store.taken)} taken on disk · "
        f"mode={pool.mode} unique_session={cfg.unique_session_per_request}[/]"
    )
    if cfg.debug:
        ip_label = "[bold]exit IP[/]" if cfg.debug_show_ip else "no IP"
        console.print(
            "[magenta]Debug ON[/] — each request logs "
            f"[bold]username[/] + {ip_label} "
            "[dim](set debug.enabled = false for max RPS)[/]"
        )

    if stats.total == 0:
        console.print("[green]Nothing to check. All valid usernames are already in available.txt or taken.txt.[/]")
        store.close()
        return 0

    stop = asyncio.Event()
    _install_signal_handlers(asyncio.get_running_loop(), stop)

    queue: asyncio.Queue[Job] = asyncio.Queue()
    for name in pending:
        queue.put_nowait((name, 0, ""))

    sem = asyncio.Semaphore(cfg.max_concurrent)
    timeout = aiohttp.ClientTimeout(total=cfg.request_timeout, connect=cfg.connect_timeout)
    connector = _build_connector(cfg)
    worker_count = max(1, min(cfg.workers, stats.total, cfg.max_concurrent * 2))
    worker_tasks: list[asyncio.Task] = []

    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=REQUEST_HEADERS,
        ) as session:
            ctx = RunContext(cfg, queue, session, pool, store, stats, sem, stop)
            for i in range(worker_count):
                worker_tasks.append(asyncio.create_task(worker(ctx), name=f"worker-{i}"))

            with Live(
                render_ui(stats, pool),
                console=console,
                refresh_per_second=cfg.ui_refresh_hz,
                transient=True,
                get_renderable=lambda: render_ui(stats, pool),
            ):
                await _wait_queue_or_stop(queue, stop)
    finally:
        stop.set()
        for t in worker_tasks:
            t.cancel()
        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)
        store.close()

    console.print(render_ui(stats, pool))
    console.print()
    console.print(render_summary(stats, cfg))
    return 0


def _result_files(cfg: Config) -> tuple[str, str, str]:
    return cfg.available_file, cfg.taken_file, cfg.errors_file


def _reset_result_files(cfg: Config) -> None:
    for path in _result_files(cfg):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8"):
            pass


def _ask_continue_previous_run() -> bool:
    if not sys.stdin.isatty():
        return True
    return Confirm.ask("Continue the previous run?", default=True, console=console)


def main() -> None:
    try:
        cfg = load_config()
    except (FileNotFoundError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    try:
        if not _ask_continue_previous_run():
            _reset_result_files(cfg)
            console.print("[dim]Previous results cleared. Starting a new run.[/]")
        raise SystemExit(asyncio.run(async_main(cfg)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted — progress is on disk.[/]")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
