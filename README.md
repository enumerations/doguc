<p align="center">
  <img src="assets/logo.png" width="420" alt="doguc">
</p>

<h1 align="center">doguc</h1>

<p align="center">
  <strong>d</strong>iscord · <strong>OGU</strong> · <strong>c</strong>hecker<br>
  Live terminal UI · rotating residential proxies · Ctrl+C and pick up where you left off.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/aiohttp-async-2EA44F?style=for-the-badge" alt="aiohttp">
  <img src="https://img.shields.io/badge/rich-UI-9B59B6?style=for-the-badge" alt="Rich">
  <a href="https://github.com/vinny/discord-username-checker/stargazers"><img src="https://img.shields.io/github/stars/vinny/discord-username-checker?style=for-the-badge" alt="Stars"></a>
  <a href="https://github.com/vinny/discord-username-checker/issues"><img src="https://img.shields.io/github/issues/vinny/discord-username-checker?style=for-the-badge" alt="Issues"></a>
</p>

---

Check a list of handles against Discord’s public unique-username endpoint, see **available / taken** in a live dashboard, and keep every result on disk so a crash or `Ctrl+C` never wastes work.

## Why people star this

Most checkers either die on the first `429`, or dump you into a wall of logs. This one is built like a production crawler:


|                                 |                                                                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **A 429 never stops the run**   | The burned IP is dropped. Other workers keep going. That username retries on a fresh session.                   |
| **Resume is the default**       | Hits land in `available.txt` / `taken.txt`. Rerun skips them. `errors.txt` is retried next launch.              |
| **Honest Discord headers**      | Bucket remaining, reset-after, and Cloudflare invalid-request budget are tracked **per exit IP**.               |
| **A UI you can actually watch** | Progress, req/s, ETA, available vs taken, proxy health — powered by [Rich](https://github.com/Textualize/rich). |
| **No Discord token**            | Unauthenticated `username-attempt-unauthed`. Secrets are only your **proxy** credentials.                       |




## Features

- **asyncio workers** with a bounded semaphore (`max_concurrent`) and a retry queue
- **Residential gateway** (`user:pass@host:port`) or a static `proxies.txt` list
- **Rotating** — reuse a session until Discord/Cloudflare burns it, then replace *that slot only*
- **Static list** — `proxies.txt` with round-robin, cooldown, and temporary death
- **Optional IP-per-request** if you prefer fewer 429s over raw throughput
- **Strict username validation** before anything hits the API (`a-z0-9._`, 2–32 chars, no `..`)
- **Buffered disk writes** (flush every N hits, `fsync` on shutdown)
- **Debug mode** — log username + exit IP per request when you need to see what the proxy is doing



## Setup

**Requires Python 3.11+** (`tomllib` is in the standard library).

```bash
git clone https://github.com/vinny/discord-username-checker.git
cd discord-username-checker

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```



### 1. Proxy credentials

Open [`config.toml`](config.toml) and fill in your residential gateway:

```toml
[gateway]
enabled = true
host = "gw.your-provider.com"
port = 8080
user = "your-username"
password = "your-password"
```

Do not commit real credentials.

### 2. Usernames to check

Edit `[usernames.txt](usernames.txt)` — one name per line, `#` for comments. Invalid names are skipped locally and **never** sent to Discord.

To use another list, change the path:

```toml
[files]
usernames = "usernames.txt"
```



### 3. Gateway or proxy list

**Gateway (default)** — `gateway.enabled = true` in `config.toml`. Credentials are the `host` / `port` / `user` / `password` fields in that same file.

**Static list** — set `enabled = false`, then put one proxy per line in `[proxies.txt](proxies.txt)`:

```text
host:port
user:pass@host:port
host:port:user:pass
http://user:pass@host:port
```



### 4. Run

```bash
python checker.py
```

Stop with `Ctrl+C`. Progress is already on disk. Start again to continue.

```text
available.txt   # not taken
taken.txt       # already claimed
errors.txt      # abandoned after max_retries — retried on the next run
```



## How it works

```
usernames.txt ──► validate ──► skip if already in available/taken
                                      │
                                      ▼
                               asyncio queue
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
                 worker            worker            worker
                    │                 │                 │
                    └────────► acquire live exit IP ◄───┘
                                      │
                                      ▼
              POST /api/v9/unique-username/username-attempt-unauthed
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
                 taken            available            429 / net
                    │                 │                 │
                    ▼                 ▼                 ▼
               taken.txt        available.txt     drop IP, retry name
```

On HTTP 200 the JSON field `taken` is a boolean. Anything else is treated as a retryable miss, not a false “available”.

## Proxy modes

Set these in `config.toml` under `[gateway]`.


| Mode                       | When to use                    | What happens on 429                                                   |
| -------------------------- | ------------------------------ | --------------------------------------------------------------------- |
| gateway (`enabled = true`) | Residential gateway, high RPS  | That session is replaced. Other slots keep their IP.                  |
| list (`enabled = false`)   | You already have `proxies.txt` | That line cools down / goes dead. The rest of the pool keeps working. |


```toml
[gateway]
enabled = true
unique_session_per_request = false   # true = new IP every request (fewer 429s, less RPS)
sessions = 400                       # parallel sessions ≈ max_concurrent
```



## Configuration

**Performance**


| Key                                   | Role                                      |
| ------------------------------------- | ----------------------------------------- |
| `max_concurrent`                      | In-flight HTTP requests                   |
| `workers`                             | Queue consumers (a bit above concurrency) |
| `request_timeout` / `connect_timeout` | Fail fast on a dead tunnel                |
| `max_retries`                         | Per-username attempts before `errors.txt` |
| `flush_every`                         | Disk flush interval                       |


**Rate limits & Cloudflare**


| Key                                   | Role                                        |
| ------------------------------------- | ------------------------------------------- |
| `low_remaining_threshold`             | Drop an IP when Discord remaining hits this |
| `max_inflight_per_ip`                 | Usually `1` — one request per exit IP       |
| `huge_retry_after`                    | Treat a giant Retry-After as a burned IP    |
| `cloudflare.window_seconds` / `limit` | Stay under CF’s invalid-request budget      |


Turn on per-request logs when you are debugging proxies — it **will** tank RPS:

```toml
[debug]
enabled = true
show_exit_ip = true
```



## Project layout

```text
.
├── checker.py          # the whole checker
├── config.toml         # settings + gateway credentials
├── proxies.txt         # used when gateway.enabled = false
├── usernames.txt       # names to check
├── requirements.txt
└── assets/
    ├── logo.png
    └── preview.svg
```



## Requirements

```text
aiohttp>=3.9.0
rich>=13.7.0
```

That’s it. No Discord bot, no browser, no extra services.

## Disclaimer

This tool talks to Discord’s public unique-username endpoint. **Automated traffic can violate [Discord’s Terms of Service](https://discord.com/terms).** Use it on lists you have a reason to check, respect rate limits, and keep proxy credentials private.

You are responsible for how you run it. The authors are not affiliated with Discord.

## License

Released under the [MIT License](LICENSE).

---

If this saved you a night of babysitting 429s, a star helps the next person find it.