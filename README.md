<div align="center">

# headerpwn v2

<img src="static/banner.png" alt="headerpwn v2" width="760">

**HTTP header fuzzer & bug-class payload scanner**

[![Version](https://img.shields.io/badge/version-v2.0.0-2ea44f?style=for-the-badge)](https://github.com/Bernic777/headerpwn-v2/releases)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-6e40c9?style=for-the-badge)]()
[![Fork](https://img.shields.io/badge/fork-Bernic777%2Fheaderpwn--v2-181717?style=for-the-badge&logo=github)](https://github.com/Bernic777/headerpwn-v2)

**Maintained by [Bernic Yesnat (@Bernic777)](https://github.com/Bernic777)**

Based on the original [headerpwn](https://github.com/devanshbatham/headerpwn) by [@devanshbatham](https://github.com/devanshbatham)

</div>

---

## Table of Contents

- [Features](#features)
- [What's New in v2](#whats-new-in-v2)
- [Install](#install)
- [Usage](#usage)
  - [HTTP Methods](#http-methods)
  - [Bug-Class Collections](#bug-class-collections)
  - [OOB Payloads](#oob-payloads-collabplz)
  - [Whitelist Bypass](#whitelist-bypass-googlecom)
  - [Fingerprints](#fingerprints)
  - [Raw Requests (Burp Repeater)](#raw-requests-burp-repeater)
  - [Output](#output)
- [Flags](#flags)
- [Proxying Through Burp Suite](#proxying-requests-through-burp-suite)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

## Features

- **Bug-class wordlists** — LFI, RCE, XXE, SSRF, SSTI, and open redirect, packed with real-world header payloads.
- **Nuclei-style fingerprinting** — response bodies are matched against regex patterns and hits are highlighted as `[MATCH: ...]`.
- **Any HTTP method** — `-m POST`, comma-separated lists, `-ma` for all common methods, or custom verbs like `PURGE`.
- **Raw request replay** — drop a full request copied from Burp Repeater with `-r`, including HTTP/2 request lines and bodies.
- **OOB ready** — blind payloads use `$collabplz`, auto-replaced with a Burp Collaborator domain; use `-oob` outside Burp.
- **Whitelist bypass payloads** — SSRF/redirect collections assume `google.com` is the trusted domain and include bypass variants.
- **Low-noise output** — deduplicated by status + content length, unique status codes highlighted, fingerprint hits sorted to the top.
- **Burp-friendly** — built-in proxy support, TLS verification toggle, timeouts, and a configurable concurrency limit.
- **Config-driven** — wordlists and fingerprints live in `~/.config/headerpwn/` and can be edited freely.

## What's New in v2

| Area | v1 | v2 |
| --- | --- | --- |
| HTTP methods | GET only | `-m`, `-ma`, comma lists, custom verbs |
| Request source | URL only | URL or full raw request (`-r`) |
| Payloads | generic `headers.txt` | bug-class collections (`-lfi`, `-rce`, `-xxe`, `-ssrf`, `-ssti`, `-redirect`) |
| Detection | status + length | nuclei-style body fingerprints with `[MATCH: ...]` |
| Output | streaming duplicates | deduplicated summary, unique status highlighting |
| Redirects | followed | **not followed** — `3xx` stays visible |
| Blind testing | — | `$collabplz` / `-oob` OOB integration |
| Configuration | hardcoded | `~/.config/headerpwn/{wordlists,fingerprints}` |

## Install

**Go install (recommended):**

```sh
go install github.com/Bernic777/headerpwn-v2@v2.0.0
```

**Build from source:**

```sh
git clone https://github.com/Bernic777/headerpwn-v2.git
cd headerpwn-v2
go build -trimpath -ldflags="-s -w" -o headerpwn .
sudo install -m 0755 headerpwn /usr/local/bin/headerpwn
```

## Usage

headerpwn lets you test how a server responds to different HTTP headers. Point it at a target and provide a list of headers to fuzz:

```sh
headerpwn -url https://example.com -headers my_headers.txt
```

Header file format — one header per line:

```http
Proxy-Authenticate: foobar
Proxy-Authentication-Required: foobar
Proxy-Authorization: foobar
Proxy-Connection: foobar
Proxy-Host: foobar
Proxy-Http: foobar
```

Or replay a complete request captured from Burp Repeater:

```sh
headerpwn -r raw.txt -headers my_headers.txt
```

## HTTP Methods

Use `-m` to choose the method (or a comma-separated list), and `-ma` to test all common methods at once.

```sh
# Single method
headerpwn -url https://example.com -headers my_headers.txt -m POST

# Several methods
headerpwn -url https://example.com -headers my_headers.txt -m GET,POST,PUT,PATCH,DELETE

# Every common method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE
headerpwn -url https://example.com -headers my_headers.txt -ma
headerpwn -url https://example.com -headers my_headers.txt -m ALL

# Custom / WebDAV methods are accepted too
headerpwn -url https://example.com -headers my_headers.txt -m PROPFIND
headerpwn -url https://example.com -headers my_headers.txt -m PURGE
```

Every header from the headers file is tested once per selected method, so `-ma` with 100 headers sends 800 requests.

## Bug-Class Collections

Ready-made header + payload collections per bug class are stored in the app's config directory (`~/.config/headerpwn/`, or `$XDG_CONFIG_HOME/headerpwn`). They are created automatically on first run and can be edited freely:

```
~/.config/headerpwn/
├── wordlists/            # headers + payloads, one per line
│   ├── lfi.txt
│   ├── rce.txt
│   ├── xxe.txt
│   ├── ssrf.txt
│   ├── ssti.txt
│   └── redirect.txt
└── fingerprints/         # nuclei-style regexes, one per line: "name: regex"
    ├── lfi.txt
    ├── rce.txt
    ├── xxe.txt
    ├── ssrf.txt
    ├── ssti.txt
    └── redirect.txt
```

Select a collection with its flag (they combine):

```sh
headerpwn -url https://example.com -lfi
headerpwn -url https://example.com -rce
headerpwn -url https://example.com -ssrf
headerpwn -url https://example.com -ssti
headerpwn -url https://example.com -xxe
headerpwn -url https://example.com -redirect

# Combine classes, and merge with your own headers file
headerpwn -url https://example.com -lfi -ssrf -headers my_headers.txt

# List the collections and their payload/pattern counts
headerpwn -list
```

| Flag | Payloads | Fingerprints | Focus |
| --- | --- | --- | --- |
| `-lfi` | 28 | 8 | path traversal, wrappers, localization includes |
| `-rce` | 22 | 6 | command separators, ShellShock, log4shell (`$collabplz`) |
| `-xxe` | 12 | 7 | in-band `file://` and blind `$collabplz` entities |
| `-ssrf` | 34 | 9 | OOB callbacks, cloud metadata, `google.com` whitelist bypass |
| `-ssti` | 12 | 6 | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` probes |
| `-redirect` | 12 | — | host/callback headers, `google.com` as allowed domain |

### OOB Payloads (`$collabplz`)

Blind payloads use the `$collabplz` marker. In Burp Suite it is automatically replaced with a Collaborator domain as the OOB server — just copy the request through Burp and it works. Outside Burp, swap the marker with your own OOB domain:

```sh
headerpwn -url https://example.com -ssrf -oob abc123.oast.pro
```

A note is printed when payloads contain `$collabplz` and `-oob` is not set.

### Whitelist Bypass (`google.com`)

The SSRF and redirect collections assume `google.com` is the whitelisted/trusted domain, so they include bypass payloads that abuse it: userinfo tricks (`http://google.com@169.254.169.254/`), decimal/hex/octal IP forms, protocol-relative URLs, `nip.io`-style subdomains, and plain `google.com` baselines.

### Fingerprints

When a bug-class flag is used, response bodies (capped at 1 MB) are matched against the regexes in `fingerprints/<class>.txt` — nuclei-style patterns such as `root:x:0:0:` (LFI/XXE), `uid=\d+\([^)]*\)` (RCE), `ami-id` / `instance-id` (SSRF), `7777777` (SSTI). Hits are shown as `[MATCH: name]`, sorted to the top, and summarized:

```
[GET] [200] [CL: 67] [X-Original-URL: /etc/passwd] [https://example.com] [MATCH: etc-passwd, daemon-passwd]
[+] Fingerprint matches: 25 request(s) hit a fingerprint (rows marked [MATCH: ...])
```

Edit the fingerprint files to add your own patterns; delete a file to restore the default on the next run. Redirect detection is status-based (`3xx`) — redirects are never followed, so a `302` appears directly in the output.

## Raw Requests (Burp Repeater)

Copy the request from Burp Repeater (**right click → Copy to file**, or paste it into a file) and pass it with `-r`. The request line, headers, and body are replayed exactly, and every fuzz header is injected into a fresh copy of that request.

```sh
# Replay the raw request (method, path, query, headers, and body come from the file)
headerpwn -r raw.txt -headers my_headers.txt

# Replay the raw request once, without fuzzing any header
headerpwn -r raw.txt

# Override the method from the raw request
headerpwn -r raw.txt -headers my_headers.txt -m PUT

# Replay a request captured for one host against another destination.
# -url replaces the destination (including the Host header).
headerpwn -r raw.txt -headers my_headers.txt -url https://staging.example.com

# Plain HTTP target with a relative request target
headerpwn -r raw.txt -headers my_headers.txt -scheme http
```

A complete example is included in [`raw.txt`](raw.txt):

```http
POST /api/v1/login?lang=en HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 54
Origin: https://example.com
Referer: https://example.com/login
Cookie: session=REPLACE_WITH_YOUR_SESSION
Authorization: Bearer REPLACE_WITH_YOUR_TOKEN
X-Requested-With: XMLHttpRequest

{"username":"test","password":"test","remember":false}
```

Notes:

- The file must contain the request line, all headers, one empty line, then the body. `HTTP/1.1` and `HTTP/2` request lines are both accepted.
- The body is sent byte-for-byte. `Content-Length` from the raw request is recalculated from the body by the HTTP client, and hop-by-hop headers such as `Connection`, `Transfer-Encoding`, and `Proxy-Connection` are managed by the transport.
- When `-url` is used together with `-r`, it overrides the scheme, host, path, and query from the raw request. The raw `Host` header is not preserved; fuzz it explicitly with a `Host: ...` line in the headers file if needed.
- With a relative request target (e.g. `/api/v1/login`), the destination is built from the raw `Host` header. `-scheme auto` (the default) picks `https`, except for port `80`; use `-scheme http` or `-scheme https` to force it.
- `-r` is limited to 5 MB files, and `-headers` still accepts one header per line.
- Only a single header is fuzzed per request (the rest are replayed as-is).

## Output

Results are collected and printed after all requests finish. By default, identical responses are collapsed into one line per unique **status code + Content-Length** combination, so a run that produces hundreds of `[200] [CL: 1234]` lines shows just one representative.

- Results are sorted by fingerprint match first, then status code, then content length.
- Status codes that occurred only once across the whole run are highlighted (black on yellow), so outliers such as a single `403` or `500` stand out.
- Status classes are colored: 2xx green, 3xx yellow, 4xx red, 5xx white on red.
- Fingerprint hits show `[MATCH: ...]` and are never hidden by deduplication.
- A summary at the end shows the number of requests, displayed results, every status code, and the fingerprint hit count.
- Use `-all` to disable deduplication and print every individual result.

```sh
# Deduplicated summary (default)
headerpwn -url https://example.com -headers my_headers.txt -ma

# Every request result
headerpwn -url https://example.com -headers my_headers.txt -ma -all
```

## Flags

| Flag | Description |
| --- | --- |
| `-url` | Target URL (required unless `-r` is used) |
| `-headers` | File with headers to test, one per line (optional with `-r`) |
| `-m` | HTTP method or comma-separated list: `POST`, `GET,POST,PUT`, `ALL` |
| `-ma` | Test all common methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE |
| `-r` | Path to a raw HTTP request file (Burp Repeater format) |
| `-scheme` | Scheme for `-r` with a relative target: `auto` (default), `http`, `https` |
| `-proxy` | Proxy server: `127.0.0.1:8080` or `http://127.0.0.1:8080` |
| `-k` | Skip TLS certificate verification |
| `-timeout` | Per-request timeout (default `15s`) |
| `-c` | Number of concurrent requests (default `10`) |
| `-nb` | Disable the cachebuster query parameter |
| `-all` | Show every result (disable status + content length deduplication) |
| `-lfi` | Fuzz with the LFI wordlist + fingerprints |
| `-rce` | Fuzz with the RCE wordlist + fingerprints (log4shell `$collabplz` OOB) |
| `-ssrf` | Fuzz with the SSRF wordlist + fingerprints (`$collabplz` OOB, `google.com` whitelist) |
| `-ssti` | Fuzz with the SSTI wordlist + fingerprints |
| `-xxe` | Fuzz with the XXE wordlist + fingerprints (`$collabplz` OOB) |
| `-redirect` | Fuzz with the open-redirect wordlist (`google.com` whitelisted) |
| `-oob` | Replace `$collabplz` with this OOB domain (Burp auto-replaces it) |
| `-list` | List bug-class wordlists/fingerprints and exit |
| `-v` | Print per-request errors |
| `-q` | Suppress the banner |

## Proxying requests through Burp Suite

Follow these steps to proxy requests through Burp Suite:

- Export Burp's Certificate:

    - In Burp Suite, go to the "Proxy" tab.
    - Under the "Proxy Listeners" section, select the listener that is configured for `127.0.0.1:8080`.
    - Click on the "Import/Export CA Certificate" button.
    - In the certificate window, click "Export Certificate" and save the certificate file (e.g., `burp.der`).

- Install Burp's Certificate:

    - Install the exported certificate as a trusted certificate on your system. How you do this depends on your operating system.
    - On Windows, you can double-click the `.cer` file and follow the prompts to install it in the "Trusted Root Certification Authorities" store.
    - On macOS, you can double-click the `.cer` file and add it to the "Keychain Access" application in the "System" keychain.
    - On Linux, you might need to copy the certificate to a trusted certificate location and configure your system to trust it.

You should be all set:

```sh
headerpwn -url https://example.com -headers my_headers.txt -proxy 127.0.0.1:8080
```

## Credits

- **v2 development & maintenance:** [Bernic Yesnat (@Bernic777)](https://github.com/Bernic777)
- **Original headerpwn:** [Devansh Batham (@devanshbatham)](https://github.com/devanshbatham)
- **`headers.txt` sources:** compiled from various sources, including the [SecLists project](https://github.com/danielmiessler/SecLists).
- **Fingerprint patterns:** inspired by [Nuclei](https://github.com/projectdiscovery/nuclei) fuzzing templates.

## Disclaimer

headerpwn is intended for authorized security testing and research only. Use it only against systems you own or have explicit written permission to test. The author is not responsible for misuse or damage caused by this tool.
