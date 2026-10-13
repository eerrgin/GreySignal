# GreySignal

**Passive web security header auditor** for systems you own or are authorized to assess.

GreySignal makes a single ordinary HTTP `GET` request and reports common browser security headers. It does not exploit vulnerabilities, crawl pages, brute-force, scan ports, or attempt authentication.

## Features

- Checks a small set of defensive HTTP response headers
- Reports missing, present, and noteworthy header values
- Supports JSON output for automation
- Uses conservative timeouts and makes only one request per run
- Includes a clear authorization boundary

## Requirements

- Python 3.10+
- `requests`

## Install

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

Only test a site you own or have explicit permission to assess.

```bash
python greysignal.py https://example.com
python greysignal.py https://example.com --json report.json
```

The tool does not follow links or perform additional endpoint discovery. Redirects are disabled so the request remains limited to the URL you supplied.

## Checks

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`

A missing header is a review prompt, not proof of a vulnerability. Header requirements depend on the application and deployment.

## Project status

This is a small defensive learning project, not a full penetration-testing suite. Contributions that improve tests, documentation, and safe reporting are welcome.

## License

MIT. See [LICENSE](LICENSE).
