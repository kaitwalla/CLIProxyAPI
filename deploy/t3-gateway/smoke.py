#!/usr/bin/env python3
"""Run against staging only; --live explicitly permits one billable API request."""
import argparse
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--base", required=True, help="Private gateway origin, without /v1")
parser.add_argument("--model", required=True)
parser.add_argument("--live", action="store_true")
args = parser.parse_args()
base = args.base.rstrip("/")
parsed = urlparse(base)
if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
    parser.error("base must be an origin")
if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")):
    parser.error("use HTTPS or explicit loopback for staging")
key = os.environ["T3_GATEWAY_CLIENT_KEY"]
monitor = os.environ["T3_GATEWAY_MONITOR_KEY"]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def request(path, auth, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=body,
        headers={"Authorization": "Bearer " + auth, "Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=120) as res:
            return res.status, res.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        e.close()
        return e.code, b""

def expect(path, auth, status, payload=None):
    actual, body = request(path, auth, payload)
    if actual != status:
        raise SystemExit(f"{path}: expected {status}, got {actual}")
    print(f"PASS {path}: {actual}")
    return body

payload = {"model": args.model, "input": "Reply with OK.", "max_output_tokens": 128}
expect("/v1/models", "invalid-key", 401)
models = json.loads(expect("/v1/models", key, 200))
if args.model not in [entry["id"] for entry in models["data"]]:
    raise SystemExit("configured model missing")
expect("/usage", key, 401)
expect("/usage", monitor, 200)
expect("/v0/management/config", key, 404)
expect("/v1/responses", monitor, 401, payload)
expect("/v1/responses", key, 403, dict(payload, model="invalid-test-model"))
expect("/v1/responses", key, 403, dict(payload, background=True))
expect("/v1/responses/compact", key, 404, payload)
if args.live:
    data = json.loads(expect("/v1/responses", key, 200, payload))
    usage = data.get("usage")
    if not usage or not isinstance(usage.get("output_tokens"), int):
        raise SystemExit("No authoritative output usage in response")
    if not 0 <= usage["output_tokens"] <= payload["max_output_tokens"]:
        raise SystemExit("Provider output cap violated")
    print("PASS reported output cap")
    expect("/usage", monitor, 200)
else:
    print("No inference requested. Use --live only with an approved staging API key.")
