#!/usr/bin/env python3
"""
extract-secrets.py — read a saved mitmproxy flow file and pull out every
credential a captured session leaked: JWTs (decoded), bearer tokens, API keys,
refresh/access tokens, cookies, and auth-bearing request/response bodies.

This is the "so what" step after an interception run: it turns a raw capture into
a ranked list of the sensitive material an app put on the wire — exactly what a
mobile pentest report needs to evidence "sensitive data in transit" findings.

Usage: extract-secrets.py [flows.mitm]   (defaults to workspace/mitm/last.mitm)
"""
import sys, os, json, base64, re
from mitmproxy import io, http

ROOT = os.path.dirname(os.path.abspath(__file__))
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "workspace/mitm/last.mitm")

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}')
TOKEN_KEYS = ('token', 'auth', 'secret', 'key', 'session', 'bearer', 'password',
              'credential', 'access', 'refresh', 'id_token', 'apikey', 'api_key')
# Common auth-bearing request headers. Add any app-specific custom header
# (e.g. x-<app>-signature) you spot during recon.
AUTH_HEADERS = ('authorization', 'cookie', 'x-api-key', 'x-auth-token',
                'x-access-token', 'x-firebase-appcheck', 'x-signature')

def b64pad(s): return s + '=' * (-len(s) % 4)

def decode_jwt(tok):
    try:
        h, p, _ = tok.split('.')
        payload = json.loads(base64.urlsafe_b64decode(b64pad(p)))
        return payload
    except Exception:
        return None

seen_jwt = {}
seen_headers = {}
interesting_bodies = []
hosts = set()

def scan_text(where, text):
    for m in JWT_RE.findall(text or ''):
        if m not in seen_jwt:
            seen_jwt[m] = (where, decode_jwt(m))

with open(path, 'rb') as f:
    for flow in io.FlowReader(f).stream():
        if not isinstance(flow, http.HTTPFlow):
            continue
        req = flow.request
        hosts.add(req.pretty_host)
        # auth-bearing request headers
        for k, v in req.headers.items():
            lk = k.lower()
            if lk in AUTH_HEADERS:
                seen_headers.setdefault(lk, set()).add(v[:400])
            scan_text(f"req header {k} @ {req.pretty_host}", v)
        # bodies
        try: scan_text(f"req body @ {req.pretty_host}{req.path[:40]}", req.get_text() or '')
        except Exception: pass
        if flow.response:
            try:
                rt = flow.response.get_text() or ''
                scan_text(f"resp @ {req.pretty_host}{req.path[:40]}", rt)
                if any(k in rt.lower() for k in ('access_token', 'refresh_token', 'id_token')):
                    interesting_bodies.append((req.pretty_host + req.path[:60], rt[:600]))
            except Exception: pass

print("=" * 70)
print(f"HOSTS CONTACTED ({len(hosts)}):")
for h in sorted(hosts): print("  ", h)

print("\n" + "=" * 70)
print(f"JWT TOKENS FOUND: {len(seen_jwt)}")
for i, (tok, (where, payload)) in enumerate(seen_jwt.items(), 1):
    print(f"\n[{i}] from: {where}")
    print("   ", tok[:80] + "..." if len(tok) > 80 else tok)
    if payload:
        keep = {k: payload[k] for k in payload if k in
                ('iss','aud','sub','user_id','email','phone_number','exp','iat','name','uid','auth_time')}
        print("    decoded claims:", json.dumps(keep, indent=0)[:500])

print("\n" + "=" * 70)
print("AUTH HEADERS:")
for k, vs in seen_headers.items():
    for v in vs:
        print(f"  {k}: {v}")

print("\n" + "=" * 70)
print(f"TOKEN-BEARING RESPONSE BODIES: {len(interesting_bodies)}")
for host, body in interesting_bodies[:5]:
    print(f"\n  @ {host}")
    print("   ", body[:400].replace('\n', ' '))
