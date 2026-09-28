#!/usr/bin/env python3
"""
intercept.py — decrypt a target app's HTTPS traffic on a jailbroken iOS test device.

Certificate pinning is defeated *in-process* by hooking BoringSSL — the layer all
modern iOS TLS converges on — so no CA needs to be installed on the device and the
approach works where classic SSL-Kill-Switch tweaks fail. Traffic is then routed
through a local mitmproxy over a reverse SSH tunnel.

Two modes:

  FULL (default) — mitmproxy REGULAR mode + the device's system HTTP proxy.
    Captures BOTH requests AND responses, and the app keeps working normally.
    Requires the device's Wi-Fi proxy set to 127.0.0.1:8080 (one-time, 2 taps) —
    the reverse SSH tunnel carries that to mitmproxy on this machine.

  QUICK (--quick) — hands-off, no proxy tap. Frida redirects traffic itself.
    Captures REQUESTS only and may break the app's networking (responses can't be
    forwarded). Good for a fast look at what an app SENDS (tokens, keys, bodies).

Usage:
  intercept.py <bundleid>            # FULL two-way (set device proxy first)
  intercept.py <bundleid> --quick    # hands-off, requests only
  intercept.py --all                 # FULL, every app launched while running

The BoringSSL/connect hook scripts live in interception/ — they are adapted from
HTTP Toolkit's frida-interception-and-unpinning (AGPL-3.0); see SETUP.md for how
to fetch and configure them. Ctrl-C tears everything down and extracts secrets.
"""
import frida, subprocess, sys, os, time, signal, threading, atexit

ROOT = os.path.dirname(os.path.abspath(__file__))
CREDS = os.environ.get("IOS_CREDS", os.path.expanduser("~/.ios-pentest-creds.env"))
ITC = os.path.join(ROOT, "interception")
PORT = 8080

def cred(key):
    try:
        for line in open(CREDS):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip('"')
    except FileNotFoundError:
        sys.exit("missing creds file: %s  (see SETUP.md)" % CREDS)
    return None

IP = cred("DEVICE_IP")
FRIDA_HOST = cred("FRIDA_HOST")
SSH_PASS = cred("DEVICE_SSH_PASS") or " "
SSH_USER = cred("DEVICE_SSH_USER") or "mobile"

# FULL mode needs only the pinning bypass (system proxy handles routing).
FULL_SCRIPTS  = [os.path.join(ITC, "config.js"), os.path.join(ITC, "native-tls-hook.js")]
# QUICK mode also redirects traffic itself via the connect hooks.
QUICK_SCRIPTS = [os.path.join(ITC, f) for f in
                 ("config.js", "ios-connect-hook.js", "native-tls-hook.js", "native-connect-hook.js")]

procs = []
FLOWS = os.path.join(ROOT, "workspace", "mitm", "last.mitm")
LOG = os.path.join(ROOT, "workspace", "mitm", "intercept.log")

def agent(scripts):
    return "\n".join(open(p).read() for p in scripts)

def start_proxy(mode):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    open(LOG, "w").close()
    args = [os.path.join(ROOT, ".venv/bin/mitmdump"),
            "--listen-host", "127.0.0.1", "--listen-port", str(PORT),
            "--set", "block_global=false", "-w", FLOWS, "--flow-detail", "1"]
    if mode == "quick":
        args += ["--mode", "transparent", "--showhost",
                 "--set", "connection_strategy=lazy"]
    # FULL mode = default regular HTTP proxy (understands CONNECT from the system proxy)
    p = subprocess.Popen(args, stdout=open(LOG, "w"), stderr=subprocess.STDOUT,
                         start_new_session=True)
    procs.append(p)

def start_tunnel():
    p = subprocess.Popen(
        ["sshpass", "-p", SSH_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ExitOnForwardFailure=yes", "-N",
         "-R", f"{PORT}:localhost:{PORT}", f"{SSH_USER}@{IP}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    procs.append(p)

def tail():
    with open(LOG) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3); continue
            line = line.replace("\0", "").rstrip()
            if any(m in line for m in ("GET http", "POST http", "PUT http",
                                       "PATCH http", "DELETE http", "<< ")):
                print("  " + line.split("]")[-1].strip(), flush=True)

_torn = False
def cleanup(*_):
    global _torn
    if _torn: return
    _torn = True
    print("\n[*] tearing down proxy + tunnel...", flush=True)
    for p in procs:
        try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            try: p.kill()
            except Exception: pass
    print(f"[*] capture saved. Pull tokens/keys with:  ios secrets", flush=True)
    os._exit(0)

def main():
    args = [a for a in sys.argv[1:]]
    if not args:
        print("usage: intercept.py <bundleid> [--quick] | --all"); sys.exit(1)
    quick = "--quick" in args
    args = [a for a in args if not a.startswith("--") or a == "--all"]
    target = args[0]
    mode = "quick" if quick else "full"

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    atexit.register(cleanup)

    print(f"[*] starting mitmproxy ({mode}) + reverse tunnel...", flush=True)
    start_proxy(mode); start_tunnel(); time.sleep(4)
    if mode == "full":
        print("[!] FULL mode needs the device's Wi-Fi proxy = 127.0.0.1 : 8080", flush=True)
        print("    (Settings > Wi-Fi > (i) > Configure Proxy > Manual). Turn it OFF when done.\n", flush=True)
    threading.Thread(target=tail, daemon=True).start()

    dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)
    code = agent(QUICK_SCRIPTS if quick else FULL_SCRIPTS)

    if target == "--all":
        print("[*] spawn-gating: EVERY app launched now is intercepted.", flush=True)
        dev.enable_spawn_gating()
        def on_spawn(spawn):
            try:
                s = dev.attach(spawn.pid)
                s.create_script(code).load(); dev.resume(spawn.pid)
                print(f"[+] intercepting {spawn.identifier}", flush=True)
            except Exception as e:
                print(f"[-] {spawn.identifier}: {e}", flush=True)
                try: dev.resume(spawn.pid)
                except Exception: pass
        dev.on("spawn-added", on_spawn)
        for s in dev.enumerate_pending_spawn(): on_spawn(s)
        print("[*] launch apps on the device now.\n", flush=True)
        sys.stdin.read()
    else:
        print(f"[*] spawning {target}...", flush=True)
        pid = dev.spawn([target]); session = dev.attach(pid)
        session.create_script(code).load(); dev.resume(pid)
        print(f"[+] {target} running. Traffic below (Ctrl-C to stop + extract secrets):\n", flush=True)
        while True: time.sleep(1)

if __name__ == "__main__":
    main()
