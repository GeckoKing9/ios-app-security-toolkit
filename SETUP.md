# Setup

The workstation-side driver is in this repo. The heavy engines and the
device-side packages are fetched separately (they're large, and several carry
their own licenses).

## 0. Requirements
- A jailbroken iOS **test device** with `frida-server` running in network mode.
- A Linux/macOS workstation with Python 3, Node, Docker, an SSH client,
  `sshpass`, and a JDK (for Ghidra).

## 1. Credentials
Create a git-ignored creds file at `~/.ios-pentest-creds.env` (chmod 600):
```
DEVICE_IP=<test-device-lan-ip>
DEVICE_SSH_USER=mobile
DEVICE_SSH_PASS="<device-ssh-password>"
FRIDA_HOST=<test-device-lan-ip>:27042
```
Point `bin/ios` at a different path by exporting `IOS_CREDS=/path/to/file`.
Add `bin/` to your `PATH` (or call `./bin/ios`).

## 2. Python venv
```
python3 -m venv .venv
.venv/bin/pip install frida-tools objection mitmproxy paramiko scp "setuptools<81" hermes-dec
```

## 3. Node (frida-compile + ObjC bridge, for the ObjC Frida scripts)
```
npm install frida-compile frida-objc-bridge
./frida-scripts/build.sh          # compiles frida-scripts/src/*.js -> frida-scripts/*.js
```

## 4. Vendored engines (into vendor/ and bin/)
- **Ghidra 12.x** → symlink to `vendor/ghidra`, plus a JDK 21
- **PyGhidra**: install the wheels shipped inside your Ghidra
  (`Ghidra/Features/PyGhidra/pypkg/dist/*.whl`) into `.venv`
- **ipsw** ([blacktop](https://github.com/blacktop/ipsw)) release → `bin/ipsw`
- **.NET** (`dotnet-install.sh --channel 8.0`) → `vendor/dotnet`
- **ilspycmd**: `dotnet tool install ilspycmd --tool-path vendor/dotnet-tools`
- **Il2CppDumper** ([Perfare](https://github.com/Perfare/Il2CppDumper)) → `vendor/Il2CppDumper`
- **MobSF**: `docker pull opensecurity/mobile-security-framework-mobsf`

## 5. Third-party clones
```
git clone https://github.com/Ch0pin/medusa.git
git clone https://github.com/AloneMonkey/frida-ios-dump.git dump
```

## 6. HTTPS interception scripts (AGPL — fetched, not vendored)
`ios intercept` drives HTTP Toolkit's BoringSSL unpinning scripts. They are
AGPL-3.0 and intentionally **not** included in this MIT repo. Fetch and adapt:
```
git clone https://github.com/httptoolkit/frida-interception-and-unpinning interception
```
Then in `interception/config.js`:
1. Run `.venv/bin/mitmdump` once (Ctrl-C) so mitmproxy generates its CA.
2. Set `CERT_PEM` to `~/.mitmproxy/mitmproxy-ca-cert.pem`, `PROXY_PORT = 8080`,
   `PROXY_SUPPORTS_SOCKS5 = false`, `BLOCK_HTTP3 = true`.
3. On iOS 16, resolve `fcntl`/`send`/`recv`/`connect` globally in
   `native-connect-hook.js` (they live in `libsystem_kernel.dylib`).

## Device-side packages (via Sileo/apt on the test device)
`frida-server`, Filza, NewTerm, Choicy, `radare2` (+ r2ghidra), `ldid`, `nmap`,
`tcpdump`, `netcat`, `socat`, `python3`.
