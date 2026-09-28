# iOS App Security Toolkit

A single command-line driver that covers the whole iOS application security
assessment lifecycle — recon, static reverse-engineering across **every** app
runtime, dynamic instrumentation with Frida, and TLS interception that defeats
certificate pinning at the BoringSSL layer.

It wraps a pile of specialist tools (Frida, Objection, mitmproxy, Ghidra, ipsw,
ILSpy, Il2CppDumper, MobSF, radare2) behind one consistent verb-based interface —
`ios <verb> <target>` — so an assessment is a sequence of readable commands
instead of a directory full of half-remembered one-liners.

```
ios apps                    # enumerate installed apps (your targets)
ios pull com.example.app    # decrypt + pull the app off the device
ios classify workspace/…    # what runtime is it, and what code can I recover?
ios decompile <binary>      # Ghidra headless -> readable C pseudocode
ios explore com.example.app # live Objection shell, SSL-unpin + jailbreak-bypass on
ios intercept com.example.app  # decrypt its HTTPS, pinning and all
ios secrets                 # rip JWTs / tokens / API keys out of the capture
```

> **Authorized testing only.** This is a lab toolkit built and used against a
> jailbroken **test device** and apps that are *meant* to be attacked
> (see [Legal & scope](#legal--scope)). It ships no exploits and no target data.

---

## Why it's interesting

Most public "iOS pentest" repos are a wrapper around one tool. The engineering
here is the **breadth behind one interface**, and three parts in particular:

### 1. Pinning bypass at the BoringSSL layer
`ios intercept` defeats certificate pinning *in-process* by hooking BoringSSL —
the layer **all** modern iOS TLS converges on — instead of chasing per-library
pinning logic. That's why it works on hardened apps where classic
`SSL-Kill-Switch`-style tweaks fail (measured: 0/1374 handshakes bypassed by the
old approach on iOS 16). Traffic is then routed through a local mitmproxy over a
reverse SSH tunnel, so **no CA is installed on the device** and both requests and
responses are captured while the app keeps working.

### 2. "Recover the real source, not just pseudocode"
Native Objective-C/Swift only decompiles to C-like pseudocode. Cross-platform
runtimes give you something much closer to original source — *if* you identify the
runtime first. `ios classify` inspects a pulled app and tells you exactly what you
can get back and with which tool:

| Runtime detected | What you recover | Tool routed to |
|---|---|---|
| Unity (Mono) | Near-original C# | ILSpy on `Assembly-CSharp.dll` |
| Unity (IL2CPP) | C# structure | Il2CppDumper (binary + `global-metadata.dat`) |
| Xamarin / .NET MAUI | Near-original C# | ILSpy on the `.dll`s |
| React Native (Hermes) | Hermes bytecode | `hermes-dec` on the `.hbc` |
| React Native (JSC) | Readable JavaScript | beautify `main.jsbundle` |
| Cordova / Ionic | Plain HTML/JS/CSS | just read `www/` |
| Flutter | AOT-compiled Dart | blutter / Ghidra on `libapp.so` |
| Native ObjC/Swift | Pseudocode + live runtime | Ghidra + Frida |

### 3. Dynamic instrumentation that survived the Frida 17 break
Frida 17 removed the global ObjC/Swift bridges, breaking most published scripts.
The scripts in [`frida-scripts/src/`](frida-scripts/src) are written against
`frida-objc-bridge` and compiled with `frida-compile` — a runtime class-dumper, a
live method tracer, a CommonCrypto key/plaintext monitor, and a soft iOS-version
spoofer, all working on current Frida.

### 4. Findings that map to a standard, not a text file
An assessment is only worth what its report is worth. `ios protections` reads a
decrypted Mach-O in **pure Python** — PIE, stack canaries, ARC, the FairPlay
`cryptid`, an embedded code signature, `get-task-allow`, `@rpath` hygiene — with
no `otool` and no macOS, so it runs on any binary `ios pull` brings back.
`ios report` then stitches `classify`, `protections`, and a captured `secrets`
run into one Markdown report where every finding carries its **OWASP MASVS v2**
control and a severity, and `ios checklist` prints those controls beside the verb
that tests each one. Nothing is invented: a section that had no input is marked
*not assessed*, so the gaps stay visible.

---

## Command reference

Run `ios help` for the full list. Grouped:

- **Recon** — `apps`, `ps`, `ssh`
- **Dynamic (Frida)** — `explore`, `spawn`, `attach`, `spoof`, `crypto`, `dump`, `trace`, `repl`, `medusa`, `r2`
- **Static RE** — `pull`, `classify`, `headers`, `decompile`, `ilspy`, `il2cpp`, `hermes`, `protections`, `mobsf`
- **HTTPS interception** — `intercept`, `intercept-all`, `secrets`
- **Reporting** — `checklist`, `report`

## Architecture

```
your workstation                          jailbroken test device (WiFi)
────────────────                          ─────────────────────────────
ios <verb>                                frida-server (network mode)
  ├─ frida / objection ───── remote ────► app process  (hook / trace / dump)
  ├─ mitmproxy ◄── reverse SSH tunnel ──── system HTTP proxy
  │     ▲ BoringSSL hook injected via Frida (pinning defeated in-process)
  ├─ Ghidra / ILSpy / Il2CppDumper …      (static RE, on the workstation)
  └─ frida-ios-dump ──────── SSH ────────► decrypt + pull IPA
```

The heavy engine lives on the workstation; the device just runs `frida-server`
and (optionally) points its Wi-Fi proxy at the tunnel. No USB required for any
operation.

## Setup

Third-party engines (Ghidra, .NET, MobSF, Medusa, frida-ios-dump, and the
AGPL interception scripts) are **not vendored** — [`SETUP.md`](SETUP.md) lists the
exact fetch/build steps and the device-side packages. Connection details live in a
git-ignored creds file; nothing about any real device or app is in this repo.

## Tech stack

Bash · Python 3 · Frida / frida-objc-bridge · Objection · mitmproxy · Ghidra
(PyGhidra) · ipsw · ILSpy · Il2CppDumper · hermes-dec · radare2 · MobSF · Medusa

## Legal & scope

Built for authorized mobile application security assessment and personal
research. Use it **only** against:

- apps you own or are explicitly contracted/authorized to test, or
- deliberately vulnerable training apps — [DVIA-v2](https://github.com/prateek147/DVIA-v2),
  [OWASP iGoat](https://github.com/OWASP/igoat), [OWASP MASTG](https://mas.owasp.org/) crackmes.

Do not use it against third-party production apps or services you are not
authorized to test. You are responsible for staying within the law and any
engagement's rules of engagement.

## License

MIT — see [LICENSE](LICENSE). The interception scripts fetched during setup are
HTTP Toolkit's, under AGPL-3.0, and are **not** included here.
