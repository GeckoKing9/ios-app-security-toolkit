#!/usr/bin/env python3
"""
classify.py — detect how an iOS app was built, and report what source/code is
recoverable and with which tool. Point it at a .app bundle or an unzipped IPA dir.

The single most important step before decompiling an iOS app: native ObjC/Swift
gives you only pseudocode, but managed-code / JS frameworks give you near-source.
"""
import sys, os, glob

def find(root, pattern):
    return glob.glob(os.path.join(root, "**", pattern), recursive=True)

def app_dir(path):
    if path.endswith(".app"):
        return path
    hits = glob.glob(os.path.join(path, "**", "*.app"), recursive=True)
    return hits[0] if hits else path

def classify(path):
    app = app_dir(path)
    if not os.path.isdir(app):
        print(f"[!] Not a directory: {app}\n    Unzip the .ipa first (unzip app.ipa -d out/), then point me at out/Payload/")
        return
    print(f"[*] Inspecting: {app}\n")

    checks = []  # (matched, framework, recoverability, tool)

    unity_mono = find(app, "Assembly-CSharp.dll") or find(app, "libmonosgen*.dylib")
    unity_il2cpp = find(app, "global-metadata.dat") or find(app, "UnityFramework")
    if unity_mono:
        checks.append((True, "Unity (Mono)", "HIGH — near-original C#",
                       "ILSpy / dnSpyEx on Assembly-CSharp.dll (like jadx, but for C#)"))
    elif unity_il2cpp:
        checks.append((True, "Unity (IL2CPP)", "MEDIUM — recovered C# structure, not full bodies",
                       "Il2CppDumper (needs the binary + global-metadata.dat)"))

    dotnet = [d for d in find(app, "*.dll") if "Assembly-CSharp" not in d]
    xamarin = find(app, "libxamarin*.dylib") or find(app, "libmonosgen*.dylib")
    if xamarin or (dotnet and not unity_mono):
        checks.append((True, "Xamarin / .NET MAUI", "HIGH — near-original C#",
                       "ILSpy / dnSpyEx on the .dll files (real jadx-equivalent)"))

    hermes = find(app, "libhermes*.dylib") or find(app, "*.hbc")
    jsbundle = find(app, "main.jsbundle") or find(app, "index.*.bundle")
    if hermes:
        checks.append((True, "React Native (Hermes)", "MEDIUM — Hermes bytecode",
                       "hermes-dec / hbctool to disassemble the .hbc bundle"))
    elif jsbundle:
        checks.append((True, "React Native (JSC)", "HIGH — readable JavaScript",
                       "js-beautify the main.jsbundle — often plain JS"))

    flutter = find(app, "Flutter.framework") or find(app, "flutter_assets") or find(app, "libapp.so")
    if flutter:
        checks.append((True, "Flutter", "LOW — native-compiled Dart",
                       "blutter (AOT snapshot parser); otherwise Ghidra on libapp.so"))

    cordova = find(app, "cordova.js") or (find(app, "index.html") and find(app, "www"))
    if cordova:
        checks.append((True, "Cordova / Ionic", "HIGH — plain HTML/JS/CSS",
                       "Just read the www/ directory — it's the whole app"))

    if not checks:
        # native ObjC/Swift
        macho = None
        info = os.path.join(app, "Info.plist")
        exe = os.path.basename(app)[:-4]
        cand = os.path.join(app, exe)
        macho = cand if os.path.exists(cand) else "<main binary in the .app>"
        print("[=] NATIVE app (Objective-C / Swift) — no bytecode to recover.")
        print(f"    Main binary: {macho}\n")
        print("    What you CAN get:")
        print("      1. Class/method/property headers (the code's shape):")
        print("           ios headers <binary>        (ipsw class-dump, Swift-aware)")
        print("      2. Decompiler pseudocode (C-like, readable):")
        print("           ios decompile <binary>      (Ghidra headless)")
        print("      3. Live runtime behaviour (the real jadx-beater for native):")
        print("           ios explore <bundleid>  /  ios dump  /  ios trace")
        return

    print("[+] Cross-platform framework detected — real code is recoverable:\n")
    for _, fw, rec, tool in checks:
        print(f"    Framework:      {fw}")
        print(f"    Recoverability: {rec}")
        print(f"    Best tool:      {tool}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: classify.py <path-to-.app-or-unzipped-IPA>")
        sys.exit(1)
    classify(sys.argv[1])
