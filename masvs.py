#!/usr/bin/env python3
"""
masvs.py — map this toolkit's capabilities onto the OWASP MASVS v2 controls and
MASTG test areas, so an assessment reads as coverage of a recognised standard
instead of an ad-hoc pile of commands.

`ios checklist` prints the assessment checklist: each control, the verb that
tests it, and what a pass/fail looks like. report.py reuses CONTROLS to tag each
finding with its MASVS id.
"""

# One row per control we can actually exercise with this toolkit.
# (id, title, the `ios` verb that tests it, what you are checking)
CONTROLS = [
    ("MASVS-STORAGE-1", "No sensitive data in app-private storage in the clear",
     "explore / dump", "Keychain items, plists, and DBs pulled at runtime are not plaintext secrets"),
    ("MASVS-STORAGE-2", "No sensitive data leaked to logs / IPC / backups",
     "trace", "Method tracing shows no tokens written to NSLog / pasteboard / shared containers"),
    ("MASVS-CRYPTO-1", "Sound key management, no hardcoded keys",
     "crypto", "crypto-monitor shows keys derived, not string-constant; no static key in the binary"),
    ("MASVS-CRYPTO-2", "Proven crypto primitives, correct modes",
     "crypto", "No ECB, no static IV, no home-rolled cipher on the wire"),
    ("MASVS-AUTH-1", "Credentials are not recoverable from the client",
     "secrets", "Captured session yields no reusable long-lived secret beyond the access token"),
    ("MASVS-NETWORK-1", "Encrypted channel, correct TLS",
     "intercept", "All traffic is TLS; no plaintext HTTP endpoint carries app data"),
    ("MASVS-NETWORK-2", "Certificate pinning present and effective",
     "intercept", "Pinning is enforced; interception without the BoringSSL hook fails (that it exists is the finding)"),
    ("MASVS-PLATFORM-1", "Safe use of platform APIs / IPC / WebViews",
     "classify / trace", "No exported URL handler, pasteboard, or WKWebView bridge exposes app internals"),
    ("MASVS-CODE-1", "App is built with secure compiler settings",
     "protections", "PIE, stack canaries, and ARC are all on"),
    ("MASVS-CODE-4", "Debug symbols and debug code are removed",
     "protections", "Binary is not debuggable (get-task-allow off) and ships no debug entitlement"),
    ("MASVS-RESILIENCE-1", "App detects a jailbroken/rooted device",
     "explore", "Jailbreak detection is present (that we bypass it is the finding)"),
    ("MASVS-RESILIENCE-2", "App resists dynamic instrumentation / hooking",
     "explore / dump", "Frida/Objection attach is resisted (anti-debug, anti-hook)"),
    ("MASVS-RESILIENCE-3", "App resists reverse engineering of its code",
     "classify / decompile", "Native, no near-source runtime, obfuscation present"),
    ("MASVS-RESILIENCE-4", "App detects tampering / repackaging",
     "intercept", "Integrity check catches a modified binary or an installed CA"),
]

# Which severity a FAILED control usually carries in a mobile report.
# A missing resilience control is lower stakes than a leaked credential.
DEFAULT_SEVERITY = {
    "MASVS-STORAGE": "High",
    "MASVS-CRYPTO": "High",
    "MASVS-AUTH": "Critical",
    "MASVS-NETWORK": "High",
    "MASVS-PLATFORM": "Medium",
    "MASVS-CODE": "Low",
    "MASVS-RESILIENCE": "Medium",
}


def family(control_id):
    return control_id.rsplit("-", 1)[0]


def severity_for(control_id):
    return DEFAULT_SEVERITY.get(family(control_id), "Info")


def checklist():
    print("OWASP MASVS v2 — assessment checklist for this toolkit\n")
    width = max(len(c[0]) for c in CONTROLS)
    fam = None
    for cid, title, verb, checking in CONTROLS:
        f = family(cid)
        if f != fam:
            fam = f
            print(f"\n{f}")
        print(f"  {cid:<{width}}  [ios {verb}]")
        print(f"  {'':<{width}}  {title}")
        print(f"  {'':<{width}}  check: {checking}")
    print("\nControls this toolkit does not cover (do them by hand or with MobSF):")
    print("  MASVS-STORAGE backups/iCloud, MASVS-PRIVACY-*, server-side auth logic.")


if __name__ == "__main__":
    checklist()
