#!/usr/bin/env python3
"""
report.py — turn the artefacts of an assessment into a MASVS-mapped Markdown
report. This is the deliverable step: `classify`, `protections`, and a captured
`secrets` run each answer part of the standard, and this stitches them into the
document a client actually reads, with every finding tagged to its MASVS control
and a severity.

Usage:
    report.py --target "DVIA-v2" [--app PATH] [--binary PATH] \
              [--flows workspace/mitm/last.mitm] [--out workspace/report.md]

Nothing here invents findings: a section appears only when you supply its input,
otherwise it is marked "not assessed" so the gaps are visible.
"""
import argparse
import datetime
import os
import subprocess
import sys

import masvs

ROOT = os.path.dirname(os.path.abspath(__file__))


def h(level, text):
    return f"{'#' * level} {text}\n"


def protections_section(binary):
    import protections
    r = protections.analyze(binary)
    if r.errors:
        return f"Could not parse `{os.path.basename(binary)}`: {'; '.join(r.errors)}\n", []
    lines = ["| Check | Result | Detail | MASVS |", "|---|---|---|---|"]
    findings = []
    for label, ok, detail, mid in r.rows:
        lines.append(f"| {label} | {'PASS' if ok else 'FAIL'} | {detail} | {mid} |")
        if not ok and mid.startswith("MASVS"):
            findings.append((mid, masvs.severity_for(mid), f"{label}: {detail}"))
    note = ""
    if r.encrypted:
        note = "\n> Binary is still FairPlay-encrypted; decrypt with `ios pull` before trusting the byte-level checks.\n"
    return "\n".join(lines) + "\n" + note, findings


def secrets_section(flows):
    """Run the existing extractor and embed its output; never parse secrets here."""
    tool = os.path.join(ROOT, "extract-secrets.py")
    py = os.path.join(ROOT, ".venv/bin/python")
    py = py if os.path.exists(py) else sys.executable
    try:
        out = subprocess.run([py, tool, flows], capture_output=True, text=True, timeout=120)
        body = (out.stdout or "").strip() or "(no secrets extracted)"
        return f"```\n{body}\n```\n"
    except Exception as e:
        return f"Could not run extract-secrets on `{flows}`: {e}\n"


def build(args):
    today = datetime.date.today().isoformat()
    out = []
    out.append(h(1, f"iOS App Security Assessment — {args.target}"))
    out.append(f"_Date:_ {today}  \n_Method:_ MASVS v2 / MASTG, using ios-app-security-toolkit  \n"
               "_Scope:_ authorized testing against a jailbroken test device and an app in scope.\n")

    findings = []

    out.append(h(2, "1. Build & recoverability"))
    if args.app:
        import classify
        s = classify.summarize(args.app)
        if s.get("error"):
            out.append(f"{s['error']}\n")
        else:
            out.append(f"- **Framework:** {s['framework']}\n"
                       f"- **Code recoverability:** {s['recoverability']}\n"
                       f"- **Route:** {s['tool']}\n")
            if s["native"] is False:
                findings.append(("MASVS-RESILIENCE-3", "Medium",
                                 f"Near-source recoverable ({s['framework']}); no anti-RE hardening"))
    else:
        out.append("_Not assessed (pass `--app`)._\n")

    out.append(h(2, "2. Binary protections (MASVS-CODE)"))
    if args.binary:
        section, f2 = protections_section(args.binary)
        out.append(section)
        findings += f2
    else:
        out.append("_Not assessed (pass `--binary`)._\n")

    out.append(h(2, "3. Data in transit (MASVS-NETWORK / MASVS-AUTH)"))
    if args.flows:
        out.append(secrets_section(args.flows))
    else:
        out.append("_Not assessed (pass `--flows` a captured .mitm)._\n")

    out.append(h(2, "4. Findings"))
    if findings:
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda f: order.get(f[1], 9))
        out.append("| # | Severity | MASVS | Finding |\n|---|---|---|---|")
        for i, (mid, sev, desc) in enumerate(findings, 1):
            out.append(f"| {i} | {sev} | {mid} | {desc} |")
        out.append("")
    else:
        out.append("_No automated findings. Complete the manual controls below._\n")

    out.append(h(2, "5. MASVS coverage"))
    out.append("| Control | Verb | Status |\n|---|---|---|")
    failed_ids = {f[0] for f in findings}
    assessed = set()
    if args.binary:
        assessed |= {"MASVS-CODE-1", "MASVS-CODE-4"}
    if args.app:
        assessed |= {"MASVS-RESILIENCE-3"}
    for cid, title, verb, _ in masvs.CONTROLS:
        if cid in failed_ids:
            status = "FAIL"
        elif cid in assessed:
            status = "PASS"
        else:
            status = "manual"
        out.append(f"| {cid} | ios {verb} | {status} |")
    out.append("")

    return "\n".join(out)


def main(argv):
    ap = argparse.ArgumentParser(description="Assemble a MASVS-mapped Markdown report.")
    ap.add_argument("--target", required=True, help="app / engagement name")
    ap.add_argument("--app", help="path to the .app or unzipped IPA (runs classify)")
    ap.add_argument("--binary", help="path to the main Mach-O (runs protections)")
    ap.add_argument("--flows", help="captured mitmproxy flow file (runs secrets)")
    ap.add_argument("--out", help="write here instead of stdout")
    args = ap.parse_args(argv)

    md = build(args)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as fh:
            fh.write(md)
        print(f"-> {args.out}")
    else:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
