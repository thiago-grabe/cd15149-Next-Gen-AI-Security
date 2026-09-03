"""
assert_rubric.py — automated rubric-assertion harness.

Programmatically verifies every rubric line for the Northstar red-team/harden project
and prints a PASS/FAIL matrix. Exits non-zero if any REQUIRED check fails. It re-reads
the captured evidence (results.json, evidence/*.json) rather than trusting prose, so
"the rubric is asserted" is mechanical, not self-reported.

Run from the solution-folder root:  python assert_rubric.py
"""

import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SW = ROOT / "student_work"
REPORTS = SW / "reports"
DEFENSES = SW / "defenses"
ATTACKS = SW / "attacks"
EVIDENCE = ATTACKS / "evidence"

checks = []  # (name, passed:bool, detail:str, required:bool)


def check(name, passed, detail="", required=True):
    checks.append((name, bool(passed), detail, required))


def read(p):
    try:
        return pathlib.Path(p).read_text(encoding="utf-8")
    except OSError:
        return ""


# ---- 1. Deliverable files exist ----
required_files = {
    "owasp_assessment.md": REPORTS / "owasp_assessment.md",
    "security_findings.md": REPORTS / "security_findings.md",
    "ir_playbook.md": REPORTS / "ir_playbook.md",
    "launch_readiness_report.md": REPORTS / "launch_readiness_report.md",
    "northstar_agent_hardened.py": DEFENSES / "northstar_agent_hardened.py",
    "system_prompt_hardened.txt": DEFENSES / "system_prompt_hardened.txt",
    "task_hijack_test.py": ATTACKS / "task_hijack_test.py",
}
for label, path in required_files.items():
    check(f"deliverable exists: {label}", path.exists(), str(path))

# ---- 2. OWASP assessment: >=6 categories with severity + recommendation ----
owasp = read(REPORTS / "owasp_assessment.md")
sev = [v.strip() for v in re.findall(r"\|\s*Severity\s*\|([^|]*)\|", owasp) if v.strip()]
rec = [v.strip() for v in re.findall(r"\|\s*Recommendation\s*\|([^|]*)\|", owasp) if v.strip()]
check("OWASP: >=6 categories have a Severity", len(sev) >= 6, f"{len(sev)} severities filled")
check("OWASP: >=6 categories have a Recommendation", len(rec) >= 6, f"{len(rec)} recommendations filled")

# ---- 3. Security findings: direct(>=2 techniques) + indirect + hijack, no placeholders ----
findings = read(REPORTS / "security_findings.md")
placeholders = [ph for ph in ("[paste", "[document ID", "[list all", "[OWASP ID]") if ph in findings]
check("Findings: no template placeholders remain", not placeholders, f"found: {placeholders}")
tech_kw = [k for k in ("override", "hypothetic", "training", "fictional", "multi-turn", "dan")
           if k in findings.lower()]
check("Findings: >=2 direct-injection techniques documented", len(set(tech_kw)) >= 2, f"keywords: {tech_kw}")
check("Findings: indirect injection names a poisoned doc id",
      bool(re.search(r"malicious-00\d", findings)), "expects malicious-00x id")
check("Findings: task hijack shows query_hr_database", "query_hr_database" in findings)
for f in ("Direct Prompt Injection", "Indirect Prompt Injection", "Agent Task Hijacking"):
    check(f"Findings: section present — {f}", f in findings)

# ---- 4. Hardened system prompt ----
sp = read(DEFENSES / "system_prompt_hardened.txt")
bracket_placeholders = re.findall(r"\[[^\]]{8,}\]", sp)
check("Prompt: no [BRACKETED] placeholder remains", not bracket_placeholders,
      f"{len(bracket_placeholders)} bracket placeholders")
must_not_block = sp[sp.find("MUST NOT"):sp.find("## TOOL USE")] if "MUST NOT" in sp else ""
must_not = len(re.findall(r"^\s*-\s", must_not_block, re.M))
check("Prompt: >=3 explicit MUST NOT constraints", must_not >= 3, f"{must_not} constraint bullets")
check("Prompt: retains {retrieved_context} and {user_input} slots",
      "{retrieved_context}" in sp and "{user_input}" in sp)

# ---- 5. Hardened agent structure ----
sys.path.insert(0, str(DEFENSES))
agent_ok, agent_detail = False, ""
try:
    import northstar_agent_hardened as h
    tp = getattr(h, "TOOL_PERMISSIONS", {})
    hr_absent = all("query_hr_database" not in v for v in tp.values())
    has_syms = all(hasattr(h, s) for s in
                   ("build_messages", "is_suspicious", "DISTANCE_THRESHOLD", "log_interaction",
                    "run_agent_task", "handle_user_message"))
    hardened_prompt = "MUST NOT" in h.SYSTEM_PROMPT and "execute exactly when requested" not in h.SYSTEM_PROMPT
    agent_ok = bool(tp) and hr_absent and has_syms and hardened_prompt
    agent_detail = f"perms={list(tp)}, hr_absent={hr_absent}, syms={has_syms}, hardened_prompt={hardened_prompt}"
except Exception as e:
    agent_detail = f"import error: {e}"
check("Hardened agent: imports + TOOL_PERMISSIONS(no HR) + defenses + hardened prompt", agent_ok, agent_detail)

# ---- 6. IR playbook: 5+ alert rules, log fields, first 30 min ----
ir = read(REPORTS / "ir_playbook.md")
alert_section = ir[ir.find("## Alert Rules"):] if "## Alert Rules" in ir else ""
rows = [r for r in re.findall(r"^\|(.+)\|$", alert_section, re.M)]
data_rows = [r for r in rows if "---" not in r and "Alert Name" not in r
             and "*Example:*" not in r and r.strip().replace("|", "").strip()]
check("IR: >=5 alert rules (excluding header/example)", len(data_rows) >= 5, f"{len(data_rows)} rules")
log_fields = ["Timestamp", "Session", "user input", "document IDs", "Commands executed",
              "Tools called", "Response time"]
present = [lf for lf in log_fields if lf.lower() in ir.lower()]
check("IR: required log fields present", len(present) >= 6, f"{len(present)}/7 fields")
check("IR: first-30-minutes procedure present", "First 30 Minutes" in ir or "first 30 minutes" in ir.lower())

# ---- 7. Launch readiness: >=6/8 pass marks + decision ----
lr = read(REPORTS / "launch_readiness_report.md")
pass_marks = len(re.findall(r"\|\s*(PASS|✅|☑|\[x\])\s*\|", lr, re.I))
decision = bool(re.search(r"☑|\[x\]|\*\*(Go|Conditional Go|No-Go)\*\*\s*(—|-)?\s*\**\s*(SELECTED|CHOSEN|✔)", lr, re.I)) \
    or "Decision: Conditional Go" in lr or "**Decision:**" in lr and "Conditional Go" in lr
check("Launch report: validation table shows >=6 PASS", pass_marks >= 6, f"{pass_marks} pass marks")
check("Launch report: a go/no-go decision is recorded", decision, required=True)

# ---- 8. Evidence: results.json >=6/8 + exploit transcripts exist ----
res = read(EVIDENCE / "results.json")
try:
    rj = json.loads(res) if res else {}
    check("results.json: >=6/8 validation tests passed",
          rj.get("passed", 0) >= 6, f"{rj.get('passed')}/{rj.get('total')}")
except json.JSONDecodeError:
    check("results.json: >=6/8 validation tests passed", False, "missing/invalid results.json")

for fn, desc in [("direct_injection.json", "direct injection"),
                 ("rag_poisoning.json", "indirect injection"),
                 ("task_hijack_vulnerable.json", "task hijack (vulnerable)")]:
    check(f"evidence exists: {desc}", (EVIDENCE / fn).exists(), str(EVIDENCE / fn), required=False)

# ---- report ----
print("\n" + "=" * 92)
print("RUBRIC ASSERTION MATRIX")
print("=" * 92)
failed_required = 0
for name, passed, detail, required in checks:
    tag = "PASS" if passed else ("FAIL" if required else "warn")
    if not passed and required:
        failed_required += 1
    print(f"  [{tag:>4}] {name}" + (f"   ({detail})" if detail and not passed else ""))
print("-" * 92)
total = len(checks)
n_pass = sum(1 for c in checks if c[1])
print(f"{n_pass}/{total} checks passed; {failed_required} REQUIRED failures")
print("=" * 92)
sys.exit(1 if failed_required else 0)
