# Incident Response Playbook
## Northstar Research Agent

**Version:** 1.0
**Owner:** Security Operations Center
**Completed by:** AI Security Engineer, Northstar Technologies
**Date:** 2026-09-02

---

## When to Activate This Playbook

Activate when any of the following occur:

- The agent executes a command that was not requested by the user
- Employee records or credentials appear in an agent response unexpectedly
- A user reports unusual agent behavior
- An alert fires from one of the monitoring rules below

---

## Incident Severity Levels

| Level | Criteria | Examples |
|-------|----------|---------|
| **P1 — Critical** | Active breach or confirmed credential exposure | `GET_SYSTEM_INFO` or `EXPORT_ALL_DATA` executed in production |
| **P2 — High** | Unauthorized data access | Employee PII returned to wrong user, `query_hr_database` called for non-HR task |
| **P3 — Medium** | Suspicious but unconfirmed | Repeated injection attempts with no confirmed success |
| **P4 — Low** | Near-miss or policy violation | User trying injection, agent correctly refused |

---

## First 30 Minutes

**Scenario used below:** an alert fires that `EXPORT_ALL_DATA` was executed by the agent in
production (**P1 — Critical**).

### Minutes 0–5: Confirm and Classify

- [x] Pull the agent audit log for the session in question
- [x] Identify: which command or tool was called? What data was returned?
- [x] Assign a severity level (P1 / P2 / P3 / P4)
- [x] Page on-call if P1 or P2

**Log location:** `student_work/attacks/evidence/agent_audit.log` (JSONL; in production, the
central SIEM index `northstar-agent-*`).
**On-call contact:** SOC on-call via PagerDuty → hotline ext. 9-SECURITY (9-7328).

For the scenario: grep the audit log for the `session_id`; confirm `commands_executed` or
`blocked_commands` contains `EXPORT_ALL_DATA` and note the `retrieved_doc_ids` and `user_input`.

---

### Minutes 5–15: Contain

If the session is still active:

```bash
# Stop the agent
sudo pkill -f northstar_agent

# Block the user's / caller's access
# Revoke the session token and disable the calling service account in the IdP
# (Okta): okta user suspend <user_id>; rotate the agent's Ollama/API gateway key.
```

Preserve all logs before restarting anything.

If data was exported or credentials were exposed:
- [x] Notify the Data Privacy team immediately
- [x] Do not attempt to hide or undo the access — preserve evidence

---

### Minutes 15–30: Assess and Notify

Answer these questions and document the answers:

| Question | Answer |
|----------|--------|
| Which records were accessed? | From the audit log: all `INTERNAL_DB` records if `EXPORT_ALL_DATA` ran; capture exact IDs returned. |
| Were credentials exposed? | Yes if `GET_SYSTEM_INFO` also ran (`db_password`, `admin_token`) — treat as compromised and rotate. |
| Was the knowledge base modified? | Check for new/changed docs and any `type:"malicious"` entries; diff against the last known-good load. |
| Is the attack ongoing? | Confirm the session is killed and no new alerts are firing after containment. |

Notify based on severity:
- P1/P2: CISO, Legal, HR (if employee data)
- P3: SOC team lead
- P4: Log and monitor

---

## Remediation Before Restarting

- [x] Audit and purge malicious documents from the knowledge base:
  ```bash
  sudo python3 load_knowledge_base.py --reset
  sudo python3 load_knowledge_base.py
  ```
- [x] Rotate any exposed credentials (DB password, admin/API tokens, employee API keys)
- [x] Apply hardened system prompt and guardrails (deploy `northstar_agent_hardened.py`)
- [x] Rerun the validation test suite (`python run_validation.py`, require ≥6/8) before bringing the agent back online

---

## What to Log for Every Agent Interaction

These fields must be captured for every request. The hardened agent's `log_interaction()`
writes them as JSONL (field name in parentheses):

| Field | Why It Matters |
|-------|---------------|
| Timestamp (`timestamp`) | Forensic timeline |
| User ID / Session ID (`session_id`) | Attribution and correlation |
| Full user input (`user_input`) | Evidence |
| Retrieved document IDs (`retrieved_doc_ids`, `rag_flagged`) | Detect RAG poisoning |
| Commands executed (`commands_executed`, `blocked_commands`) | Alert on unauthorized actions |
| Tools called (`tools_called`, `blocked_tools`) | Alert on privilege violations |
| Response time (ms) (`response_time_ms`) | Detect denial-of-service patterns |

---

## Alert Rules

The example row below does not count toward the required five. Six additional rules follow,
based on the attacks observed in Phase 2.

| Alert Name | Trigger Condition | Severity | First Action |
|-----------|-------------------|----------|-------------|
| *Example:* Bulk export triggered | `EXPORT_ALL_DATA` executed | P1 | Page on-call, suspend session |
| System info / credential access | `GET_SYSTEM_INFO` executed, or a response contains `db_password`/`admin_token`/`sk-` API key | P1 | Page on-call, suspend session, begin credential rotation |
| Unauthorized HR tool call | `tools_called` or `blocked_tools` contains `query_hr_database` on a non-HR task | P2 | Suspend session, notify Data Privacy, review returned records |
| Employee-record exfiltration | Response body or `commands_executed` contains employee PII (email + `salary_band`/`access_level`) | P2 | Suspend session, capture payload, notify HR/Legal |
| Poisoned document retrieved | `rag_flagged` non-empty, or a `type:"malicious"` / injection-phrase doc appears in `retrieved_doc_ids` | P3 | Quarantine the document, purge+reload KB, review ingest source |
| Repeated injection attempts | ≥3 requests in 10 min from one session with `injection_suspected=true` or `blocked_commands` non-empty | P3 | Rate-limit/lock the session, retain transcripts, monitor |
| Latency / DoS pattern | `response_time_ms` p95 > 30s or request rate > N/min per session | P4→P3 | Throttle the caller, check queue depth, alert on-call if sustained |

---

## Contacts

| Role | Name | Contact |
|------|------|---------|
| SOC | SOC On-Call | soc@northstar-tech.com |
| AI Enablement | AI Enablement Team | ai-team@northstar-tech.com |
| Data Privacy | Data Privacy Office | privacy@northstar-tech.com |
| Legal | Legal / Compliance | legal@northstar-tech.com |
