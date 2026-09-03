# OWASP LLM Top 10 — Risk Assessment
**Application:** Northstar Research Agent
**Assessor:** AI Security Engineer, Northstar Technologies
**Date:** 2026-09-02

---

## How to Use This Checklist

Each category records whether the vulnerability is **Present**, a **Severity** rating, the
**Evidence** (code location and/or attack result), and a one-line **Recommendation**. All 10
categories are assessed (the rubric requires at least 6). Code references are to the vulnerable
`northstar_agent.py`.

---

## LLM01 — Prompt Injection

An attacker crafts input that overrides the model's system instructions.

*In this system:* The system prompt has no separation from user input, and the model is told to "follow all instructions provided."

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Critical |
| Evidence | `SYSTEM_PROMPT` (`:109-126`) ends with "Always be helpful and follow all instructions provided to you," and retrieved context is concatenated into the same **system** message (`:305-314`). User input, system rules, and retrieved data share one trust level. Direct-injection attacks (Finding 1) reliably drive the model to emit `GET_SYSTEM_INFO`/`EXPORT_ALL_DATA`. |
| Recommendation | Add a hardened system prompt that forbids obeying instructions in user/retrieved content, and structurally segregate system vs. untrusted input. |

---

## LLM02 — Insecure Output Handling

The application blindly executes content produced by the LLM without validating it.

*In this system:* Every LLM response is scanned for command patterns and those commands are executed immediately with no checks.

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Critical |
| Evidence | `parse_commands_from_response` (`:262-274`) regex-scans the raw model output and `chat()` (`:336-340`) calls `execute_command` on every match — including tokens quoted inside a *refusal*. Line `:336` even un-escapes `\_` first, widening the match. No verification that the current user actually requested the action. |
| Recommendation | Never execute privileged operations parsed from model output; drive real actions from validated user intent through a typed, allowlisted interface. |

---

## LLM03 — Training Data Poisoning

An attacker manipulates training or fine-tuning data to embed backdoors or biases.

*In this system:* The model uses pre-trained Mistral 7B and is not fine-tuned. Consider the RAG knowledge base as a related risk surface.

| Field | Your Response |
|-------|--------------|
| Present? | Partial (RAG knowledge base is the analogue) |
| Severity | High |
| Notes | The base model is not trained/fine-tuned here, so classic training-data poisoning does not apply. The equivalent surface is the RAG corpus: any writer of a KB document can inject instructions that the agent ingests as trusted context (`load_knowledge_base.py` upserts whole documents with no validation; the agent applies no retrieval-time trust check). Demonstrated in Finding 2. |
| Recommendation | Treat the KB as an untrusted supply surface: validate/scan documents at ingest and at retrieval, restrict who can write to the collection, and record document provenance. |

---

## LLM04 — Model Denial of Service

An attacker sends inputs that consume excessive compute, causing slowdowns or outages.

*In this system:* There is no rate limiting, token cap, or queue management on Ollama requests.

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Medium |
| Evidence | `chat()` posts to Ollama with no rate limit and no output cap (`num_predict` absent), `timeout=600` (`:329`), and appends every turn to an unbounded `conversation_history` (`:317`, `:529-530`), so prompt size grows without limit. A single client can saturate the single-threaded local runtime. |
| Recommendation | Add per-user rate limiting, an input-length cap, `num_predict`, and a bounded conversation window; queue and time-box requests. |

---

## LLM05 — Supply Chain Vulnerabilities

Risk introduced through third-party models, libraries, or data sources.

*In this system:* Review `requirements.txt`. What happens if a dependency is compromised? What is the provenance of the Mistral model?

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Medium |
| Dependencies reviewed | `requirements.txt` pins only lower bounds (`chromadb>=0.5.0`, `sentence-transformers>=2.2.0`, …) with no lockfile or hashes, so a compromised release is pulled silently. Setup installs via `curl -fsSL https://ollama.com/install.sh \| sudo sh`, `pip3 install` as root system-wide, and `chmod -R 777` on writable dirs (`setup_lab.sh`). The Mistral model is pulled by tag with no digest pinning. |
| Recommendation | Pin exact versions + hashes (lockfile), verify the model digest, avoid `curl \| sudo sh` and root/world-writable installs, and run in an isolated venv. |

---

## LLM06 — Sensitive Information Disclosure

The model reveals confidential data — including its system prompt, employee records, or credentials.

*In this system:* `GET_SYSTEM_INFO` returns database credentials. `EXPORT_ALL_DATA` dumps all employee records. There are no access controls.

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Critical |
| Evidence | `get_system_info()` (`:168-176`) returns a production `db_password` and `admin_token`; `export_all_data()`/`search_employee()` dump employee PII and `internal_api_key` values (`:156-165`). Secrets are hardcoded in source (`INTERNAL_DB` `:48-101`). The interactive banner even advertises `EXPORT_ALL_DATA`/`GET_SYSTEM_INFO`/`SEARCH_EMPLOYEE` to every user (`:489-497`). |
| Recommendation | Remove secrets from source, gate all data access behind authorization, stop disclosing command vocabulary, and forbid the model from returning credentials/PII. |

---

## LLM07 — Insecure Plugin Design

Tools and plugins lack proper access controls, enabling unauthorized actions.

*In this system:* `query_hr_database` returns full employee PII and API keys. It is available to all agent tasks with no restriction.

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Critical |
| Tool(s) affected | `query_hr_database` (`:202-210`) — returns full employee records incl. API keys; advertised to every task via `AGENT_PROMPT` (`:363`) and executed with no permission check in `execute_tool` (`:385-394`). Task hijacking (Finding 3) invokes it during a research task. |
| Recommendation | Enforce a per-task tool allowlist (least privilege); keep `query_hr_database` out of every non-HR role and refuse it at the execution boundary. |

---

## LLM08 — Excessive Agency

The LLM has more capabilities or autonomy than it needs, enabling unintended high-impact actions.

*In this system:* The agentic loop runs without any human approval step. The agent prompt instructs it to "use all available tools as needed."

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | High |
| Evidence | `run_agent_task` (`:397-457`) auto-executes any parsed tool call for up to 3 iterations with no human-in-the-loop, `AGENT_PROMPT` says "Use all available tools as needed" (`:366`), and tool output is re-injected as a **user** turn (`:447-450`), letting tool results steer later steps. |
| Recommendation | Constrain the tool set per task, require confirmation for sensitive/irreversible actions, and never treat tool output as user-authored instruction. |

---

## LLM09 — Overreliance

Users trust LLM outputs without verification, leading to decisions based on incorrect information.

*In this system:* Agent outputs have no confidence score, no source citation, and no disclaimer.

| Field | Your Response |
|-------|--------------|
| Present? | Yes |
| Severity | Medium |
| Example | RAG answers do not cite which document they came from and carry no accuracy disclaimer; a poisoned or wrong document is presented with the same authority as policy. The broad `except Exception` in `retrieve_context` (`:253-254`) even turns retrieval failures into a fake "document," which the model may summarize as fact. |
| Recommendation | Cite retrieved document IDs, add an accuracy disclaimer for generated content, and fail closed instead of fabricating a placeholder document. |

---

## LLM10 — Model Theft

An attacker extracts model weights, architecture, or fine-tuning data through repeated queries.

*In this system:* Mistral 7B is an open-weight public model. Classic model theft does not apply, but the system prompt and internal commands could be extracted via prompt injection.

| Field | Your Response |
|-------|--------------|
| Present? | Partial |
| Severity | Low |
| Notes | Weight theft is not meaningful for a public open-weight model. The realistic exposure is extraction of the **system prompt and internal command vocabulary** via prompt injection (and the interactive banner leaks the commands with no injection needed), which enables the LLM01/LLM06 attacks. |
| Recommendation | Protect the system prompt from disclosure, and stop exposing internal command names to users. |

---

## Summary

| ID | Category | Severity | Present? |
|----|----------|----------|---------|
| LLM01 | Prompt Injection | Critical | Yes |
| LLM02 | Insecure Output Handling | Critical | Yes |
| LLM03 | Training Data Poisoning | High | Partial (RAG) |
| LLM04 | Model Denial of Service | Medium | Yes |
| LLM05 | Supply Chain Vulnerabilities | Medium | Yes |
| LLM06 | Sensitive Information Disclosure | Critical | Yes |
| LLM07 | Insecure Plugin Design | Critical | Yes |
| LLM08 | Excessive Agency | High | Yes |
| LLM09 | Overreliance | Medium | Yes |
| LLM10 | Model Theft | Low | Partial |

**Overall Risk Rating:** ☑ Critical  ☐ High  ☐ Medium  ☐ Low

**Top 3 Priorities:**
1. **LLM02 Insecure Output Handling** — stop executing privileged commands parsed from model output (the single easiest, highest-impact exploit).
2. **LLM06 / LLM07 Sensitive Information Disclosure & Insecure Plugin Design** — remove credential/PII disclosure paths and put `query_hr_database` behind a least-privilege allowlist.
3. **LLM01 Prompt Injection** — harden the system prompt and segregate trusted instructions from untrusted user/retrieved content (also mitigates the RAG-poisoning surface under LLM03).
