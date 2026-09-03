# Northstar Research Agent — Red Team & Harden (VM / Vocareum Solution)

Self-contained submission for the cd15149 capstone, packaged to run on the **Vocareum lab VM**
(Ubuntu/Debian container, `sudo`, project root `/project`). It contains the same graded
deliverables as `../local_solution/` plus VM-specific provisioning.

> **Provenance:** all reports and the evidence transcripts in
> `student_work/attacks/evidence/` were generated locally on macOS against the identical target
> model `mistral:7b-instruct-v0.2-q4_0` and the identical code shipped here. They reproduce on the
> VM via the pipeline below (LLM output is non-deterministic in wording, but the structural
> outcomes are deterministic because the hardened agent removes the execution paths entirely).

## One-command setup + deploy

```bash
cd vm_solution
sudo bash setup_vm.sh
```

`setup_vm.sh` installs system + Python deps, installs/starts Ollama, pulls the model, loads the
knowledge base, runs a smoke test, and **deploys the deliverables to `/project/student_work/`** so
the grader's expected paths resolve:

| Grader path (`/project/…`) | Source in this folder |
|----------------------------|-----------------------|
| `student_work/reports/owasp_assessment.md` | `student_work/reports/owasp_assessment.md` |
| `student_work/reports/security_findings.md` | same |
| `student_work/reports/ir_playbook.md` | same |
| `student_work/reports/launch_readiness_report.md` | same |
| `student_work/defenses/northstar_agent_hardened.py` | same |
| `student_work/defenses/system_prompt_hardened.txt` | same |
| `student_work/attacks/task_hijack_test.py` | same |

## Reproduce the pipeline on the VM

From `/project` (after `setup_vm.sh`):

```bash
sudo python3 student_work/attacks/direct_injection_attacks.py
sudo python3 load_knowledge_base.py --reset && sudo python3 load_knowledge_base.py --with-malicious
sudo python3 student_work/attacks/rag_poisoning_attack.py
sudo python3 student_work/attacks/task_hijack_test.py --vulnerable   # hijack SUCCEEDS
sudo python3 before_after.py
sudo python3 run_validation.py                                       # >= 6/8 (target 8/8)
sudo python3 student_work/attacks/task_hijack_test.py                # hijack BLOCKED
sudo python3 assert_rubric.py                                        # rubric assertion matrix
```

## Verify Your Implementation (rubric)

`run_validation.py` runs the 8 required test scenarios; `assert_rubric.py` mechanically checks
every rubric line and exits non-zero on any failure. The hardened defenses and their evidence are
documented in `student_work/reports/launch_readiness_report.md`.

## Notes for the VM environment

- Everything resolves paths relative to the current directory — run all commands from `/project`.
- If Ollama stops responding: `sudo pkill -f 'ollama serve'` then `sudo ollama serve &`.
- If ChromaDB raises a `sqlite3` version error: `sudo pip3 install pysqlite3-binary` (the agent
  shim picks it up automatically).
- The full defense write-up and design rationale mirror `../local_solution/README.md`.
