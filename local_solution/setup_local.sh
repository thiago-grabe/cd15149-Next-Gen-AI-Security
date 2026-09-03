#!/usr/bin/env bash
# setup_local.sh — provision the Northstar red-team/harden project locally on macOS.
# No sudo required. Uses uv for the Python environment and a local Ollama runtime.
#
#   bash setup_local.sh
#
# Prereqs (install once):
#   - uv        : https://docs.astral.sh/uv/  (brew install uv)
#   - ollama    : https://ollama.com          (brew install ollama)
set -euo pipefail
cd "$(dirname "$0")"

MODEL="mistral:7b-instruct-v0.2-q4_0"

echo "==> 1/5  Python env (uv, Python 3.12)"
uv venv --python 3.12 2>/dev/null || uv venv --python 3.13
# torch/sentence-transformers are listed in requirements.txt but NOT used by the
# default ChromaDB embedding function (ONNX). Install the runtime deps we actually need;
# sentence-transformers is optional and can be added with: uv pip install sentence-transformers
UV_HTTP_TIMEOUT=600 uv pip install "chromadb>=0.5.0,<1.0.0" "requests>=2.31.0" "Pillow>=10.0.0"

echo "==> 2/5  Ensure Ollama is running"
if ! curl -s --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "    starting 'ollama serve' in the background (log: /tmp/ollama_serve.log)"
  nohup ollama serve >/tmp/ollama_serve.log 2>&1 &
  for _ in $(seq 1 30); do
    curl -s --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
fi

echo "==> 3/5  Pull the model ($MODEL, ~4 GB) if missing"
if ! ollama list | grep -q "$MODEL"; then
  ollama pull "$MODEL"
fi

echo "==> 4/5  Load the knowledge base (benign)"
. .venv/bin/activate
python load_knowledge_base.py

echo "==> 5/5  Smoke test (hardened agent demo)"
python student_work/defenses/northstar_agent_hardened.py --demo

echo
echo "Setup complete. Next:"
echo "  . .venv/bin/activate"
echo "  python student_work/attacks/direct_injection_attacks.py     # attack the vulnerable agent"
echo "  python load_knowledge_base.py --reset && python load_knowledge_base.py --with-malicious"
echo "  python student_work/attacks/rag_poisoning_attack.py"
echo "  python student_work/attacks/task_hijack_test.py --vulnerable # hijack succeeds (evidence)"
echo "  python before_after.py                                       # before/after evidence"
echo "  python run_validation.py                                     # 8 validation tests (>=6/8)"
echo "  python student_work/attacks/task_hijack_test.py              # hijack blocked (hardened)"
echo "  python assert_rubric.py                                      # rubric assertion matrix"
