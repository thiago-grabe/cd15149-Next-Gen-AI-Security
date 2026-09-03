#!/usr/bin/env bash
# setup_vm.sh — provision + deploy the Northstar red-team/harden solution on the
# Vocareum lab VM (Ubuntu/Debian container). Mirrors the official SETUP.md flow, then
# deploys the graded deliverables to /project/student_work so the rubric paths resolve.
#
#   sudo bash setup_vm.sh
#
# Run from this folder (vm_solution/). Idempotent where practical.
set -euo pipefail
cd "$(dirname "$0")"
SRC="$(pwd)"
PROJECT_DIR="${PROJECT_DIR:-/project}"
MODEL="mistral:7b-instruct-v0.2-q4_0"

echo "==> 1/7  System dependencies"
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv curl git

echo "==> 2/7  Python packages"
# pysqlite3-binary is needed on the lab's older sqlite3; the agent shim uses it if present.
# sentence-transformers is listed in requirements.txt but NOT used by the default ChromaDB
# ONNX embedding function, so the runtime set below is sufficient.
sudo pip3 install pysqlite3-binary "chromadb>=0.5.0,<1.0.0" "requests>=2.31.0" "Pillow>=10.0.0"

echo "==> 3/7  Install + start Ollama"
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sudo sh
fi
if ! curl -s --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
  nohup ollama serve >/var/log/ollama.log 2>&1 &
  for _ in $(seq 1 30); do
    curl -s --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done
fi

echo "==> 4/7  Pull the model ($MODEL, ~4 GB) if missing"
ollama list | grep -q "$MODEL" || ollama pull "$MODEL"

echo "==> 5/7  Stage the project into $PROJECT_DIR"
sudo mkdir -p "$PROJECT_DIR"
sudo cp -R "$SRC/northstar_agent.py" "$SRC/load_knowledge_base.py" "$SRC/requirements.txt" \
          "$SRC/run_validation.py" "$SRC/before_after.py" "$SRC/assert_rubric.py" \
          "$SRC/knowledge_base" "$SRC/student_work" "$PROJECT_DIR"/
sudo chmod -R 777 "$PROJECT_DIR/student_work"

echo "==> 6/7  Load the knowledge base (benign)"
cd "$PROJECT_DIR"
sudo python3 load_knowledge_base.py

echo "==> 7/7  Smoke test (hardened agent demo)"
sudo python3 student_work/defenses/northstar_agent_hardened.py --demo

cat <<EOF

Deployed to $PROJECT_DIR. Graded deliverables are at $PROJECT_DIR/student_work/.

Reproduce the pipeline (run from $PROJECT_DIR):
  sudo python3 student_work/attacks/direct_injection_attacks.py
  sudo python3 load_knowledge_base.py --reset && sudo python3 load_knowledge_base.py --with-malicious
  sudo python3 student_work/attacks/rag_poisoning_attack.py
  sudo python3 student_work/attacks/task_hijack_test.py --vulnerable   # hijack succeeds
  sudo python3 before_after.py
  sudo python3 run_validation.py                                       # >= 6/8 (target 8/8)
  sudo python3 student_work/attacks/task_hijack_test.py                # hijack blocked
  sudo python3 assert_rubric.py                                        # rubric matrix
EOF
