#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG="$SCRIPT_DIR/llm-harness.config.json"

cd "$PROJECT_ROOT"

# Locate bun
BUN=""
for c in "$(command -v bun 2>/dev/null)" "$HOME/.bun/bin/bun" "/usr/local/bin/bun"; do
  [ -x "$c" ] && BUN="$c" && break
done
[ -z "$BUN" ] && { echo "ERROR: bun not found"; exit 1; }

[ ! -f "$CONFIG" ] && { echo "Config not found: $CONFIG"; echo "  cp scripts/llm-harness.config.example.json $CONFIG"; exit 1; }

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║   OpenCode Warden — LLM Test Harness — Full Suite Runner          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

# Extract model instances from config (flattened provider/model keys)
MODEL_KEYS=()
while IFS= read -r line; do
    [ -n "$line" ] && MODEL_KEYS+=("$line")
done < <("$BUN" -e '
  const c = await Bun.file("'"$CONFIG"'").json();
  let entries = [];
  if (c.providers) {
    for (const [pn, p] of Object.entries(c.providers)) {
      if (p.models) for (const [mn] of Object.entries(p.models)) entries.push(`${pn}/${mn}`);
      else if (p.model) entries.push(`${pn}/default`);
    }
  } else if (c.provider) entries.push("default/default");
  for (const e of entries) console.log(e);
' 2>/dev/null)

COUNT=${#MODEL_KEYS[@]}
[ "$COUNT" -eq 0 ] && { echo "No models configured."; exit 1; }

# Display available models
echo "  Available models:"
for i in "${!MODEL_KEYS[@]}"; do
  KEY="${MODEL_KEYS[$i]}"
  MODEL=$("$BUN" -e '
    const c = await Bun.file("'"$CONFIG"'").json();
    const [p, m] = "'"${KEY}"'".split("/");
    const pc = c.providers?.[p]; const mc = pc?.models?.[m];
    console.log(mc?.model || pc?.model || "?");
  ' 2>/dev/null)
  printf "    [%2d] %-30s %s\n" "$((i+1))" "$KEY" "$MODEL"
done
echo ""

# Multi-select
if [ "$COUNT" -eq 1 ]; then
  SELECTED="${MODEL_KEYS[0]}"
  echo "  → Single model: $SELECTED"
else
  read -p "  Select models (comma-separated numbers, or 'all'): " -r
  echo ""
  if [[ "$REPLY" =~ ^[Aa][Ll][Ll]$ ]]; then
    SELECTED=$(IFS=,; echo "${MODEL_KEYS[*]}")
    echo "  → All $COUNT models"
  else
    SELECTED_ARR=()
    IFS=',' read -ra INDICES <<< "$REPLY"
    for idx in "${INDICES[@]}"; do
      idx=$(echo "$idx" | tr -d ' ')
      if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "$COUNT" ]; then
        SELECTED_ARR+=("${MODEL_KEYS[$((idx-1))]}")
      fi
    done
    [ ${#SELECTED_ARR[@]} -eq 0 ] && { echo "  No valid selection."; exit 1; }
    SELECTED=$(IFS=,; echo "${SELECTED_ARR[*]}")
    echo "  → ${#SELECTED_ARR[@]} model(s): $SELECTED"
  fi
fi
echo ""

# Run mode
MODE_ARGS=()
if [ "$COUNT" -gt 1 ] || [[ "$SELECTED" == *","* ]]; then
  echo "  Run mode:"
  echo "    [1] Sequential"
  echo "    [2] Side-by-side (per-provider concurrency limited)"
  read -p "  Choice [1]: " -r
  echo ""
  [[ "$REPLY" == "2" ]] && MODE_ARGS+=("--mode" "side-by-side") && echo "  → Side-by-side" || echo "  → Sequential"
fi

# Resume check
BASE_OUTPUT=$("$BUN" -e 'const c = await Bun.file("'"$CONFIG"'").json(); console.log((c.output || "scripts/llm-harness-results").replace(/\.json$/,""))' 2>/dev/null)
LATEST=""
for f in "${BASE_OUTPUT}"-*.json; do
  [ -e "$f" ] && LATEST="$f"
done

RUN_ARGS=("--model" "$SELECTED" "${MODE_ARGS[@]}")

if [ -n "$LATEST" ]; then
  echo "  Found: $LATEST"
  read -p "  Resume? [Y/n]: " -r
  echo ""
  [[ ! $REPLY =~ ^[Nn]$ ]] && RUN_ARGS+=("--resume") && echo "  → Resuming" || echo "  → Fresh run"
else
  echo "  → Fresh run (timestamped output)"
fi
echo ""

# Pass-through args
PASS=()
while [[ $# -gt 0 ]]; do PASS+=("$1"); shift; done

exec "$BUN" run scripts/llm-harness.ts "${RUN_ARGS[@]}" "${PASS[@]}"
