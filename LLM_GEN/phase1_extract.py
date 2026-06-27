import os
import json
import time
import random
import re
import argparse
from pathlib import Path
from openai import OpenAI

# ──────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────
SILICONFLOW_API_KEY  = "..."
SILICONFLOW_BASE_URL = "..."

SAMPLE_DIR   = r"..."
OUTPUT_DIR   = Path(__file__).parent / "result"
OUTPUT_DIR.mkdir(exist_ok=True)

SAMPLE_COUNT       = 1000
RANDOM_SEED        = 42
MAX_CODE_LEN       = 4000
SLEEP_BETWEEN      = 1.0

VIRTUAL_SCRIPT_NAME = "_virtual_behavior_script.js"

MODELS = {

}

# ──────────────────────────────────────────────────────────
# Prompt 1: Reasoning
# ──────────────────────────────────────────────────────────
PROMPT_TEMPLATE = """You are a malware analyst. The code below is from a KNOWN MALICIOUS NPM package.
Analyze the JavaScript code and extract every sensitive call and its parameters. Identify each malicious step and output one detection rule per step.
Ignore benign code; only output rules for suspicious/malicious behaviors.

Each rule is a JSON object with exactly 3 fields:
  "rule_id":   prefix+number  (IG=InfoGathering, DT=DataTransmission, DE=DataEncoding, PE=PayloadExecution, SP=Special)
  "category":  one of the following:
    INFORMATION_GATHERING  — reads system info, environment variables, files, DNS, process list
    DATA_TRANSMISSION      — network connections, HTTP requests, data exfiltration, external URLs
    DATA_ENCODING          — base64, hex encoding, obfuscation, serialization, embedded credentials
    PAYLOAD_EXECUTION      — command execution, spawning processes, eval, dynamic code, shell scripts
    SPECIAL_PATTERNS       — stealth/evasion behaviors that cross categories or don't fit above:
                             e.g. /tmp/ operations, >/dev/null redirection, chmod 777,
                             silent flags (-s), persistence mechanisms, anti-detection tricks
  "pdcg_pattern": object with node_type plus ONE matching field:
      if node_type is "CALL"     -> {{"node_type":"CALL",     "callee_name_regex":"<regex matching function/method name>"}}
      if node_type is "ARGUMENT" -> {{"node_type":"ARGUMENT", "content_regex":     "<regex matching argument value>"}}

CRITICAL RULES — SKIP the step entirely if any of these apply:
  1. The callee is a custom/private function invented by this package author
     (e.g. sendPayload, collectInfo, exfilData, myHelper, doEvil).
     Only write CALL rules for well-known built-in or standard-library APIs:
     Node.js built-ins (exec, spawn, execSync, execFile, eval, require, fs.readFile,
     os.hostname, dns.lookup, http.request, https.get, net.connect, Buffer.from …),
     shell commands passed as string arguments (bash, curl, wget, nc, chmod …),
     or widely-used third-party APIs (axios.post, fetch …).
  2. The argument is a variable, concatenated expression, or runtime value — only
     match hard-coded string literals that carry the malicious signal themselves
     (e.g. a C2 domain, a shell command string, a base64 flag).
  3. The pattern would fire on normal, benign JavaScript (e.g. bare toString, JSON.stringify,
     Buffer.from without context, require without a suspicious module name).

Examples:
  {{"rule_id":"PE-001","category":"PAYLOAD_EXECUTION","pdcg_pattern":{{"node_type":"CALL","callee_name_regex":"(spawn|exec)$"}}}}
  {{"rule_id":"IG-001","category":"INFORMATION_GATHERING","pdcg_pattern":{{"node_type":"ARGUMENT","content_regex":"^(os|fs)$"}}}}
  {{"rule_id":"SP-001","category":"SPECIAL_PATTERNS","pdcg_pattern":{{"node_type":"ARGUMENT","content_regex":"/(tmp|temp)/"}}}}

Return a JSON array only. No text outside the array.

Code:
{code}"""

VALID_CATEGORIES = {
    "INFORMATION_GATHERING", "DATA_TRANSMISSION",
    "DATA_ENCODING", "PAYLOAD_EXECUTION", "SPECIAL_PATTERNS",
}


def get_client() -> OpenAI:
    return OpenAI(api_key=SILICONFLOW_API_KEY, base_url=SILICONFLOW_BASE_URL)


def load_js_code(sample_path: str) -> str:
    js_parts = []
    virtual_path = os.path.join(sample_path, VIRTUAL_SCRIPT_NAME)
    if os.path.exists(virtual_path):
        try:
            with open(virtual_path, encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            if content:
                js_parts.append(f"// === {VIRTUAL_SCRIPT_NAME} ===\n{content}")
        except Exception:
            pass

    pkg_dir    = os.path.join(sample_path, "package")
    search_dir = pkg_dir if os.path.isdir(pkg_dir) else sample_path
    for root, _, files in os.walk(search_dir):
        for fname in sorted(files):
            if not fname.endswith(".js"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if content:
                    js_parts.append(f"// === {fname} ===\n{content}")
            except Exception:
                continue

    return "\n\n".join(js_parts)[:MAX_CODE_LEN]


def call_llm(client: OpenAI, model_id: str, code: str, retries: int = 3) -> str:
    prompt = PROMPT_TEMPLATE.format(code=code)
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model_id,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=2048,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            wait = 2 ** attempt
            print(f"      [Retry {attempt+1}/{retries}] {e}, waiting {wait}s")
            time.sleep(wait)
    return ""


def parse_output(raw: str):
    raw = re.sub(r'```.*?```', '', raw, flags=re.DOTALL).strip()
    m = re.search(r'\[.*\]', raw, re.DOTALL)
    if not m:
        return False, []
    try:
        rules = json.loads(m.group())
        if isinstance(rules, list):
            return True, rules
    except json.JSONDecodeError:
        pass
    return False, []


def filter_valid_rules(rules: list) -> list:
    valid = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        pat = r.get("pdcg_pattern", {})
        if not isinstance(pat, dict):
            continue
        nt = pat.get("node_type")
        if nt == "CALL" and not pat.get("callee_name_regex"):
            continue
        if nt == "ARGUMENT" and not (pat.get("content_regex") or pat.get("content")):
            continue
        if r.get("category") not in VALID_CATEGORIES:
            continue
        if not r.get("rule_id"):
            continue
        valid.append(r)
    return valid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", type=int, default=0,
                        help="Pilot mode: use N samples only (0 = full run)")
    parser.add_argument("--model", default="all",
                        choices=["qwen", "deepseek", "all"],
                        help="Which model(s) to run (default: all)")
    args = parser.parse_args()
    pilot_n = args.pilot

    if args.model == "all":
        selected_models = list(MODELS.items())
    else:
        selected_models = [(args.model, MODELS[args.model])]

    all_samples = [e.path for e in os.scandir(SAMPLE_DIR) if e.is_dir()]
    random.seed(RANDOM_SEED)
    n = pilot_n if pilot_n > 0 else min(SAMPLE_COUNT, len(all_samples))
    test_samples = random.sample(all_samples, min(n, len(all_samples)))
    tag = f"[PILOT-{pilot_n}]" if pilot_n > 0 else "[FULL]"
    print(f"{tag} Sample count: {len(test_samples)}  Models to run: {[k for k,_ in selected_models]}")

    suffix = f"_pilot{pilot_n}" if pilot_n > 0 else ""
    client = get_client()

    for model_key, (model_name, model_id) in selected_models:
        print(f"\n{'='*55}")
        print(f"  Model: {model_name}")
        print(f"{'='*55}")

        result_file = OUTPUT_DIR / f"{model_name}_full_rules{suffix}.json"

        results   = []
        done      = set()
        if result_file.exists():
            with open(result_file, encoding="utf-8") as f:
                results = json.load(f)
            done = {r["sample"] for r in results}
            print(f"  Resume: {len(done)} completed, {len(test_samples)-len(done)} remaining")

        for i, sample_path in enumerate(test_samples, 1):
            name = os.path.basename(sample_path)
            if name in done:
                continue

            print(f"  [{i:4d}/{len(test_samples)}] {name}", end=" ... ", flush=True)

            code = load_js_code(sample_path)
            if not code.strip():
                print("skip (empty)")
                continue

            raw      = call_llm(client, model_id, code)
            is_valid, rules = parse_output(raw)
            valid_rules     = filter_valid_rules(rules) if is_valid else []

            record = {
                "sample":      name,
                "valid_json":  is_valid,
                "rule_count":  len(rules) if is_valid else 0,
                "valid_count": len(valid_rules),
                "rules":       valid_rules,
            }
            results.append(record)
            done.add(name)

            if is_valid:
                print(f"[OK] rules={record['rule_count']}  valid={record['valid_count']}")
            else:
                print("[FAIL] JSON parse failed")

            if len(results) % 10 == 0:
                with open(result_file, "w", encoding="utf-8") as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)

            time.sleep(SLEEP_BETWEEN)

        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        total       = len(results)
        valid_cnt   = sum(1 for r in results if r["valid_json"])
        total_rules = sum(r["valid_count"] for r in results)
        print(f"\n[Done] {model_name}: {total} samples  Valid JSON: {valid_cnt}  Total valid rules: {total_rules}")
        print(f"Result saved to: {result_file}")

    print(f"\nAll models completed. Next step: python phase2_consolidate_single.py --model all{' --pilot ' + str(pilot_n) if pilot_n > 0 else ''}")


if __name__ == "__main__":
    main()