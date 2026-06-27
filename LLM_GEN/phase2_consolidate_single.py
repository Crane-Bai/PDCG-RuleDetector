import json
import re
import time
import argparse
from pathlib import Path
from collections import Counter, defaultdict
from openai import OpenAI

# ──────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────
SILICONFLOW_API_KEY  = "..."
SILICONFLOW_BASE_URL = "..."

INPUT_DIR  = Path(__file__).parent / "result"
OUTPUT_DIR = Path(__file__).parent / "consolidation"
OUTPUT_DIR.mkdir(exist_ok=True)

MODELS = {

}

MAX_RULES_PER_BATCH = 80     # Single category single input upper limit; if exceeded, batch then merge
MIN_FREQ            = 2      # Low frequency filter: atomic rules appearing only 1 time are considered noise
SLEEP_BETWEEN       = 1.5
MAX_TOKENS          = 4096
TEMPERATURE         = 0.1

VALID_CATEGORIES = {
    "INFORMATION_GATHERING", "DATA_TRANSMISSION",
    "DATA_ENCODING", "PAYLOAD_EXECUTION", "SPECIAL_PATTERNS",
}
PREFIX_MAP = {
    "INFORMATION_GATHERING": "IG",
    "DATA_TRANSMISSION":     "DT",
    "DATA_ENCODING":         "DE",
    "PAYLOAD_EXECUTION":     "PE",
    "SPECIAL_PATTERNS":      "SP",
}

# ──────────────────────────────────────────────────────────
# Prompt 2: Induction
# ──────────────────────────────────────────────────────────
CONSOLIDATE_PROMPT = """\
You are a security rules engineer building a malicious npm package detector.

Below are {n} atomic detection rules for ONE category ({category} / {prefix}), \
extracted from {total_samples} known malicious npm packages.
The "_freq" field shows how many distinct samples contained that exact pattern.

GOAL
====
Consolidate these atomic rules into a MINIMAL set of high-quality generalized
rules that maximize coverage while avoiding false positives on benign JavaScript.

TASK
====
1. MERGE rules that detect the SAME malicious behavior into one generalized rule
   using alternation (A|B). Keep CALL and ARGUMENT rules SEPARATE — never mix them.
2. GENERALIZE sample-specific artifacts:
   • Specific IPs        → /dev\\/tcp\\/\\d+(\\.\\d+){{3}}\\/\\d+  (or drop if not reverse-shell)
   • Hash subdomains (abc123.oast.fun) → service domain only: \\.oast\\.fun
   • Sample filenames (evil.sh, poc.sh) → drop unless _freq >= 3
3. DEDUPLICATE: remove duplicate or near-duplicate branches inside any alternation
   (if the same string appears twice, keep one).
4. ASSIGN sequential IDs: {prefix}-001, {prefix}-002, …

REGEX STYLE
===========
CALL  — match the method/function name token:
  (exec|execSync|execFile)$  or  os\\.(hostname|userInfo|homedir)$
ARGUMENT — match the hard-coded string literal:
  ^(os|fs|path|crypto)$  or  (oastify\\.com|burpcollaborator\\.net|\\.oast\\.fun)

MERGING CONSTRAINTS (mandatory — these prevent low-quality rules)
=================================================================
• ONE rule = ONE semantic purpose. Do NOT combine patterns from different
  attack sub-goals (e.g. file reading vs network access vs flag arguments are
  three separate purposes — write separate rules or drop the weakest).
  If you cannot describe a merged rule in <= 5 words, it is TOO BROAD — split it.
• Do NOT include bare command-line flags (-i, -e, -d, -1, -n, -x) as signal
  patterns; a flag alone carries no malicious intent without context.
• Limit alternation to at most 8 branches that share the same attack intent.
  If more candidates exist, keep only the highest-_freq ones and drop the rest.
• DROP rules whose regex would fire on common benign JS
  (bare require, toString, JSON.stringify, console.log, write, get, post …).
• DISCARD custom author function names (sendPayload, collectInfo …) entirely.

OUTPUT
======
Return ONLY a JSON array. No markdown, no explanation.
[{{"rule_id":"{prefix}-NNN","name":"<= 8 words","category":"{category}",
   "pdcg_pattern":{{"node_type":"CALL","callee_name_regex":"<regex>"}}}}]
(Use content_regex instead of callee_name_regex for ARGUMENT rules.)

ATOMIC RULES TO CONSOLIDATE
===========================
{rules_json}
"""


def get_client() -> OpenAI:
    return OpenAI(api_key=SILICONFLOW_API_KEY, base_url=SILICONFLOW_BASE_URL,
                  max_retries=0, timeout=60.0)


def call_llm(client, prompt, model, retries=3):
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=TEMPERATURE, max_tokens=MAX_TOKENS,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            wait = 2 ** attempt
            print(f"    [Retry {attempt+1}/{retries}] {e}, waiting {wait}s")
            time.sleep(wait)
    return ""


def parse_json_array(raw):
    raw = re.sub(r'```.*?```', '', raw, flags=re.DOTALL).strip()
    m = re.search(r'\[.*\]', raw, re.DOTALL)
    if not m:
        return []
    try:
        result = json.loads(m.group())
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass
    return []


def pattern_key(rule):
    pat = rule.get("pdcg_pattern", {})
    val = (pat.get("callee_name_regex")
           or pat.get("content_regex")
           or pat.get("content", "")).strip()
    return (rule.get("category", ""), pat.get("node_type", ""), val)


def validate_rules(rules):
    out = []
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
        if not r.get("name"):
            r["name"] = r["rule_id"]
        # Syntax validation: regex must be compilable
        regex = pat.get("callee_name_regex") or pat.get("content_regex") or pat.get("content", "")
        try:
            re.compile(regex)
        except re.error:
            continue
        out.append(r)
    return out


# ──────────────────────────────────────────────────────────
# Code side: deduplication + frequency statistics + low frequency filter + grouping
# ──────────────────────────────────────────────────────────

def load_atomic_rules(input_file):
    with open(input_file, encoding="utf-8") as f:
        data = json.load(f)
    total = len(data)
    counter, key_to_rule = Counter(), {}
    for record in data:
        seen = set()
        for rule in record.get("rules", []):
            k = pattern_key(rule)
            if k not in seen:
                counter[k] += 1
                key_to_rule[k] = rule
                seen.add(k)
    print(f"[Step 1] Samples={total}  Unique atomic rules={len(counter)}")
    return total, counter, key_to_rule


def group_by_category(counter, key_to_rule, min_freq):
    groups = defaultdict(list)
    filtered = 0
    for key, freq in counter.most_common():
        if freq < min_freq:
            filtered += 1
            continue
        rule = dict(key_to_rule[key])
        rule["_freq"] = freq
        cat = rule.get("category", "")
        if cat in VALID_CATEGORIES:
            groups[cat].append(rule)
    kept = sum(len(v) for v in groups.values())
    print(f"[Step 2] Low frequency filter(freq<{min_freq}): dropped {filtered}  kept {kept}")
    for cat in VALID_CATEGORIES:
        print(f"    {PREFIX_MAP[cat]}: {len(groups.get(cat, []))} rules")
    return groups


# ──────────────────────────────────────────────────────────
# Single-segment induction: one LLM call per category (or batch then merge)
# ──────────────────────────────────────────────────────────

def _call_consolidate(client, cat, prefix, rules, total_samples, model):
    prompt = CONSOLIDATE_PROMPT.format(
        n=len(rules), category=cat, prefix=prefix,
        total_samples=total_samples,
        rules_json=json.dumps(rules, ensure_ascii=False, indent=2),
    )
    raw = call_llm(client, prompt, model)
    return validate_rules(parse_json_array(raw))


def consolidate_category(client, cat, rules, total_samples, model):
    """Execute single-segment induction for a single category. If too many rules, batch then merge."""
    prefix = PREFIX_MAP[cat]
    n = len(rules)

    if n <= MAX_RULES_PER_BATCH:
        print(f"  {prefix}: {n} rules → single induction", end=" ... ", flush=True)
        out = _call_consolidate(client, cat, prefix, rules, total_samples, model)
        if not out:
            # Single failure: split in half and retry, avoid degrading to keep all atomic rules on one transient failure
            print("→ failed, splitting in half and retrying", end=" ... ", flush=True)
            mid = n // 2
            halves = [rules[:mid], rules[mid:]]
            recovered = []
            ok = True
            for h in halves:
                res = _call_consolidate(client, cat, prefix, h, total_samples, model)
                if not res:
                    ok = False
                    break
                recovered.extend(res)
                time.sleep(SLEEP_BETWEEN)
            if ok and recovered:
                # After split success, consolidate once more
                merged = _call_consolidate(client, cat, prefix, recovered, total_samples, model)
                out = merged if merged else recovered
                print(f"→ recovered {len(out)} rules")
            else:
                # Final fallback: keep original atomic rules (remove private fields)
                out = validate_rules(
                    [{k: v for k, v in r.items() if not k.startswith("_")} for r in rules]
                )
                print(f"→ still failed, fallback kept {len(out)} rules")
        else:
            print(f"→ {len(out)} rules")
    else:
        # Batch induction → merge then consolidate once more
        n_batch = (n + MAX_RULES_PER_BATCH - 1) // MAX_RULES_PER_BATCH
        print(f"  {prefix}: {n} rules > {MAX_RULES_PER_BATCH}, batch into {n_batch} then merge")
        partial = []
        for bi in range(n_batch):
            batch = rules[bi*MAX_RULES_PER_BATCH:(bi+1)*MAX_RULES_PER_BATCH]
            print(f"    Batch {bi+1}/{n_batch} ({len(batch)} rules)", end=" ... ", flush=True)
            res = _call_consolidate(client, cat, prefix, batch, total_samples, model)
            if not res:
                res = validate_rules(
                    [{k: v for k, v in r.items() if not k.startswith("_")} for r in batch]
                )
            print(f"→ {len(res)} rules")
            partial.extend(res)
            time.sleep(SLEEP_BETWEEN)
        # Merge consolidation
        print(f"    Merge {len(partial)} rules → final induction", end=" ... ", flush=True)
        out = _call_consolidate(client, cat, prefix, partial, total_samples, model)
        if not out:
            out = validate_rules(partial)
            print(f"→ merge failed, kept {len(out)} rules")
        else:
            print(f"→ {len(out)} rules")

    # Sequential numbering
    for i, r in enumerate(out, 1):
        r["rule_id"] = f"{prefix}-{i:03d}"
    return out


def cross_category_cleanup(rules):
    """Code-side deterministic cleanup (no additional prompt), replaces part of original Round 3:
      1. Delete bare command flag rules (^-c$ / ^-e$ / -d etc. short flags without malicious semantics)
      2. Cross-category deduplication: under same node_type, rules with identical regex, keep one by category priority
    Category priority (more specific / more definitive categories prioritized): PE > DT > DE > IG > SP
    """
    CAT_PRIORITY = {
        "PAYLOAD_EXECUTION": 0, "DATA_TRANSMISSION": 1,
        "DATA_ENCODING": 2, "INFORMATION_GATHERING": 3, "SPECIAL_PATTERNS": 4,
    }
    # Bare flag regex: only matches single 1~2 character command-line short flags
    bare_flag = re.compile(r'^\^?-{1,2}[a-zA-Z]{1,2}\$?$')

    def regex_of(r):
        pat = r.get("pdcg_pattern", {})
        return (pat.get("node_type", ""),
                (pat.get("callee_name_regex") or pat.get("content_regex") or "").strip())

    # 1. Delete bare flag rules
    kept = []
    dropped_flags = []
    for r in rules:
        _, rx = regex_of(r)
        if bare_flag.match(rx):
            dropped_flags.append(r["rule_id"])
            continue
        kept.append(r)

    # 2. Cross-category identical regex deduplication
    best = {}   # (node_type, regex) -> rule (keep highest priority category)
    for r in kept:
        key = regex_of(r)
        if key not in best:
            best[key] = r
        else:
            old = best[key]
            if CAT_PRIORITY.get(r.get("category"), 9) < CAT_PRIORITY.get(old.get("category"), 9):
                best[key] = r
    deduped = list(best.values())

    n_dup = len(kept) - len(deduped)
    if dropped_flags:
        print(f"  [Cleanup] Deleted bare flag rules {len(dropped_flags)}: {dropped_flags}")
    if n_dup:
        print(f"  [Cleanup] Cross-category deduplication deleted {n_dup} duplicate regexes")

    # Re-number by category order
    out = []
    for cat in ["INFORMATION_GATHERING", "DATA_TRANSMISSION", "DATA_ENCODING",
                "PAYLOAD_EXECUTION", "SPECIAL_PATTERNS"]:
        cat_rules = [r for r in deduped if r.get("category") == cat]
        prefix = PREFIX_MAP[cat]
        for i, r in enumerate(cat_rules, 1):
            r["rule_id"] = f"{prefix}-{i:03d}"
            out.append(r)
    return out


def build_final_json(rules, model_name):
    cat_stats = Counter(r.get("category") for r in rules)
    return {
        "metadata": {
            "version":     "5.0-two-prompt",
            "description": "LLM-consolidated malicious behavior detection rules (single-prompt consolidation)",
            "source":      f"Consolidated from atomic rule extraction ({model_name})",
            "pipeline":    "phase1_extract.py → phase2_consolidate_single.py",
            "total_rules": len(rules),
            "category_breakdown": {
                PREFIX_MAP[cat]: cnt for cat, cnt in cat_stats.items() if cat in PREFIX_MAP
            }
        },
        "rules": rules,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pilot", type=int, default=0)
    parser.add_argument("--min-freq", type=int, default=None)
    parser.add_argument("--model", default="all",
                        choices=["qwen", "deepseek", "all"])
    args = parser.parse_args()
    pilot_n = args.pilot

    model_keys = list(MODELS.keys()) if args.model == "all" else [args.model]
    suffix = f"_pilot{pilot_n}" if pilot_n > 0 else ""
    min_freq = args.min_freq if args.min_freq is not None else (1 if pilot_n else MIN_FREQ)
    client = get_client()

    sep = "=" * 60
    print(f"{sep}\n  Phase 2: Single-prompt induction  {'[PILOT-'+str(pilot_n)+']' if pilot_n else '[FULL]'}\n{sep}")

    for model_key in model_keys:
        model_name, model_id = MODELS[model_key]
        input_file = INPUT_DIR / f"{model_name}_full_rules{suffix}.json"

        print(f"\n{sep}\n  Model: {model_name}  Induction engine: {model_id}\n{sep}")
        if not input_file.exists():
            print(f"  [Skip] Input file does not exist: {input_file}")
            continue

        total_samples, counter, key_to_rule = load_atomic_rules(input_file)
        groups = group_by_category(counter, key_to_rule, min_freq)

        print(f"\n── Single-segment induction (by category) ──")
        final_rules = []
        for cat in VALID_CATEGORIES:
            rules = groups.get(cat, [])
            if not rules:
                print(f"  {PREFIX_MAP[cat]}: no rules, skip")
                continue
            final_rules.extend(consolidate_category(client, cat, rules, total_samples, model_id))
            time.sleep(SLEEP_BETWEEN)

        final_rules = validate_rules(final_rules)
        print(f"\n── Cross-category cleanup (code-side, no additional prompt) ──")
        final_rules = cross_category_cleanup(final_rules)
        output = build_final_json(final_rules, model_name)
        final_file = OUTPUT_DIR / f"{model_name}_final_rules{suffix}.json"
        with open(final_file, "w", encoding="utf-8") as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(f"\n[Done] {model_name} final rules={len(final_rules)} → {final_file}")
        for cat, cnt in Counter(r.get("category") for r in final_rules).most_common():
            print(f"    {PREFIX_MAP.get(cat,'??')}: {cnt} rules")


if __name__ == "__main__":
    main()