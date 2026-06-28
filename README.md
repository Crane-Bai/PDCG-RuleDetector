# PDCG-RuleDet

A static analysis framework for detecting malicious NPM packages. It transforms
JavaScript source into a **Package Dependency & Call Graph (PDCG)**, matches a
curated knowledge base of malicious-behavior rules, and produces an
**87-dimensional feature vector** (60 rule-matching + 27 graph-structure
features) per package for downstream classification.

This is the open-access artifact accompanying the paper.

---

## Pipeline overview

```text
 package source  ──▶  (0) package.json virtualization  ──▶  (1) AST  ──▶  (2) PDCG  ──▶  (3) Features
                          │                                  │                                ├─ 60 rule-matching
                          │                                  │                                └─ 27 graph-structure
                          └─ install hooks -> virtual JS     └─ .ast.json per file
```

The pipeline includes an important preprocessing step before AST generation:
if an NPM package contains `preinstall`, `install`, or `postinstall` scripts in
`package.json`, these commands are converted into a virtual JavaScript file so
that installation-time behavior is preserved for static analysis.

| Stage | Directory | Entry point | Runtime |
|-------|-----------|-------------|---------|
| 0. package.json virtualization | `1_ast_generation/` | `preprocessor.py`, `batch_preprocessor.py` | Python |
| 1. AST generation | `1_ast_generation/` | `generate_ast.py` | Python + Node.js (`@babel/parser`) |
| 2. PDCG construction | `2_pdcg_generation/` | `PDCG_GEN.py` / `PDCGAnalyzer` | Python |
| 3. Feature extraction | `3_feature_extraction/` | `feature_extractor.py` | Python |

---

## Repository layout

```text
PDCG-RuleDet/
├── 1_ast_generation/
│   ├── preprocessor.py            # package.json install hooks -> virtual JS
│   ├── batch_preprocessor.py      # batch wrapper for preprocessing many packages
│   ├── generate_ast.py            # JS -> AST (.ast.json)
│   ├── package.json               # Node dependency: @babel/parser
│   └── js/
│       ├── babel_parser_bridge.js # Node bridge invoked per file
│       └── beautify_code.js
├── 2_pdcg_generation/
│   └── PDCG_GEN.py                # AST -> PDCG (.pdcg.json), class PDCGAnalyzer
├── 3_feature_extraction/
│   └── feature_extractor.py       # PDCG + rules -> 87-dim feature CSV
├── LLM_GEN/
│   ├── phase1_extract.py          # LLM-assisted rule generation helper (phase 1)
│   ├── phase2_consolidate_single.py # LLM-assisted rule consolidation helper (phase 2)
│   └── rule_effectiveness_evaluator.py # evaluates rule coverage / precision on dataset
├── rules/
│   └── malicious_rules.json       # 60-rule malicious-behavior knowledge base
├── datasets/
│   ├── MacPacDetor.csv            # labeled 87-dim feature dataset (MalnpmDB)
│   └── monitor_result/            # deployment-time evaluation datasets
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Installation

```bash
# Python side
pip install -r requirements.txt

# Node side (required for AST generation)
cd 1_ast_generation
npm install            # installs @babel/parser
cd ..
```

Requirements: Python >= 3.9, Node.js >= 16.

---

## Usage

Below, `INPUT` is a directory holding one or more unpacked NPM package folders.

### Step 0 — Convert package.json install hooks into virtual JavaScript

This step should be run before AST generation whenever you want to preserve
installation-time behavior.

#### Single package

```bash
python 1_ast_generation/preprocessor.py \
    --package_dir /path/to/unpacked_package
```

Behavior:
- If `package.json` contains `preinstall`, `install`, or `postinstall`, the
  script creates `_virtual_behavior_script.js` containing equivalent
  `spawn(...)` calls.
- If no install hooks are found, it creates `_virtual_placeholder_script.js`.
- If no JS files exist at all, it still creates a placeholder file so later
  analysis can proceed.

#### Batch mode

```bash
# classified mode: base_dir contains malicious/ and benign/
python 1_ast_generation/batch_preprocessor.py \
    --base_dir /path/to/packages_root \
    --mode classified \
    --output batch_preprocessing_results.json

# direct mode: process all subdirectories under base_dir
python 1_ast_generation/batch_preprocessor.py \
    --base_dir /path/to/packages_root \
    --mode direct \
    --output batch_preprocessing_results.json
```

---

### Step 1 — AST generation

```bash
python 1_ast_generation/generate_ast.py \
    --mode direct \
    --input-dir  /path/to/INPUT \
    --output-dir /path/to/AST_OUT
```

Produces one `*.ast.json` per source file under `AST_OUT`.

---

### Step 2 — PDCG construction

`2_pdcg_generation/PDCG_GEN.py` exposes `PDCGAnalyzer`; convert each AST to a PDCG:

```python
from PDCG_GEN import PDCGAnalyzer
import json, pathlib

analyzer = PDCGAnalyzer()
for ast_file in pathlib.Path("AST_OUT").rglob("*.ast.json"):
    pdcg = analyzer.analyze_pdcg_from_ast(str(ast_file))
    out = ast_file.stem.replace(".ast", "") + ".pdcg.json"
    json.dump(pdcg, open(pathlib.Path("PDCG_OUT") / out, "w"))
```

---

### Step 3 — Feature extraction

```bash
# batch mode: PDCG_ROOT contains benign/ and malicious/ sub-folders
python 3_feature_extraction/feature_extractor.py \
    --batch  /path/to/PDCG_ROOT \
    --output features.csv

# direct mode: no benign/malicious split
python 3_feature_extraction/feature_extractor.py \
    --mode direct \
    --input-dir  /path/to/PDCG_OUT \
    --output-dir /path/to/FEATURE_OUT
```

The output CSV contains, per package:
- 60 `rule_*` columns
- 27 graph-structure columns

Pass `--rules rules/malicious_rules.json` if running from another directory.

---

## The 87 features

**Rule-matching (60):** one column per rule in `rules/malicious_rules.json`,
organized into five behavioral categories:
- `IG` Information Gathering
- `DT` Data Transmission
- `DE` Data Encoding
- `PE` Payload Execution
- `SP` Special Patterns

**Graph-structure (27):** malicious-node statistics, per-category ratios,
internal connectivity (edges / density / components), full-graph and
malicious-subgraph centrality (degree / PageRank / betweenness), and community
structure (count / max maliciousness ratio / entropy).

---

## Rule knowledge base

`rules/malicious_rules.json` (v3.0) is the curated knowledge base of 60
malicious-behavior patterns used by stage 3. Each rule carries a `rule_id`
(category-prefixed, e.g. `DT-008`), a description, and a `pdcg_pattern`
matched against CALL / ARGUMENT nodes of the PDCG.

The rules were produced offline with an LLM and manually curated. The artifact
includes helper scripts under `LLM_GEN/` for extraction / consolidation and a
rule evaluation script, but not the original closed-model generation pipeline.

---

## Dataset

`datasets/MacPacDetor.csv` is the labeled feature dataset (MalnpmDB): one row
per package with the 87 features described above plus a `label` column
(`1` = malicious, `0` = benign). It can be used directly to reproduce the
classification experiments without re-running stages 0–3.

The `datasets/monitor_result/` directory contains deployment-time datasets used
for real-world evaluation and continual-learning analysis.

---

## Citation

If you use this artifact, please cite the accompanying paper. (BibTeX will be
added upon publication.)
