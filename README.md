# PDCG-RuleDet

A static analysis framework for detecting malicious NPM packages. It transforms
JavaScript source into a **Package Dependency & Call Graph (PDCG)**, matches a
curated knowledge base of malicious-behavior rules, and produces an
**87-dimensional feature vector** (60 rule-matching + 27 graph-structure
features) per package for downstream classification.

This is the open-access artifact accompanying the paper.

---

## Pipeline overview

```
 .js source ──▶ (1) AST ──▶ (2) PDCG ──▶ (3) Features (88-dim)
                                              ├─ 61 rule-matching features
                                              └─ 27 graph-structure features
```

| Stage | Directory | Entry point | Runtime |
|-------|-----------|-------------|---------|
| 1. AST generation | `1_ast_generation/` | `generate_ast.py` | Python + Node.js (`@babel/parser`) |
| 2. PDCG construction | `2_pdcg_generation/` | `ast_simplifier.py` (`PDCGAnalyzer`) | Python |
| 3. Feature extraction | `3_feature_extraction/` | `feature_extractor.py` | Python |

---

## Repository layout

```
PDCG-RuleDet/
├── 1_ast_generation/
│   ├── generate_ast.py            # JS -> AST (.ast.json)
│   ├── package.json               # Node dependency: @babel/parser
│   └── js/
│       ├── babel_parser_bridge.js # Node bridge invoked per file
│       └── beautify_code.js
├── 2_pdcg_generation/
│   └── ast_simplifier.py          # AST -> PDCG (.pdcg.json), class PDCGAnalyzer
├── 3_feature_extraction/
│   └── feature_extractor.py       # PDCG + rules -> 87-dim feature CSV
├── rules/
│   └── malicious_rules.json       # 60-rule malicious-behavior knowledge base
├── datasets/
│   └── MacPacDetor.csv            # labelled 87-dim feature dataset (MalnpmDB)
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# Python side (stages 2 & 3)
pip install -r requirements.txt

# Node side (stage 1, required for AST generation)
cd 1_ast_generation
npm install            # installs @babel/parser
cd ..
```

Requirements: Python ≥ 3.9, Node.js ≥ 16.

---

## Usage

The three stages are run independently. Below, `INPUT` is a directory holding
one or more unpacked NPM package folders (each containing `.js` files).

### Stage 1 — AST generation

```bash
python 1_ast_generation/generate_ast.py \
    --mode direct \
    --input-dir  /path/to/INPUT \
    --output-dir /path/to/AST_OUT
```

Produces one `*.ast.json` per source file under `AST_OUT`.

### Stage 2 — PDCG construction

`ast_simplifier.py` exposes `PDCGAnalyzer`; convert each AST to a PDCG:

```python
from ast_simplifier import PDCGAnalyzer
import json, pathlib

analyzer = PDCGAnalyzer()
for ast_file in pathlib.Path("AST_OUT").rglob("*.ast.json"):
    pdcg = analyzer.analyze_pdcg_from_ast(str(ast_file))
    out = ast_file.stem.replace(".ast", "") + ".pdcg.json"
    json.dump(pdcg, open(pathlib.Path("PDCG_OUT") / out, "w"))
```

### Stage 3 — Feature extraction

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

The output CSV contains, per package: `rule_*` (60 columns) + 27 graph-feature
columns. Pass `--rules rules/malicious_rules.json` if running from another
directory.

---

## The 87 features

**Rule-matching (60):** one count column per rule in
`rules/malicious_rules.json`, organised into five behavioural categories —
`IG` Information Gathering, `DT` Data Transmission, `DE` Data Encoding,
`PE` Payload Execution, `SP` Special Patterns.

**Graph-structure (27):** malicious-node statistics, per-category ratios,
internal connectivity (edges / density / components), full-graph and
malicious-subgraph centrality (degree / PageRank / betweenness), and community
structure (count / max maliciousness ratio / entropy).

---

## Rule knowledge base

`rules/malicious_rules.json` (v3.0) is the curated knowledge base of 60
malicious-behaviour patterns used by stage 3. Each rule carries a `rule_id`
(category-prefixed, e.g. `DT-008`), a description, and a `pdcg_pattern`
matched against CALL / ARGUMENT nodes of the PDCG. The rules were produced
offline with an LLM and manually curated; the generation script is not part of
this artifact.

---

## Dataset

`datasets/MacPacDetor.csv` is the labelled feature dataset (MalnpmDB): one row
per package with the 87 features described above plus a `label` column
(`1` = malicious, `0` = benign). It can be used directly to reproduce the
classification experiments without re-running stages 1–3.

---

## Citation

If you use this artifact, please cite the accompanying paper. (BibTeX to be
added upon publication.)
