# Conformance corpus - provenance and licence

This directory (`tests/conformance/`) is the **committed golden corpus** for
the dual-path conformance oracle (`tools/conformance_oracle.py`), which is
M2 exit criterion ⑤: *the conformance oracle runs on the corpus with zero
unexplained divergences*. It is deliberately small, pinned and committed so
the gate can run offline in CI.

## 1. Third-party rules (20 files)

| | |
|---|---|
| Source | <https://github.com/SigmaHQ/sigma> (upstream files under `rules/`) |
| Pinned commit | `8a4813404ea3074890e0cda9272d4d1a8b2941d6` |
| Licence | **Detection Rule License (DRL) 1.1** - SPDX `DRL-1.1`, text: <https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md> |
| Files | committed **verbatim** (byte-identical to upstream); `tests/conformance/expected.json` records each file's `sha256` so any drift fails the gate |
| Layout | upstream's own directory structure (`rules/windows/...`, `rules/network/zeek/...`, `rules/linux/...`) is preserved so a re-fetch can be diffed |

Upstream's own `LICENSE` states: *"The rules contained in the SigmaHQ
repository are released under the Detection Rule License (DRL) 1.1."*

### What DRL 1.1 requires of this project

DRL 1.1 is MIT-based and explicitly permits distribution, modification,
private and commercial use. It requires two things:

1. **License and copyright notice** - satisfied by this file, which names the
   licence, links its text and states that the rules are the work of the
   SigmaHQ authors.
2. **Author attribution** - every rule file keeps its upstream `author:` field
   untouched, `tests/conformance/expected.json` copies that `author` into the
   machine-readable manifest, and any view that *shows matches produced by
   these rules* (findings list, evidence export, oracle report) must surface
   the rule's author alongside the match. Do not strip `author:` from a rule
   file and do not add rules here whose authorship cannot be named.

DRL 1.1 imposes **no** obligation to publish, no copyleft on the code that
executes the rules, and no restriction on use inside a closed product - the
attribution obligation travels with the *rules and their matches*, not with
Sentinel.

### Re-fetching (deliberately not run in CI)

```powershell
git clone https://github.com/SigmaHQ/sigma research/work/_stage1_work/sigma-rules
git -C research/work/_stage1_work/sigma-rules checkout 8a4813404ea3074890e0cda9272d4d1a8b2941d6
```

The checkout stays gitignored (D6-009); only the 20 selected files are
committed, with their shas pinned in `expected.json`.

## 2. Sentinel-authored rules (3 files)

`rules/sentinel/*.yml` are **written for this project**, carry
`author: Sentinel` and `tags: [conformance.t-c]`, and are not copies of any
third-party work. They exist because the pinned SigmaHQ corpus contains no
rule exercising the listed modifiers, so the oracle would otherwise compare
nothing:

| File | Covers |
|---|---|
| `conformance_numeric_comparisons.yml` | `gt`, `gte`, `lt`, `lte` (zero occurrences upstream at the pinned commit) |
| `conformance_neq_exists.yml` | `neq`, `exists` (zero occurrences upstream at the pinned commit) |
| `conformance_case_modifiers.yml` | `cased`, `i` (upstream uses them only inside rules that are native-only for other reasons) |

These three are the project's own work; they may be reused under this
repository's licence.

## 3. What is *not* here

- **No SigmaHQ checkout** is committed - only the 20 selected rule files.
- **No EVTX / packet capture / dataset** is committed (D6-009, §6.3). The
  oracle's events are the project's own `tests/fixtures/canonical_events/*.yaml`
  plus events synthesized deterministically from each rule's own selections;
  `--evtx` can add a locally fetched sample but is never required by CI.
- **No third-party rule pack is required to run the gate.** CI must not
  clone or download anything to execute `tests/integration/test_conformance_oracle.py`.
