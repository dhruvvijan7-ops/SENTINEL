# LIGHT-HIDS (arXiv:2509.13464v1) — Primary-Source Research Report

**Date of report:** 2026-10-08
**Scope:** Stage-1 landscape study of a Windows-first offline security backend ("Sentinel"). This report establishes, from primary sources only, what the LIGHT-HIDS paper actually says — identity, datasets, input representation, trace collection, architecture, quantitative claims, Windows applicability, artifact availability, and reporting gaps — and verifies specific assertions already made by a downstream deliverable.
**Research only:** no application code was written or modified.

## Evidence rules applied (strict)

- **Primary sources only.** The arXiv paper (HTML full text + abstract page) is the primary source. Official LID-DS repository/wiki pages are primary sources for LID-DS facts. Author-maintained homepage and the public GitHub API are primary sources for artifact-availability checks.
- **Every factual claim is labeled** `VERIFIED` / `INFERRED` / `UNVERIFIED`.
- **Every claim carries provenance:** a source key `[S#]` resolving to a full URL in the Source list below (all **accessed 2026-10-08**), or an explicit "not stated in paper (UNVERIFIED)".
- **Numbers** carry provenance or are marked `UNVERIFIED`.
- **Quotes** are marked as quotes, kept short (≤15 lines each).
- Absence of a fact in the paper is reported as **"not stated in paper (UNVERIFIED)"** — never guessed.

### Source list (all URLs accessed 2026-10-08)

- **[S1]** Full paper HTML: https://arxiv.org/html/2509.13464v1
  - Figure images: https://arxiv.org/html/2509.13464v1/framework.png ; https://arxiv.org/html/2509.13464v1/bruteforce_metrics.png ; https://arxiv.org/html/2509.13464v1/sql_metrics.png
- **[S2]** arXiv abstract page: https://arxiv.org/abs/2509.13464
- **[S3]** arXiv non-exclusive licence text: https://arxiv.org/licenses/nonexclusive-distrib/1.0/
- **[S4]** GitHub REST API searches (2026-10-08): https://api.github.com/search/repositories?q=LIGHT-HIDS+in:name ; https://api.github.com/search/repositories?q=LIGHT-HIDS+DeepSVDD ; https://api.github.com/search/repositories?q=2509.13464 ; https://api.github.com/search/repositories?q=%22Onat+Gungor%22 ; https://api.github.com/search/repositories?q=LID-DS+DeepSVDD ; https://api.github.com/search/users?q=%22Onat+Gungor%22+in:fullname ; https://api.github.com/users/onatucsd/repos?per_page=100
- **[S5]** Official LID-DS repository README: https://github.com/LID-DS/LID-DS ; wiki scenario list: https://raw.githubusercontent.com/wiki/LID-DS/LID-DS/Scenarios.md ; recording-framework wiki: https://github.com/LID-DS/LID-DS/wiki/LID-DS-Recording-Framework:-Documentation-and-Installation ; scenario READMEs: https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/Bruteforce_CWE-307/README.md and https://raw.githubusercontent.com/LID-DS/LID-DS/master/scenarios/CWE-89-SQL-injection/README.md
- **[S6]** First author's homepage: https://onatucsd.github.io/
- **[S7]** First author's GitHub profile: https://github.com/onatucsd
- **[S8]** GitHub profile `rion-research` (contains an "Ishaan Kale"): https://github.com/rion-research

---

## §LIGHT-HIDS-1 — Paper identity, venue, and datasets

**Title (exact):** "LIGHT-HIDS: A Lightweight and Effective Machine Learning-Based Framework for Robust Host Intrusion Detection" — `VERIFIED` [S1 title; S2].

**Authors:** Onat Gungor, Ishaan Kale, Jiasheng Zhou, Tajana Rosing — `VERIFIED` [S1; S2]. Gungor and Kale carry a footnote: "Both authors contributed equally to this research." — `VERIFIED` (quote) [S1]. All four affiliations are *Department of Computer Science and Engineering, University of California, San Diego*, contact `{ogungor, ikale, rjzhou, tajana}@ucsd.edu` — `VERIFIED` [S1].

**arXiv dates:**
- arXiv identifier/version stamp in the paper: "arXiv:2509.13464v1 [cs.CR] 16 Sep 2025" — `VERIFIED` (quote) [S1].
- Submission history: "[v1] Tue, 16 Sep 2025 19:02:23 UTC (775 KB)"; **only v1 exists** — `VERIFIED` [S2].
- Date line printed in the paper: "16 Sept 2025" — `VERIFIED` [S1].
- DOI: https://doi.org/10.48550/arXiv.2509.13464 — `VERIFIED` [S2].

**Venue / ICMLA'25 acceptance — where does it say that?:**
- The paper **body never mentions ICMLA** (0 occurrences of "ICMLA" in the full HTML text) — `VERIFIED` [S1 full-text search, conducted 2026-10-08].
- The acceptance is stated **only in the arXiv abstract-page Comments field**: "Accepted by The 24th IEEE International Conference on Machine Learning and Applications (ICMLA'25)" — `VERIFIED` (quote) [S2].
- Corroboration (author-maintained): first author's homepage news list contains "[09/25] Two papers accepted in ICMLA 2025" — `VERIFIED` (quote) [S6]; the homepage does **not** name LIGHT-HIDS next to that line, so linking that line to this specific paper is `INFERRED`.
- The camera-ready/IEEE proceedings version was not retrieved for this report — `UNVERIFIED`.

**Datasets used:**
- Two subsets from "the Leipzig Intrusion Detection Data Set (LID-DS)": (1) **brute-force attacks**, (2) **SQL injection attacks** — `VERIFIED` [S1 §IV-A2].
- Paper citation [25] for LID-DS is "Dataset report: LID-DS 2021" — `VERIFIED` [S1 references]; therefore the dataset version being LID-DS **2021** is `INFERRED` (the body text says only "LID-DS").
- Exact LID-DS scenario identifiers (e.g., `Bruteforce_CWE-307`, `CWE-89-SQL-injection`) are **not stated in paper (UNVERIFIED)**; mapping the two subsets to those official LID-DS-2021 scenario names is `INFERRED` (names align one-to-one with the official scenario list) [S5].
- Only LID-DS is used — no other dataset appears — `VERIFIED` [S1 §IV-A2].

**Dataset size counts (samples per class):** **not stated in paper (UNVERIFIED).** No sequence counts, no class counts, no split sizes appear anywhere in the full text (searched for counts adjacent to "sequence/records/samples/train/valid/test") — `VERIFIED` absence [S1]. The paper states only qualitatively:

> **Quote (verbatim, §III-A):** "the training and validation sets contain only normal sequences, while the test set includes both normal and anomalous samples to enable comprehensive evaluation of detection performance." [S1]

Two percentages appear in §IV-A2 — "approximately 22% of attacks on edge gateways" (brute force, attributed to ref [26]) and "26% of edge threats" (SQL injection, attributed to ref [25]) — these are **threat-prevalence statistics from cited literature, not dataset sizes** — `VERIFIED` as stated-with-attribution [S1].

---

## §LIGHT-HIDS-2 — Input representation

**Integer-mapped system-call name sequences — CONFIRMED:**

> **Quote (verbatim, §III-A):** "Each unique system call name was then tokenized by mapping it to a distinct integer ID, producing a numerical representation suitable for neural network input." [S1]

Also §III: "Integer-mapped system call sequences are first processed by a neural network-based feature extractor…" — `VERIFIED` (quote, abridged) [S1]. Preprocessing discards "auxiliary metadata such as process IDs and timestamps" — `VERIFIED` [S1 §III-A].

**Vocabulary size:** **not stated in paper (UNVERIFIED)** — the word "vocabulary" does not occur in the full text; no token-count/embedding-table size is given — `VERIFIED` absence [S1].

**Sequence / window length:** **not stated in paper (UNVERIFIED)** — no input-sequence length, max length, padding, or truncation policy is given ("window" does not occur in the full text) — `VERIFIED` absence [S1].

**Stride / overlap:** **not stated in paper (UNVERIFIED)** — "stride" does not occur in the full text; no sliding-window specification is given — `VERIFIED` absence [S1]. The only shift-related statement concerns **baseline** training, not LIGHT-HIDS input: input-target pairs "constructed by shifting system call sequences by one position" for the language-modeling baselines (WaveNet/LSTM/CNNRNN) — `VERIFIED` [S1 §IV-A4].

**Embedding dimension:** **not stated in paper (UNVERIFIED)** — §III-B refers to "a high-dimensional embedding space representing each system call" with no number — `VERIFIED` absence [S1].

---

## §LIGHT-HIDS-3 — Trace collection mechanism and training-data OS

**How traces were collected:** the paper only says:

> **Quote (verbatim, §III-A):** "We first extracted the system call traces, discarding auxiliary metadata such as process IDs and timestamps." [S1]

- No collection tool is named: **strace, eBPF, auditd, sysdig** — 0 occurrences of "strace", "eBPF", "bpf", "audit", "sysdig" in the full text — `VERIFIED` absence [S1 full-text search 2026-10-08]. The mechanism is **not stated in paper (UNVERIFIED)**.
- Whether the authors re-collected traces or used LID-DS recordings as shipped: **not stated in paper (UNVERIFIED)**.

**Training-data OS (in the paper's text):** **not stated in paper (UNVERIFIED)** — the word "Linux" has **0 occurrences in the paper body text** — `VERIFIED` absence [S1 full-text search 2026-10-08].

**However, the framework figure depicts Linux:** Figure 1 (image file `framework.png`) shows a monitor labelled **"Linux host"** with a Tux penguin feeding "System call traces" into preprocessing — `VERIFIED` [S1 figure image: https://arxiv.org/html/2509.13464v1/framework.png, inspected 2026-10-08]. So the OS of the training data appears **only inside a figure**, never in prose — `VERIFIED`.

**What OS LID-DS targets:** **Linux** — `VERIFIED` from official LID-DS sources:
- LID-DS Recording Framework prerequisites are **Sysdig**, **Docker**, and `sudo apt install python3.7`, with `sudo ./install.sh`, `sudo docker …`, and Secure-Boot/sysdig kernel-module notes — [S5 recording-framework wiki].
- Scenario READMEs run victims "in a docker container" and are driven by `sudo python3 main.py …` — [S5 scenario READMEs].
- LID-DS README describes it as a host-based IDS dataset; no Windows support is stated anywhere in the official repo/wiki — `VERIFIED` absence [S5].

**Hardware (not collection):** training on one NVIDIA GTX 2080 Ti; inference on Intel Xeon Gold 6230 (CPU-only) and NVIDIA Jetson Orin NX (16 GB RAM) — `VERIFIED` [S1 §IV-A1].

---

## §LIGHT-HIDS-4 — Architecture and the "75×" claim

### Exact model stack — `VERIFIED` [S1 §III-A–§III-E] unless noted

1. **Input:** integer-mapped system-call name sequences (§III-A).
2. **Embedding:** per-syscall embedding ("high-dimensional embedding space") — dimension not stated (UNVERIFIED).
3. **Encoder:** "a convolutional neural network (CNN) composed of ReLU-activated one-dimensional convolutional (Conv1D) layers, followed by max pooling", reducing the sequence dimension, then a **fully connected layer** projecting filter outputs into the target feature space — **Conv1D encoder CONFIRMED**. Layer count / filters / kernel sizes / latent dimension: **not stated in paper (UNVERIFIED)**.
4. **Training objective for the extractor:** **DeepSVDD** (ref [22], Ruff et al. ICML 2018) — the network is trained to map normal data into a compact hypersphere with jointly optimized radius — `VERIFIED` [S1 §II-B, §III-B].
5. **Compression:** "optimized using TensorFlow Lite (TFLite) compression with quantization, significantly reducing model size and improving inference efficiency" — `VERIFIED` (paraphrase of §III-B) [S1]; **no size numbers given** (see §LIGHT-HIDS-7).
6. **Novelty detector:** **Isolation Forest** (ref [14]) fit on the latent feature vectors produced by the trained extractor — `VERIFIED` [S1 §III-C].
7. **Threshold:** anomaly score cut at **two standard deviations above the mean** of the validation-score distribution (validation = normal only), assuming approximate Gaussianity — `VERIFIED` [S1 §III-D].

**Training flow:** preprocessing → DeepSVDD-trained Conv1D/pooling/FC extractor → generate latent vectors for train/val → fit Isolation Forest on those vectors → threshold from validation scores → classify test sequences — `VERIFIED` [S1 §III].

**Important characterization corrections:**
- The combination **Conv1D + DeepSVDD + Isolation Forest is CONFIRMED**, but it is a **sequential two-stage pipeline** (extractor → detector), **not an ensemble with weighting**. Ensemble weighting / score fusion / voting: **not stated in paper (UNVERIFIED)** — no such mechanism exists in the described framework — `VERIFIED` absence [S1].
- The model is **not an autoencoder**: "autoencoders" appears exactly once in the whole paper, in Related Work (ref [20], generic prior art) — `VERIFIED` [S1 §II-B].

### The "75×" claim — exact meaning and baseline

Three restatements, all `VERIFIED` (quotes) [S1]:

> **Quote (Abstract):** "Experimental results on multiple datasets demonstrate that LIGHT-HIDS consistently enhances detection accuracy while reducing inference time by up to 75× compared to state-of-the-art methods."

> **Quote (§IV-B2, Inference Time):** "Similarly, for SQL Injection, LIGHT-HIDS delivers 75× faster inference than CNNRNN, alongside a 4.23% improvement in F1 score."

> **Quote (Conclusion):** "…improves detection accuracy while reducing inference time by up to 75× compared to state-of-the-art methods…"

**Exact baseline and conditions (Table III):** the "75×" is the **inference-time speedup versus the CNNRNN hybrid HIDS baseline on the SQL-injection subset, on the Intel Xeon Gold 6230 CPU**: LIGHT-HIDS **0.030 s** vs CNNRNN **2.248 s** → printed speedup **74.93×**, rounded to "75×" in prose — `VERIFIED` [S1 Table III]. The abstract/intro/conclusion phrase it as "up to 75× … compared to state-of-the-art methods"; the concrete instance is CNNRNN, which Table II identifies as the best-performing baseline on SQL injection — `VERIFIED` [S1 §IV-B1–2].

**All Table III values — Inference Time (s) and speedup of LIGHT-HIDS** (`VERIFIED` [S1 Table III]; units: seconds as printed):

| Model | Brute Force — Xeon (s) | Speedup | Brute Force — Jetson (s) | Speedup | SQL Injection — Xeon (s) | Speedup | SQL Injection — Jetson (s) | Speedup |
|---|---|---|---|---|---|---|---|---|
| LIGHT-HIDS | 0.004 | – | 0.030 | – | 0.030 | – | 0.293 | – |
| LSTM | 0.016 | 3.61× | 0.420 | 13.90× | 0.113 | 3.76× | 4.310 | 14.70× |
| WaveNet | 0.073 | 16.57× | 0.116 | 3.84× | 0.295 | 9.83× | 0.616 | 2.10× |
| CNNRNN | 0.149 | 33.77× | 1.011 | 33.47× | 2.248 | 74.93× | 10.939 | 37.31× |
| OCSVM | 0.028 | 6.41× | 0.056 | 1.87× | 0.288 | 9.60× | 0.494 | 1.68× |

Prose cross-check: "up to 33.77× faster inference than CNNRNN on the CPU" (brute force) with "F1 score of 0.973 compared to 0.942"; "3.6 to 6.4× faster" than LSTM/OCSVM on brute force; "nearly 10× faster" than OCSVM/WaveNet on SQL — `VERIFIED` (quotes abridged) [S1 §IV-B2].

### Reported metrics and units — `VERIFIED` [S1 §IV-A3, §IV-B1, Tables I–III]

- **Detection metrics:** precision, recall, F1-score (defined in §IV-A3).
- **LIGHT-HIDS F1:** **0.973** (brute force), **0.766** (SQL injection) — `VERIFIED` [S1 Tables I & II].
- **F1 gains vs best-of-category baselines** [S1 Table I]: brute force +1.57% (HIDS: LSTM 0.958), +25.48% (Time-series: COUTA 0.775), +1.85% (Traditional: OCSVM 0.955); SQL injection +4.23% (HIDS: CNNRNN 0.735), +9.03% (Time-series: DeepSVDD 0.702), +4.59% (Traditional: OCSVM 0.732) — `VERIFIED`.
- **F1 gains vs all baselines** [S1 §IV-B1]: brute force "up to 32.74% improvement with an average gain of 16.24%"; SQL injection "up to 40.83% improvement with an average gain of 14.11%" — `VERIFIED` (quotes abridged).
- **Internal inconsistency (both values as printed):** Table I lists the SQL/traditional gain as **4.59%**, Table II lists it as **4.60%** — `VERIFIED` [S1 Tables I, II].
- **Precision and recall numeric values:** shown only as bar charts (Fig. 2a/2b, image files `bruteforce_metrics.png` / `sql_metrics.png`) with **no data labels or numeric table** — exact precision/recall numbers are **not stated in paper (UNVERIFIED)** — `VERIFIED` absence [S1 + figure images inspected 2026-10-08]. Qualitative statement: LIGHT-HIDS has "the highest F1 score across both datasets" and stays "within 0.05 of the top-performing models" where it does not lead (e.g., recall on SQL) — `VERIFIED` (quote, abridged) [S1 §IV-B1].
- **AUC / ROC:** **not reported** ("AUC", "ROC" = 0 occurrences) — `VERIFIED` absence [S1].
- **Latency metric:** reported in **seconds** (Table III, "Time (s)"); definition given in §IV-A3 (see §LIGHT-HIDS-7).
- **Confusion matrices / error bars / variance across runs:** **not reported (UNVERIFIED)** — `VERIFIED` absence [S1].

---

## §LIGHT-HIDS-5 — Windows applicability

- **Does the paper mention Windows at all? NO** — "Windows"/"windows": **0 occurrences** in the full paper HTML text — `VERIFIED` [S1 full-text search, 2026-10-08].
- **Figures:** all three figure images were inspected; none mentions Windows — `VERIFIED` [S1 figure images, inspected 2026-10-08].
- **Also note:** the paper body never says "Linux" either (0 occurrences) — Linux appears **only as a label inside Figure 1** ("Linux host") — `VERIFIED` [S1 + framework.png].
- Therefore: **no Windows experiment, no Windows discussion, no Windows syscall vocabulary, no porting notes anywhere in the paper** — `VERIFIED` absence [S1]. Windows applicability of LIGHT-HIDS is **not stated in paper (UNVERIFIED)**.
- **What OS does LID-DS target?** **Linux** — `VERIFIED` [S5]: LID-DS recording framework requires Sysdig + Docker + `apt install`; scenario victims run in Docker containers; official repo/wiki states no Windows support (absence `VERIFIED`).
- Consequence for a Windows-first backend: the training distribution (LID-DS, Linux syscalls captured via a kernel-level facility) has **no Windows counterpart in the paper** — `VERIFIED` as an absence of evidence; whether the architecture transfers to Windows system-call sequences is an **open question, not addressed (UNVERIFIED)**.

---

## §LIGHT-HIDS-6 — Artifact availability

**Links inside the paper:**
- The full paper HTML contains exactly **two external URLs**, both ordinary references: `https://www.tensorflow.org/lite` (ref [23]) and `https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/jetson-orin/` (ref [24]) — `VERIFIED` [S1 URL extraction, 2026-10-08].
- **No GitHub link, no code link, no data link, no weights/checkpoint link, no project page, no "code availability" statement** — `VERIFIED` absence [S1].
- arXiv's own "Code, Data and Media" widgets on the abstract page are site features, not author-supplied artifacts — `VERIFIED` [S2].

**GitHub searches actually performed (2026-10-08, GitHub REST API) [S4]:**

| Query | Result |
|---|---|
| `LIGHT-HIDS in:name` (repositories) | 2 hits, both unrelated: `sebasruii/light-hids` (created 2024-02-23, last push 2024-03-01, no description) and `ashmalzahra/lightweight-linux-hids` (different, rule-based project) |
| `LIGHT-HIDS DeepSVDD` (repositories) | 0 |
| `LIGHT-HIDS intrusion` (repositories) | 0 |
| `2509.13464` (repositories) | 0 |
| `"Onat Gungor"` (repositories) | 0 |
| `LID-DS DeepSVDD` / `LID-DS IsolationForest HIDS` (repositories) | 0 / 0 |
| `"Onat Gungor" in:fullname` (users) | 1 → `onatucsd` |

- **Author account audit:** GitHub user **`onatucsd`** — name "Onat Gungor", bio "postdoctoral scholar … UCSD", company UCSD, 51 public repositories — contains **no LIGHT-HIDS repository** and nothing matching this paper (full repo list retrieved) — `VERIFIED` [S4 https://api.github.com/users/onatucsd/repos?per_page=100 ; S7].
- **Other authors:** GitHub users matching "Ishaan Kale" include `rion-research` (bio: team from VIT Pune incl. Ishaan Kale) with **0 public repositories**; whether that is the paper's co-author is `UNVERIFIED` [S8]. Accounts for the other co-authors could not be authoritatively identified — `UNVERIFIED`.

**Conclusion:** **No code, weights, data, or trained-model artifact for LIGHT-HIDS was found** — `VERIFIED` to the extent of: (a) zero links in the paper, (b) zero matching repositories across seven GitHub repository/user searches, (c) zero matching repository among the first author's 51 public repos.

**Verification limits (stated honestly):** unauthenticated GitHub **code** search returned `HTTP 401 Unauthorized`, so a code-content search was not performed; private/unreleased repositories cannot be ruled out — `UNVERIFIED` whether an unreleased/private artifact exists.

**Licence:** see assertion I — arXiv non-exclusive licence only; **no separate code licence exists because no code is released** — `VERIFIED` [S2, S3, S1].

---

## §LIGHT-HIDS-7 — Reporting gaps (what is NOT reported)

Each item: **not stated in paper (UNVERIFIED)** — `VERIFIED` absence via full-text search of [S1] on 2026-10-08 unless noted.

**Input/data parameters**
1. Vocabulary size (number of distinct system-call tokens) — absent.
2. Sequence/window length, padding/truncation policy — absent.
3. Stride/overlap of windows — absent.
4. Train/validation/test split sizes, per-class sample counts, split ratios — absent (see §LIGHT-HIDS-1).
5. Which exact LID-DS scenarios/IDs and which LID-DS release were used — only "LID-DS" + citation to the LID-DS 2021 report (`INFERRED`).

**Model hyperparameters**
6. Embedding dimension — absent.
7. Conv1D details: number of layers, filters, kernel sizes, strides, padding; max-pool sizes; fully-connected width; final latent/feature dimensionality — absent.
8. DeepSVDD nuances: simple vs soft-boundary objective, center `c` initialization/fixing, radius parameter, weight decay, bias-handling — absent (only the general description in §III-B).
9. Isolation Forest hyperparameters: `n_estimators`, `max_samples`, `contamination`, random state — absent.
10. Optimizer, learning rate, batch size, epochs, early stopping, TensorFlow/DeepOD library versions — absent.

**Latency metric definition**
11. A definition **is** given — `VERIFIED` [S1 §IV-A3]:

> **Quote (verbatim, §IV-A3):** "Inference Time: The elapsed time from inputting system call sequences to generating anomaly predictions, reflecting the model's computational overhead."

    But the **aggregation basis is not stated (UNVERIFIED):** whether Table III seconds are per-sequence, per-batch, or totals over a test set; number of sequences timed; batch size; warm-up/repetitions/statistic used; whether preprocessing/tokenization is included; thread count/BLAS settings — all absent.

**Model size / deployment**
12. Model size — **no parameter counts, no byte/KB/MB figures, no TFLite file size anywhere**; only the qualitative claim "significantly reducing model size" (§III-B) — absent (`VERIFIED` absence).
13. Energy consumption on Jetson — discussed qualitatively only, no numbers — absent.
14. Quantization scheme (dynamic-range/int8/float16) and accuracy impact of compression — absent.

**Evaluation**
15. Numeric precision/recall values (figures only, no data labels) — absent (see §LIGHT-HIDS-4).
16. AUC/ROC, confusion matrices, per-class support, error bars/multi-run variance, threshold sensitivity analysis — absent.
17. Reproducibility artifacts: code, seeds, config files, dataset counts — absent (see §LIGHT-HIDS-6).

**What IS reported (for contrast):** hardware (GTX 2080 Ti / Xeon Gold 6230 / Jetson Orin NX 16 GB) [S1 §IV-A1], threshold rule (mean + 2σ) [S1 §III-D], F1 tables [S1 Tables I–II], inference times in seconds [S1 Table III] — all `VERIFIED`.

---

## Downstream assertion check

| ID | Assertion | Verdict | Correction / precise wording |
|---|---|---|---|
| A | Paper is arXiv:2509.13464v1, dated 2025-09-16, accepted ICMLA 2025 | **CONFIRMED** (with provenance note) | v1 submitted **16 Sep 2025 19:02:23 UTC**, only version [S2]; paper prints "arXiv:2509.13464v1 [cs.CR] 16 Sep 2025" and "16 Sept 2025" [S1]. ICMLA'25 acceptance is stated **only in the arXiv abstract-page Comments** ("Accepted by The 24th IEEE International Conference on Machine Learning and Applications (ICMLA'25)") [S2] — the paper body never says "ICMLA"; author homepage news "[09/25] Two papers accepted in ICMLA 2025" corroborates [S6]. |
| B | Input = integer-mapped system-call name sequences; collection mechanism, window length, vocabulary, and OS of training data are all NOT stated in the paper | **CONFIRMED (one qualification)** | Integer-mapping confirmed verbatim §III-A [S1]. Collection mechanism (strace/eBPF/etc.), window length, vocabulary size: **not stated (UNVERIFIED)** — 0 occurrences of strace/eBPF/vocabulary/window [S1]. **Qualification:** the OS is not stated in *prose*, but **Figure 1 explicitly labels the trace source "Linux host"** (image) [S1 framework.png] — so "OS not stated" should read "OS not stated in body text; Linux shown only in Figure 1". LID-DS itself targets Linux [S5]. |
| C | The paper NEVER mentions Windows (Linux-only framing via LID-DS) | **CONFIRMED (with refinement)** | "Windows" = **0 occurrences** in full text; all 3 figures inspected, no Windows [S1]. Refinement: the paper's body never says "Linux" either (0 occurrences); Linux appears **only as the Figure 1 "Linux host" label**. Linux-only framing therefore comes from Figure 1 + LID-DS (official repo/wiki: Sysdig/Docker/apt) [S5], not from body prose. |
| D | No code/weights/data released anywhere | **CONFIRMED (within search limits)** | No code/data/weights links in the paper (only 2 URLs: tensorflow.org/lite, nvidia.com) [S1]. 7 GitHub repo/user searches → 0 relevant matches; first author's 51 public repos contain no LIGHT-HIDS repo (`onatucsd`) [S4, S7]. Caveat: unauthenticated GitHub **code** search returned 401; private/unreleased artifacts cannot be excluded — residual `UNVERIFIED`. |
| E | Architecture = Conv1D + DeepSVDD + Isolation Forest (confirm exact combination and training flow) | **CONFIRMED (characterization corrected)** | Combination correct: ReLU **Conv1D + max-pool + FC** extractor trained under **DeepSVDD**, then **TFLite quantization**, then **Isolation Forest** fit on the extractor's latent vectors, decision by **mean+2σ threshold** (§III-B–E) [S1]. **Correction:** it is a *sequential two-stage pipeline*, **not a weighted ensemble** — no ensemble weighting exists in the paper (`not stated / absent`, UNVERIFIED). It is also **not an autoencoder** (word appears once, in related work only). |
| F | Datasets = LID-DS subsets only (brute-force + SQLi), with no dataset size counts stated | **CONFIRMED** | Two LID-DS subsets — brute force and SQL injection — are the only datasets (§IV-A2) [S1]. **No sample counts / class counts / split sizes anywhere** (not stated in paper, UNVERIFIED). Add: LID-DS version = 2021 is `INFERRED` from citation [25]; exact scenario IDs are not named (`Bruteforce_CWE-307` / `CWE-89-SQL-injection` mapping `INFERRED`) [S5]. |
| G | A "75×" claim exists — report exact meaning and baseline | **CONFIRMED** | Meaning: **inference-time speedup**, not size/accuracy. Abstract/conclusion: "reducing inference time by up to 75× compared to state-of-the-art methods"; §IV-B2: "for SQL Injection, LIGHT-HIDS delivers 75× faster inference than CNNRNN" [S1]. Exact instance: **SQL-injection subset, Intel Xeon Gold 6230 CPU: LIGHT-HIDS 0.030 s vs CNNRNN 2.248 s = 74.93×** (Table III), rounded to "75×" in prose. Baseline = **CNNRNN** HIDS hybrid (best SQL baseline per Table II). |
| H | Latency metric definition and model size are not reported | **PARTIALLY CONTRADICTED → treat as CONTRADICTED on the latency half** | **Latency definition IS reported** (§IV-A3): "The elapsed time from inputting system call sequences to generating anomaly predictions…" [S1]. What is *not* reported is the **aggregation basis** (per-sequence vs aggregate), sequence count, batch size, repetitions, included preprocessing — `not stated (UNVERIFIED)`. **Model size half CONFIRMED:** no parameter counts or byte/KB/MB figures anywhere; only qualitative "significantly reducing model size" (§III-B) [S1]. |
| I | arXiv licence = arXiv non-exclusive licence (standard arXiv grant) — no separate code licence exists | **CONFIRMED** | Paper HTML footer: "License: arXiv.org perpetual non-exclusive license" [S1]; abstract page "[view license]" → http://arxiv.org/licenses/nonexclusive-distrib/1.0/ [S2], whose text reads "I grant arXiv.org a perpetual, non-exclusive license to distribute this article" [S3]. No code licence exists because no code is released (assertion D) [S1, S4]. |

---

## Open questions / not verified

1. **Sample counts per class and split sizes** for both LID-DS subsets — absent from the paper; could only be obtained from the LID-DS recordings themselves (not retrieved) — `UNVERIFIED`.
2. **Whether Table III "Time (s)" values are per-sequence or aggregate**, and the exact timing protocol (batch size, repetitions, warm-up, whether tokenization is inside the timed window) — `not stated in paper (UNVERIFIED)`.
3. **Exact precision/recall numbers** — readable only as unlabelled bars in Fig. 2a/2b; not tabulated — `UNVERIFIED`.
4. **Which LID-DS 2021 scenarios were used** — paper says only "brute-force" and "SQL injection"; mapping to `Bruteforce_CWE-307` and `CWE-89-SQL-injection` is `INFERRED`, not stated.
5. **Whether an ICMLA 2025 camera-ready version** differs from arXiv v1 (added Windows content, added numbers, added code link) — IEEE proceedings version not retrieved — `UNVERIFIED`.
6. **Existence of private/unreleased code** — GitHub code-content search requires authentication (401); only repository-level and author-repo searches were possible — `UNVERIFIED`.
7. **Co-author accounts on GitHub** — only `onatucsd` (first author, identity corroborated by UCSD bio) was authoritatively matched; the `rion-research` "Ishaan Kale" may or may not be the co-author — `UNVERIFIED`.
8. **Whether LIGHT-HIDS transfers to Windows system-call sequences** (different syscall surface, different capture APIs such as ETW) — completely unaddressed by the paper — `UNVERIFIED`.
9. **Energy figures for Jetson** — mentioned as a trade-off qualitatively, no numbers reported — `not stated in paper (UNVERIFIED)`.
10. **Reproducibility without artifacts** — all hyperparameters listed in §LIGHT-HIDS-7 are missing, so independent reimplementation would require guessed values — `UNVERIFIED` whether these will ever be released.

---

*Report compiled 2026-10-08 from primary sources listed above. All URLs accessed 2026-10-08.*
