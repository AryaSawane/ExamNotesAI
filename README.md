https://drive.google.com/file/d/1dEdUntS_RWdB_7GN6zu_XZVmgf9Ls9C4/view?usp=drivesdk

# final.ipynb — Per-User, Per-Hour AD Behavioural Baseline & Risk Scoring

A plain-language guide to what the notebook does, cell by cell.

---

## 1. What this project is, in one paragraph

We have 13 days of Windows Security and Sysmon logs from a small Active Directory network
(8 people, 12 machines, ~811,000 events). The first 7 days are known to be normal. We learn
what "normal" looks like **for each person, at each hour of the day**, in 10-minute slices.
Then we replay the last 6 days through the same machinery and give every 10-minute slice a
**risk score between 0 and 1**, plus a written explanation of why it scored that way. Finally
we check the answers against `GROUND_TRUTH.md`, which lists the real attack.

The system does **not** claim "this is malicious". It answers a narrower, more honest question:
*how different is this from what this person normally does at this time of day?*

---

## 2. How to run it

```
cd "the folder containing events.jsonl"
jupyter notebook final.ipynb          # then Run All
```

Needs: `pandas`, `numpy`, `scipy`, `scikit-learn`, `matplotlib`, `pyarrow`.

Files that must be in the same folder:

| File | What it is |
|---|---|
| `events.jsonl` | the raw log, one JSON event per line (~795 MB) |
| `GROUND_TRUTH.md` | the scenario's answer key — used **only** for scoring the results, never for detection |

First run takes a few minutes because it parses the 795 MB log. It writes
`cache/events_raw.parquet` (28 MB), so every later run starts in seconds.
Results land in `baseline_output/`.

---

## 3. Key decisions you should know before reading the code

**Everything is UTC.** Every timestamp in `events.jsonl` is UTC and every timestamp in
`GROUND_TRUTH.md` is written with a `UTC` suffix. The only mention of another zone in that file
is one header line describing its own suggested split. No clock is shifted anywhere in the
notebook — `hour` means UTC hour.

**The split.**

```
train (learn normal)  2026-07-28 .. 2026-08-03      7 calendar days
test  (score)         2026-08-04 .. 2026-08-09      6 calendar days
```

The first ground-truth attack event is `2026-08-04 21:40:06 UTC`, so the whole attack chain
falls inside the test period.

**Capture coverage.** The log starts at `18:30` on the first day and stops at `18:30` on the
last. So the first and last day are only partly recorded. The notebook detects this from the
data and marks those windows `has_telemetry = False`. They are skipped, because "the sensor was
off" and "the user was idle" are different facts. As a result, UTC hours 00–17 get **36**
baseline observations and hours 19–23 get **42** (hour 18 gets 39). The notebook prints this
table rather than pretending it is a flat 42 everywhere.

**Empty windows are kept.** A 10-minute slice where a person did nothing is a real fact about
them and stays in the data as a row of zeros. Only the out-of-capture windows are dropped.

**No cheating.** Nothing from `GROUND_TRUTH.md` is used to detect anything. No attacker IP, no
malicious filename, no attack command line appears in the detection path. Those strings only
appear in Section 20, which is grading.

---

## 4. How the detector works, without maths

Every 10-minute slice for every person gets **five scores**, each answering a different question.

| Score | The question it asks | What sets it off |
|---|---|---|
| `s_stat` | Is there **more of something** than this person usually does at this hour? | volume spikes |
| `s_nov` | Is this person doing something they have **never done before**? | a new program, a new machine, a new destination |
| `s_act` | Has a **whole category** of behaviour switched on for the first time? | first ever LSASS access, first ever service install |
| `s_rare` | Did an **event type** fire that is structurally rare in this whole network? | account created, security log cleared |
| `s_ml` | Does the overall shape look unlike any training slice? | multivariate oddity |

They are combined so that:

* **any one signal on its own is capped.** A pure volume spike can never exceed 0.55 → *Medium*.
  Somebody working late is never promoted to *High* on volume alone. This is the main defence
  against false alarms.
* **evidence that agrees compounds.** A slice that is simultaneously novel, activating a new
  capability, and firing a rare event ID heads toward 1.0.

Risk bands: `NORMAL < 0.25`, `LOW < 0.45`, `MEDIUM < 0.60`, `HIGH < 0.80`, `CRITICAL ≥ 0.80`.

**The alert threshold is not guessed.** Each baseline day is re-scored against a baseline built
from the *other* baseline days (leave-one-day-out). That gives 7,176 honest "this is normal"
scores. The threshold is read off that distribution at the point where the alert rate meets the
configured budget of 0.35 alerts per user per day. It came out at **0.576**, and it was fixed
before any test day was looked at.

---

## 5. Cell-by-cell guide

Cell numbers count from 0 at the top of the notebook. **MD** = text, **CODE** = code.

### Sections 01–02 — Setup

| Cell | Type | What it does |
|---|---|---|
| 0 | MD | Title, what the notebook builds, the four design commitments |
| 1 | MD | Explains the UTC decision and the capture-coverage problem |
| **2** | CODE | **The only cell you normally edit.** Paths, timezone, window length, train/test dates, the five fusion weights, risk bands, alert budget |
| 3 | MD | — |
| 4 | CODE | Imports, plus the chart styling (colour palette, `finish()` helper that puts recessive gridlines on every plot) |

### Section 03 — Load the data

| Cell | Type | What it does |
|---|---|---|
| 5 | MD | Why the loader is written the way it is |
| 6 | CODE | `load_events()` — streams the 795 MB JSONL in 100k-row chunks, keeps only the 87 fields that carry identity or behaviour, writes `cache/events_raw.parquet`, reads it back. Chunking matters: loading all 811k records at once needs several GB |

### Section 04 — What is in the data

| Cell | Type | What it does |
|---|---|---|
| 7 | MD | — |
| 8 | CODE | Totals, time range, Security vs Sysmon split, events per UTC day, missing-value profile of the identity fields |
| 9 | CODE | **Figure**: events per day (blue = train, orange = test) and events by hour of day |

### Section 05 — Which Event IDs exist

| Cell | Type | What it does |
|---|---|---|
| 10 | MD | Explains which field carries the *actor* for each family of events, and why |
| 11 | CODE | Builds the event catalogue table: every Event ID present, its volume, its actor field, how it will be attributed, and what it means |
| 12 | CODE | **Figure**: event volume by ID on a log scale |

`SECURITY_ACTOR_FIELD` and `SYSMON_ACTOR_FIELD` in cell 11 are the extension point — add an
Event ID there and the whole pipeline picks it up.

### Section 06 — Timestamps and coverage

| Cell | Type | What it does |
|---|---|---|
| 13 | MD | — |
| 14 | CODE | Adds `date`, `hour`, `win` (10-minute window start). Computes `CAPTURE_START` / `CAPTURE_END` and prints how many windows have no sensor coverage. Also counts exact duplicate records (there are none) |

### Sections 07–08 — Who did it? (user attribution)

This is the part most projects get wrong, so it is done in tiers and then **measured**.

| Cell | Type | What it does |
|---|---|---|
| 15 | MD | The tier table: A1 / A2 / B / C |
| 16 | CODE | **Tier A1** — Sysmon events carry `User` (or `SourceUser` for events 8/10). **Tier A2** — Security events carry the actor field from cell 11. Domain prefixes like `CORP\` are stripped |
| 17 | MD | Explains the logon-session table and the process-lifetime table |
| 18 | CODE | Builds the 4624 logon-session table, collapses it to one row per `(Computer, LogonId)`, and **validates** the `LogonId + Computer + time` join against Sysmon's own `User` field. Result: 99.3% joinable, **100% agreement, 0 ambiguous keys**. The direct field is still preferred because it covers 100% |
| 19 | CODE | **Tier B** — builds a process-lifetime interval table from Sysmon 1 (start) and 5 (exit), then attributes Security **5156** by `(Computer, PID)` with the event time inside the process's lifetime. PID reuse is handled by the time containment test |
| 20 | MD | — |
| 21 | CODE | The attribution report, and the **WARNINGS** block listing everything that could not be attributed and why |

Result: 490,807 of 811,088 events attributed (61%). The 39% that are not are almost entirely
5156 records belonging to long-running services (`lsass.exe`, `svchost.exe`, `dns.exe`) that the
Sysmon sensor never saw start. Every 5156 opened by a *user* process did attribute.

### Section 09 — Who do we actually score?

| Cell | Type | What it does |
|---|---|---|
| 22 | MD | — |
| 23 | CODE | Excludes machine accounts (`PC-003$`), built-ins (`SYSTEM`, `LOCAL SERVICE`, …) and `ANONYMOUS LOGON` — they are machine noise, not people. Then excludes principals with fewer than 200 baseline events. Prints both lists |
| 24 | MD | — |
| 25 | CODE | Builds `ev`, the **normalised event table** — one row per attributed event with all the different Security/Sysmon field names folded into one schema (`image`, `dst_ip`, `src_ip`, `domain`, `reg_path`, …) |

8 principals are scored. 4 stale service accounts are reported separately instead of being
forced into a model that cannot support them.

### Section 10 — The 10-minute grid

| Cell | Type | What it does |
|---|---|---|
| 26 | MD | Why the grid is a cross product, and why empty windows stay |
| 27 | CODE | Builds 8 users × 13 days × 144 windows = **14,976 rows**, marks `has_telemetry`, asserts every hour really has 6 windows, and prints the observations-per-`user×hour` table |

### Section 11 — Feature engineering

| Cell | Type | What it does |
|---|---|---|
| 28 | MD | Explains the process taxonomy and the command-line signature idea |
| 29 | CODE | The tool classes (`SHELLS`, `DISCOVERY`, `LOLBIN`, `ADMIN_TOOL`, …) and **50 boolean flags** on every event. Also `FEATURE_TEXT` — the plain-English name of every feature, used by the dictionary table and the explanations |
| 30 | CODE | `cmd_signature()` — turns `powershell.exe -NoProfile -Command <script>` into `powershell.exe\|-noprofile -command`. Keeps the flag *habit*, throws away the argument *values*. GUI apps are excluded because their command lines are pure churn |
| 31 | MD | — |
| 32 | CODE | Sums the flags per `(user, window)`, counts distinct values, joins onto the grid and zero-fills → `W`, the **71-feature window table** |
| 33 | CODE | Builds `ITEMS`, the 11 **categorical behaviour dimensions** (executable, command-line style, parent→child, auth source IP, auth path, host/logon-type, logon type, destination IP, destination port, DNS domain, host touched) |

To add a feature later: add one flag in cell 29. Everything downstream picks it up.

### Section 12 — Are the features usable?

| Cell | Type | What it does |
|---|---|---|
| 34 | MD | — |
| 35 | CODE | Sparsity check (features that are almost always zero go to the *activation* signal, not the z-score), the **feature dictionary table** (name, meaning, how dense, where it is routed), and the most redundant feature pairs |
| 36 | CODE | **Figure**: window-activity histogram, feature CDFs, feature correlation heatmap |

### Section 13 — Train/test split

| Cell | Type | What it does |
|---|---|---|
| 37 | MD | — |
| 38 | CODE | Splits `W` by date and asserts the last training window is strictly before the first test window — the leakage guard |

### Section 14 — Building the baseline

| Cell | Type | What it does |
|---|---|---|
| 39 | MD | Explains log-space robust statistics, the shrunk scale, the inventories, and event-ID rarity |
| 40 | CODE | `fit_baseline()` and its four parts: numeric stats per `user×hour`, behavioural inventories, event-ID rarity tables, and the activation table |
| 41 | CODE | Renders the baseline as tables: the tidy `user × hour × feature` table, **charlie.brown's 24-hour profile (median and P95)**, inventory sizes per person, what each person normally runs, and each person's authentication footprint |

Why counts are modelled in `log1p` space: Windows telemetry bursts multiplicatively, and taking
logs turns "3× more than usual" into a constant offset whatever the person's normal volume.

Why the scale is shrunk: with only 36–42 observations, a cell's own MAD is often exactly 0, which
would make *any* non-zero value look infinitely anomalous. The scale is
`max(cell MAD, 0.6 × the user's all-hours MAD, 0.35)` — still user-specific, never global.

### Section 15 — Looking at the baseline

| Cell | Type | What it does |
|---|---|---|
| 42 | MD | — |
| 43 | CODE | **Figure**: the `user × hour` activity heatmap, the individual observations behind one cell, and every person's hourly shape overlaid (this is the picture that shows why a global baseline would fail) |
| 44 | CODE | **Figure**: behavioural vocabulary per person, empty-window share, and how many cells have MAD = 0 |

### Section 16 — The scoring engine

| Cell | Type | What it does |
|---|---|---|
| 45 | MD | The five-signal table and why leave-one-day-out is necessary |
| 46 | CODE | `novelty_frame()`, `rarity_frame()`, `activation_matrix()`, `robust_z()`, `combine_stat()`, `score_block()`. Then runs the leave-one-day-out folds over the baseline period and scores the test days |
| 47 | MD | — |
| 48 | CODE | Fits Isolation Forest, Local Outlier Factor and One-Class SVM on the deviation matrix so Section 20 can measure whether ML earns its place |

Two details worth knowing in cell 46:

* **Browser damping.** Chrome and Teams reach new IP addresses all day by design, so novelty from
  a "trusted" network app is multiplied by 0.06. Novelty from `rundll32.exe` or `certutil.exe` is
  not damped. This is what stops normal web browsing from swamping the novelty signal.
* **Per-user install paths.** `C:\Users\<name>\AppData\...\slack.exe` is the same software for
  everybody, so the path is canonicalised before the *global* rarity lookup. Otherwise everyone's
  Slack would look like a globally unique binary.

### Section 17 — How the signals behave

| Cell | Type | What it does |
|---|---|---|
| 49 | MD | — |
| 50 | CODE | Table of each signal's zero-rate and tail on baseline vs test, then a **Figure** of the five distributions side by side |

### Section 18 — Turning signals into a risk score

| Cell | Type | What it does |
|---|---|---|
| 51 | MD | The noisy-OR formula, the weight rationale, and how the threshold is derived |
| 52 | CODE | Fuses the signals, assigns risk bands, and **derives `ALERT_THRESHOLD` from the leave-one-day-out null** at the configured budget → 0.576 |
| 53 | CODE | **Figure**: baseline vs test risk distributions with the threshold marked, expected alert volume vs threshold, and each signal's share of the fused score |

### Section 19 — Why did it score that?

| Cell | Type | What it does |
|---|---|---|
| 54 | MD | — |
| 55 | CODE | `explain(user, window)` reconstructs every reason from the four contribution tables and ranks them by how much they moved the score. `print_alert()` renders it as sentences. The three highest-risk windows are printed as examples |

A real example the notebook prints:

```
User: charlie.brown   Date: 2026-08-04   Window: 23:20-23:30 (UTC)
Risk Score: 0.984    Risk Level: CRITICAL

  1. [rarity    ] rare event type 8 (Sysmon CreateRemoteThread) x1 — seen 0x for
                  charlie.brown and 0x across the whole environment in 7 baseline days
  2. [activation] first occurrence for charlie.brown: high-privilege LSASS accesses = 1
  3. [novelty   ] new executable: c:\windows\temp\svc-host-helper.exe
                  (never seen anywhere in the baseline)
```

### Section 20 — Grading the results

| Cell | Type | What it does |
|---|---|---|
| 56 | MD | Explains how episodes are formed and how a window is labelled positive |
| 57 | CODE | **Parses** `GROUND_TRUTH.md` — the timeline table, the IOC lists, and the red-herring table. Nothing is hand-typed, so the grading cannot drift from the scenario |
| 58 | CODE | Rebuilds the 20 attack steps by clustering each actor's timeline rows with a 12-minute gap, expanding the two beacons to their documented durations, and recovering the spray's real victims from the data |
| 59 | CODE | Labels test windows using ground-truth evidence restricted to each episode's actor and time span |
| 60 | CODE | PR-AUC and ROC-AUC for each signal alone, the fused score, and the three ML models |
| 61 | CODE | Threshold sweep table and the **operating point** |
| 62 | MD | — |
| **63** | CODE | **The ground-truth window map** — one row per timeline event: where it lands, what the window scored, detected yes/no, plus a ±1-window tolerant column |
| 64 | MD | — |
| **65** | CODE | The same at window granularity: every distinct `(user, 10-minute window)` the ground truth points at, whether it alerted, and a breakdown by category |
| 66 | CODE | Per-episode detection table with **detection latency** |
| 67 | MD | — |
| 68 | CODE | For each undetected step, prints the raw evidence so you can see *why* — not just that it missed |
| 69 | MD | — |
| 70 | CODE | Red-herring analysis: the four planted benign activities and what each scored |
| 71 | CODE | **Ablation** — removes each signal in turn and re-measures |
| 72 | CODE | **Figure**: PR curve, ROC curve, and precision/recall/FP-rate against threshold |

### Section 21 — Charts

| Cell | Type | What it does |
|---|---|---|
| 73 | MD | — |
| 74 | CODE | **Figure**: risk over time for all 8 people, with attack episodes shaded red and planted red herrings shaded green |
| 75 | CODE | **Figure**: alerts per person, what drove the top 12 windows, normal vs alerting behaviour, and which behaviour dimensions produced the novelty |
| 76 | CODE | **Figure**: one alert fully unpacked — signal contributions beside the written reasons |

### Section 22 — Results

| Cell | Type | What it does |
|---|---|---|
| 77 | MD | Why alerting windows are grouped into incidents |
| 78 | CODE | Groups alerting windows into **incidents** (90-minute gap tolerance, because a slow implant beacons every ~40 minutes) → 76 windows become 15 incidents |
| 79 | CODE | Full explanation of the top 6 incidents |
| 80 | CODE | **Kill-chain view** — the attack story reconstructed from alerts alone, in order. Plus the unbaselined-principals table |
| 81 | CODE | The one-screen SUMMARY |

### Sections 23–24 — Save and caveats

| Cell | Type | What it does |
|---|---|---|
| 82 | MD | — |
| 83 | CODE | Writes everything to `baseline_output/` — baseline tables, inventories, rarity tables, scored windows, alerts, incidents, and `model.pkl` |
| 84 | MD | **Read this one.** Every assumption, every limitation, every warning, collected in one place |

---

## 6. Results

Measured on 2026-08-04 … 2026-08-09, at the threshold derived from baseline data only.

| Metric | Value |
|---|---|
| PR-AUC | **0.864** (positives are 1.7% of windows) |
| ROC-AUC | **0.949** |
| Precision | **0.908** |
| Recall | **0.885** |
| F1 | **0.896** |
| Attack steps detected | **17 / 20** |
| Core ground-truth windows detected | **18 / 20** |
| False positives | **7 windows over 46 user-days = 0.15 per user per day** |
| Analyst queue | **15 incidents in 6 days** (0.32 per user per day) |
| Median detection latency | **5 minutes** — within the first window |

Which signal actually does the work (ablation):

| Removed | PR-AUC | Steps detected |
|---|---|---|
| nothing (full model) | 0.864 | 17 / 20 |
| without novelty | 0.853 | 11 / 20 |
| without activation | 0.805 | 15 / 20 |
| without rarity | 0.860 | 17 / 20 |
| without statistics | 0.862 | 17 / 20 |
| without ML | 0.864 | 17 / 20 |

Novelty and activation carry the detection. The ML layer adds nothing measurable on this dataset
(PR-AUC 0.017 on its own) — the notebook says so plainly and keeps it at a small weight rather
than pretending otherwise.

---

## 7. The three attack steps that were **not** detected

None of them is a scoring failure. In each case the evidence a user-behaviour model would need
is not in the log. Section 20.3 prints the raw data for each.

| Step | Why |
|---|---|
| **20** — frank.dsouza, executive workstation | **No telemetry exists.** The source address `91.219.236.174` appears **zero** times in `events.jsonl`, and there is no 4800/4801 lock/unlock on PC-006 anywhere in the test period. `GROUND_TRUTH.md` itself notes the lock was *"Skipped (no eligible interactive session); no evidence emitted"* |
| **16** — DNS infrastructure recon | The `cdn-metrics-edge.net` lookup at that moment is issued by `svchost.exe` running as `LOCAL SERVICE` (the system resolver), not by the user's process — so it is out of scope by the attribution rules. The same domain **is** caught earlier when `rundll32.exe` resolves it under the user's own token |
| **4** — help-desk logon to FILE-01 | Genuinely weak evidence. `10.10.10.23` is already in ethan.hayes's baseline source-IP set and `FILE-01` is already in his baseline host list; only the exact *pair* is new. It scores 0.175 (LOW). Catching it would mean dropping the threshold far enough to triple the false-alarm rate |

---

## 8. The false alarms, and the red herrings

The scenario deliberately plants four benign activities that look malicious.

| Planted activity | Score | Alerted? |
|---|---|---|
| frank.dsouza signs in before dawn | 0.000 | silent |
| nina.kapoor Sunday maintenance window | 0.448 (LOW) | silent |
| ethan.hayes help-desk sessions (3 of them) | 0.592 / 0.469 / 0.465 | 1 of 3 |
| grace.lin authorised domain enumeration | 0.867 (CRITICAL) | **yes** |

The two the brief calls hardest are the two that stay quietest, and for the right reasons: the
pre-dawn sign-in scores zero because the hour-specific baseline already knows that hour exists
for him and nothing in the window is new — the model is not a "late = suspicious" rule. The
Sunday maintenance stays low because the baseline is deliberately **day-of-week independent**, so
a Sunday at 11:00 is compared against every other day at 11:00.

Grace's authorised enumeration does alert, and that is correct behaviour rather than a bug: she
genuinely ran two domain-reconnaissance binaries she had not run in seven days. The system's job
is to say how different that is from her normal. The explanation names the two executables, which
is exactly what lets an analyst close it against a change record in seconds.

Total false alarms across 6 days and 8 people: **7 windows**. Once grouped, 5 of the 15 tickets
an analyst would see are not ground-truth attacks — two of them the planted red herrings above,
three of them busy nina.kapoor windows carrying a single novel value each.

---

## 9. What gets written to `baseline_output/`

| File | What it holds |
|---|---|
| `baseline_user_hour.parquet` | the `user × hour × feature` baseline table (median, MAD, P5/P25/P75/P95, max, observation count) |
| `baseline_inventories.parquet` | every `(user, dimension, value)` the baseline saw — the novelty reference |
| `baseline_global_rarity.parquet` | how common each behaviour value is across the whole network |
| `baseline_eventid_rarity.parquet` | per-user Event ID frequencies |
| `baseline_activation.parquet` | the per-user feature maxima that define "never done before" |
| `window_features.parquet` | all 14,976 window feature vectors |
| `attributed_events.parquet` | the normalised, user-attributed event table |
| `scored_test_windows.parquet` | every test window with its five signals, risk score and band |
| `scored_baseline_windows_lodo.parquet` | the leave-one-day-out null distribution |
| `alerts.csv` | every alerting window |
| `incidents.csv` | alerting windows grouped into incidents |
| `attack_step_detection.csv` | per-attack-step detection and latency |
| `model.pkl` | the fitted baseline + Isolation Forest + full configuration, enough to score a new day without re-reading the raw log |

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **window** | a 10-minute slice of one person's activity — the unit everything is scored on |
| **principal** | an account the system baselines and scores (the 8 humans here) |
| **baseline cell** | one `(user, hour)` pair — e.g. `charlie.brown + hour 03` — learned from 36–42 windows |
| **attribution** | working out which account an event belongs to |
| **novelty** | a behaviour value this person has never shown before |
| **activation** | a whole feature that was zero for this person in every baseline hour and is now non-zero |
| **rarity** | an Event ID that is structurally uncommon for this person *and* across the network |
| **leave-one-day-out** | re-fitting the baseline without one day and scoring that day, to get an honest "normal" score distribution |
| **noisy-OR** | the way the five signals combine: any one is capped, agreeing signals compound |
| **episode** | one of the 20 attack steps from `GROUND_TRUTH.md`, with a start and end time |
| **incident** | alerting windows for the same person within 90 minutes, grouped into one ticket |
| **red herring** | a benign activity the scenario planted to look suspicious |

---

## 11. Honest limits

* One 12-day scenario, one attack chain, eight users. These numbers describe **this dataset**;
  they are not evidence of generalisation.
* `risk_score` is a **behavioural-deviation score, not a probability of maliciousness**. No
  calibrated probabilistic model was fitted, so no such claim is made.
* The fusion weights are hand-set from each signal's baseline profile, not learned — learning
  them would need labelled attacks, which would defeat the unsupervised premise. The ablation in
  cell 71 shows what each one is worth.
* 39% of events are never attributed (mostly machine-level firewall records). This is reported in
  cell 21, not hidden.
* The statistical signal is deliberately conservative because of the shrunk scale. That is a
  bias-variance trade made on purpose to keep false alarms down.

Section 24 of the notebook has the full list, plus four concrete things that would change if this
went to production.
