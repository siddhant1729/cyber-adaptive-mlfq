# Cyber-Adaptive MLFQ
### Adaptive Anti-Fraud Scheduling for High-Frequency Fintech (HFT) Systems
*Operating Systems Lab Project — JIIT, B.Tech V Semester*

A C++17 command-line simulator of a **security-aware Multi-Level Feedback
Queue scheduler**. Processes (trading requests) move between queues based on
the **behaviour of their source**: request velocity, request volume and payload
anomaly. CPU usage is not what moves them. DDoS bots and credential-stuffing
tokens are pushed down into a quarantine queue while legitimate traders stay in
a fast round-robin lane.

The simulator compares the adaptive scheduler against FCFS, Round Robin and a
classic CPU-burst MLFQ on the **same workload**, under four scenarios: no attack,
DDoS, credential stuffing and mixed.

**Headline result** (`./cmlfq --generate --scenarios`, seed 42, 50 legit + 200 attack requests):

| Legit avg wait (ticks) | FCFS | RR | MLFQ | **Adaptive-MLFQ** |
|---|---:|---:|---:|---:|
| no attack | 2.12 | 4.92 | 5.12 | **4.92** |
| DDoS | 423.22 | 753.18 | 725.60 | **6.06** |
| credential stuffing | 198.40 | 400.90 | 418.62 | **5.34** |
| mixed | 314.12 | 581.90 | 574.76 | **5.50** |

Legit latency under the adaptive scheduler stays almost flat while every
baseline degrades 40 to 150×. In all four scenarios there are **zero false
positives**: no legit request was throttled or quarantined.

---

## 1. Build and run

Requirements: Ubuntu (or any Linux), `g++` with C++17, `make`. There are no
dependencies beyond the STL and pthreads.

```bash
make            # builds ./cmlfq   (-std=c++17 -Wall -Wextra -O2 -pthread, zero warnings)
make test       # builds and runs the unit tests (hand-computed expectations)
make run        # full comparison on a generated mixed attack
make scenarios  # the no-attack / DDoS / stuffing / mixed sweep
make clean
```

### Command line

```
./cmlfq                                   # no arguments -> interactive menu (for the viva)

./cmlfq --workload workloads/hand_basic.txt --compare --gantt --cs-cost 0
./cmlfq --generate --legit 50 --bots 200 --seed 42 --attack ddos --compare --gantt --csv
./cmlfq --generate --scenarios --csv
./cmlfq --examples                        # hand-verification examples A, B, C
./cmlfq --help
```

| Option | Meaning |
|---|---|
| `--workload FILE` | load a fixed workload file |
| `--generate` | generate one with the multi-threaded ingestion layer |
| `--legit N` / `--bots N` | number of legit / attack requests (default 50 / 200) |
| `--seed N` | RNG seed. The same seed always gives the same workload and results. |
| `--attack none\|ddos\|stuffing\|mixed` | attack type (default mixed) |
| `--save-workload FILE` | write the workload to a file so the run can be reproduced |
| `--scheduler adaptive\|fcfs\|rr\|mlfq` | single-scheduler run (default adaptive) |
| `--compare` | all four schedulers on the same workload |
| `--scenarios` | sweep all four attack types × all four schedulers |
| `--gantt` | ASCII Gantt chart (truncated to `gantt_max_segments`) |
| `--csv` | write per-process and summary CSVs to `results/` |
| `-v`, `--verbose` | per-process tables in `--compare` mode |
| `--config FILE` | settings file (default `./config.ini`) |
| `--quantum N`, `--cs-cost N`, `--window N`, `--no-starvation-aging` | override config values |

### Interactive menu

Run `./cmlfq` with no arguments. It generates a default mixed-attack workload and shows:

```
  1. Load workload from file          7. Run all attack scenarios
  2. Generate workload (threaded)     8. Hand-verification examples (A, B, C)
  3. Show workload summary            9. Settings (quantum, cs cost, gantt, csv...)
  4. Run Adaptive MLFQ (detailed)    10. Show configuration
  5. Run a baseline scheduler        11. Save current workload to file
  6. Compare all schedulers           0. Exit
```

---

## 2. Architecture

```
                      ┌────────────────────────── INGESTION (real threads) ───────────────────────────┐
                      │                                                                               │
  config.ini ──▶ Config│  TRADER-001 ─┐                                                                │
                      │  TRADER-002 ─┤  push()    ┌───────────────────┐   pop()   ┌──────────────┐     │
                      │  ...         ├──────────▶ │  ArrivalBuffer    │ ────────▶ │  consumer    │     │
                      │  DDOS-IP-001 ┤ (blocks    │  bounded deque    │           │  thread      │     │
                      │  TOKEN-007  ─┘  if full)  │  mutex + 2 condvar│           └──────┬───────┘     │
                      │  one producer thread per source, each with its own seeded RNG  │             │
                      └────────────────────────────────────────────────────────────────┼─────────────┘
  workloads/*.txt ──▶ loadWorkload() ─────────────────────────┐                         │ sort by
                                                              ▼                         ▼ (arrival, source, seq)
                                                   std::vector<PCB>  (pids 1..N)
                                                              │  same copy fed to every scheduler
          ┌──────────────────────┬────────────────────────────┼──────────────────────────┐
          ▼                      ▼                            ▼                          ▼
   ┌────────────┐        ┌──────────────┐            ┌────────────────┐        ┌───────────────────────────┐
   │   FCFS     │        │ Round Robin  │            │ Classic MLFQ   │        │      Adaptive MLFQ        │
   └─────┬──────┘        └──────┬───────┘            └───────┬────────┘        │ Q0 Verified-Human  RR q=2 │
         │                      │                            │                 │ Q1 Suspicious      SJF    │
         │       all share ONE discrete-clock engine          │                 │ Q2 Quarantine      FCFS   │
         │       Scheduler::run()  (1 tick = 1 µs)           │                 │      ▲ every tick         │
         │                                                   │                 │ ┌────┴────────────────┐   │
         │                                                   │                 │ │  SecurityAuditor    │   │
         │                                                   │                 │ │  unordered_map<src, │   │
         │                                                   │                 │ │   deque<tick>>      │   │
         │                                                   │                 │ └─────────────────────┘   │
         │                                                   │                 └────────────┬──────────────┘
         └─────────────────────┴──────────────┬──────────────┴──────────────────────────────┘
                                              ▼  SimResult (final PCBs, Gantt, counters)
                                      ┌───────────────┐        ┌──────────────────────────────────┐
                                      │   Analytics   │ ─────▶ │ Reporter: tables, ASCII Gantt,   │
                                      │ legit vs bot  │        │ results/*.csv                    │
                                      └───────────────┘        └──────────────────────────────────┘
```

### Key design decision: a discrete simulated clock

**Scheduling never uses wall-clock time.** Every scheduler runs on an integer
tick counter (1 tick = 1 µs simulated), so:

* results are **deterministic**: the same input always gives the same output;
* every number can be **checked by hand** (see `tests/manual_verification.md`).

Real threads (`std::thread`, `std::mutex`, `std::condition_variable`) are used
**only** in the ingestion layer. The output is still deterministic because:

1. each producer thread draws **simulated** arrival ticks from its **own**
   seeded `std::mt19937` (seed derived from `--seed` and the source index);
2. after all threads finish, requests are **sorted** by (arrival, source,
   sequence) before pids are assigned.

The OS can interleave the threads however it likes and the workload is still
identical. This is asserted in `ingestion_is_deterministic`, and
`ingestion_tiny_buffer_stress` checks it again with a capacity-1 buffer that
makes producers block constantly.

### Modules

| Module | Files | Responsibility |
|---|---|---|
| PCB | `include/pcb.h`, `src/pcb.cpp` | Process Control Block: scheduling fields, 5-state model, security metadata |
| Config | `include/config.h`, `src/config.cpp` | All tunables plus the INI loader (`config.ini`) |
| Workload I/O | `include/workload.h`, `src/workload.cpp` | Load and save fixed workload files |
| Ingestion | `include/ingestion.h`, `src/ingestion.cpp` | Producer/consumer threads, bounded `ArrivalBuffer`, traffic generators |
| SecurityAuditor | `include/security_auditor.h`, `src/security_auditor.cpp` | Sliding-window velocity, frequency, anomaly → threat score |
| Scheduler engine | `include/scheduler.h`, `src/scheduler.cpp` | The shared tick-by-tick simulation loop with policy hooks |
| Adaptive MLFQ | `include/adaptive_mlfq.h`, `src/adaptive_mlfq.cpp` | The security-driven 3-queue scheduler |
| Baselines | `include/baselines.h`, `src/baselines.cpp` | FCFS, Round Robin, classic MLFQ |
| Analytics | `include/analytics.h`, `src/analytics.cpp` | Metrics, overall and split legit vs malicious, time-to-isolate |
| Reporter | `include/reporter.h`, `src/reporter.cpp` | `iomanip` tables, ASCII Gantt, CSV export |
| App | `include/app.h`, `src/app.cpp`, `src/main.cpp` | CLI parsing, batch modes, interactive menu |
| Examples | `include/examples.h`, `src/examples.cpp` | Hand-computable workloads shared by tests and the menu |

### The engine loop (`Scheduler::run`)

For every tick `now`:

1. **admit** processes whose `arrival == now` → `enqueue(ARRIVAL)`
2. `onTick(now)`: the adaptive scheduler re-assesses every live process here
3. if the running process must stop (`checkPreempt`) → `enqueue(QUANTUM_EXPIRED | PREEMPTED | SECURITY)`
4. if the CPU is free → `dispatch()`. Loading a *different* process than last
   time counts as a context switch and costs `context_switch_cost` ticks; the
   clock keeps running and requests keep arriving during the switch.
5. execute the running process for **one** tick

If nothing is ready, the clock jumps to the next arrival (CPU idle).

---

## 3. The adaptive scheduler

### Threat score (SecurityAuditor)

Per source: `unordered_map<sourceId, deque<(arrivalTick, anomaly)>>` plus a lifetime count.

```
velocity      = arrivals in (now − W, now] / W                (requests per tick)
normVelocity  = min(1, velocity / velocity_cap)
normFrequency = min(1, lifetime requests / frequency_cap)
anomaly       = mean payload anomaly of requests in the window
threatScore   = w1·normVelocity + w2·normFrequency + w3·anomaly

threatScore ≥ malicious_threshold  → MALICIOUS  → Q2
threatScore ≥ suspicious_threshold → SUSPICIOUS → Q1
otherwise                          → CLEAN      → Q0
```

* **Velocity** catches bursts (DDoS floods, rapid login retries).
* **Frequency** is a slow-saturating reputation term. It is capped at
  w2 = 0.2, below the suspicious threshold, so volume alone can never flag a source.
* **Anomaly** catches odd payloads, such as the failed-login pattern of credential stuffing.

### Queues

| Queue | Name | Policy | Runs when |
|---|---|---|---|
| Q0 | Verified-Human | Round Robin, micro-quantum (2 ticks) | always first |
| Q1 | Suspicious-Throttled | non-preemptive SJF (`std::priority_queue` on remaining burst) | Q0 empty |
| Q2 | Quarantine | FCFS by original arrival | Q0 **and** Q1 empty |

Between queues the policy is priority-preemptive: new work in a higher queue
preempts a lower-queue process. Inside Q1 there is no preemption.

### Feedback rules (evaluated every tick)

| Trigger | Action |
|---|---|
| Arrival | Placed in the queue matching its source's current level |
| Source becomes **MALICIOUS** | Waiting processes move to Q2 at once. A **running** process is **forcibly preempted** at once. |
| Source becomes **SUSPICIOUS** | Waiting Q0 processes move to Q1. A running one finishes its quantum, then goes to Q1. |
| Source calm (below the queue's threshold) for **K** ticks | **Promoted one level** |
| **Rehabilitation ceiling** | A source that was *ever* MALICIOUS can climb back only to `rehab_ceiling` (default Q1) |
| Waited in Q2 ≥ `starvation_limit` | Anti-starvation boost to Q1, shielded from re-demotion for one CPU visit (can be switched off) |
| Quantum expires in Q0 | Back to the tail of Q0. **CPU usage alone never demotes**, which is the key difference from classic MLFQ. |

**Why the rehabilitation ceiling?** When we first ran the scenarios with full
rehabilitation, legit wait under DDoS was **≈279 ticks** instead of ≈6.
Once an attack stops, the bot sources go quiet, their windows empty, and after K
ticks the whole queued backlog of bot requests was promoted back into Q0, where
it competed with traders. A quarantined IP should not regain "verified human"
status automatically, so ex-malicious sources now stop at Q1. Set
`rehab_ceiling = 0` in `config.ini` to see the difference live.

---

## 4. Metric definitions

| Metric | Definition |
|---|---|
| Waiting time | turnaround − burst (all time not executing, including context-switch time) |
| Turnaround time | finish − arrival |
| Response time | first start − arrival |
| P95 waiting time | 95th percentile of waiting time (nearest-rank), the tail latency an HFT desk cares about |
| Throughput | completed processes per 1000 ticks of makespan |
| CPU utilisation | busy ticks / makespan × 100. Idle and context-switch ticks are not busy. |
| Context switches | dispatches of a process different from the previous one (first dispatch not counted) |
| …loading malicious | context switches whose incoming process is a bot (CPU wasted on attackers) |
| Time-to-isolate | per bot source: first tick any of its processes entered Q2 − the source's first arrival |
| Isolated | bot sources that reached quarantine |
| Mal≥Q1 | bot requests throttled (Q1) or quarantined (Q2) |
| LegitQ1 / LegitQ2 | legit requests wrongly throttled / quarantined (false positives) |

Every timing metric is reported **overall, legit-only and malicious-only**. The
ground-truth label is used **only** by Analytics; the schedulers never read it.

---

## 5. Sample output

`./cmlfq --generate --legit 50 --bots 200 --seed 42 --attack mixed --compare`

```
Workload: mixed_s42
===================
  Processes        : 250  (50 legit from 25 sources, 200 malicious from 22 sources)
  Arrival span     : tick 6 .. 959
  Total CPU work   : 838 ticks  (legit 285, malicious 553)
  Ingestion        : 47 producer threads + 1 consumer, 250 requests
                     bounded buffer cap 64, peak occupancy 55, producer blocks 0, 4.1 ms wall

Scheduler comparison (same workload)
====================================
  Metric                                   FCFS             RR           MLFQ  Adaptive-MLFQ
  ------------------------------------------------------------------------------------------
  Avg wait  (all)                        310.52         495.74         513.21         338.15
  Avg wait  (LEGIT)                      314.12         581.90         574.76           5.50
  Avg wait  (malicious)                  309.62         474.19         497.82         421.31
  P95 wait  (LEGIT)                      572.00         975.00        1091.00          19.00
  ..........................................................................................
  Avg TAT   (all)                        313.88         499.09         516.56         341.50
  Avg TAT   (LEGIT)                      319.82         587.60         580.46          11.20
  Avg TAT   (malicious)                  312.39         476.96         500.59         424.08
  ..........................................................................................
  Avg resp  (all)                        310.52         251.05         175.83         329.74
  Avg resp  (LEGIT)                      314.12         274.04         132.72           1.96
  Avg resp  (malicious)                  309.62         245.30         186.60         411.69
  ..........................................................................................
  Throughput (/1000 ticks)               204.25         173.49         179.86         194.86
  CPU utilisation %                       68.46          58.15          60.29          65.32
  Context switches                          249            468            420            310
    ...loading malicious                    200            338            311            224
  Switch overhead (ticks)                   249            468            420            310
  Makespan (ticks)                           1224           1441           1390           1283
  Last legit finish                        1224           1441           1390            976

  Legit avg wait vs Adaptive-MLFQ:  FCFS 57.1x  RR 105.8x  MLFQ 104.5x

  Security --------------------------------------------------
  Malicious sources isolated : 22 / 22
  Time-to-isolate (ticks)    : avg 7.09, min 3, max 22
  Malicious procs contained  : 197 / 200  (181 reached quarantine Q2)
  Legit procs throttled (Q1) : 0   quarantined (Q2): 0
  Forced preemptions         : 4
  Demotions / promotions     : 55 / 167   anti-starvation boosts: 0
```

Scenario sweep (`./cmlfq --generate --scenarios`):

```
LEGIT P95 waiting time (ticks) — tail latency
  Scenario                 FCFS             RR           MLFQ  Adaptive-MLFQ
  none                     7.00          16.00          13.00          16.00
  ddos                   749.00        1202.00        1306.00          20.00
  stuffing               366.00         711.00         878.00          16.00
  mixed                  572.00         975.00        1091.00          19.00

Adaptive-MLFQ detection per scenario
  Scenario          Isolated     Mal>=Q1      AvgTTI      MaxTTI     LegitQ1     LegitQ2      Forced     CS->mal
  none                   0/0         0/0        0.00           0           0           0           0           0
  ddos                   4/4     197/200       19.75          22           0           0           0         224
  stuffing             40/40     197/200        5.72           8           0           0           2         215
  mixed                22/22     197/200        7.09          22           0           0           4         224
```

Gantt chart (Example B, `./cmlfq --examples`):

```
  +----+---+---+---+---+---+
  |P1  |P4 |P6 |P2 |P3 |P5 |
  |Q0  |Q0 |Q0 |Q2 |Q2 |Q2 |
  +----+---+---+---+---+---+
  0    4   6   9   12  15  17
```

### Honest trade-offs (good viva material)

* **Overall** average wait for the adaptive scheduler (338) is a little higher
  than FCFS (311): bots wait *longer*, by design. Legit wait falls about 57×.
* With no attack it behaves exactly like Round Robin with the same quantum. A
  unit test checks this (`adaptive_equals_rr_without_threats`). FCFS has a
  lower average wait there, but its response time is worse.
* About 3 of 200 bot requests run in Q0 before their source is detected. Time
  to isolate is ≈20 ticks for DDoS (the velocity has to build up) and ≈6 for
  stuffing (high anomaly flags it almost immediately).
* If **legit** traffic alone exceeds CPU capacity (e.g. `--legit 150` with a
  1-tick switch cost), legit wait grows in every scheduler. Under the adaptive
  scheduler it stays identical across all four scenarios, though: the attack
  adds no extra delay.

---

## 6. Validation

`make test` runs 17 test cases, more than 1000 checks:

| Test | What it proves |
|---|---|
| `fcfs_example_A`, `rr_example_A`, `mlfq_example_A` | Exact finish/wait/TAT/response and switch counts vs hand calculation |
| `fcfs_context_switch_cost` | Context-switch cost accounting |
| `idle_gap_handling` | CPU idle and clock jump |
| `workload_file_matches_example_A` | File loader |
| `ingestion_is_deterministic` | Same seed → identical workload despite threads |
| `ingestion_counts_and_labels` | Correct counts per attack type, pids in arrival order |
| `ingestion_tiny_buffer_stress` | Capacity-1 buffer: nothing lost, same result |
| `auditor_scores` | Threat-score arithmetic and window sliding |
| `adaptive_example_B`, `fcfs_example_B` | Detection, demotion, legit-vs-bot metrics, time-to-isolate |
| `adaptive_forced_preemption_example_C` | Running bot kicked off the CPU |
| `adaptive_promotion_aging`, `adaptive_rehab_ceiling` | K-tick aging and the ceiling |
| `adaptive_anti_starvation` | Q2 boost works and can be turned off |
| `adaptive_equals_rr_without_threats` | No threats → identical to RR |

The full hand working is in **`tests/manual_verification.md`**.

---

## 7. Files

```
include/            headers (one per module)
src/                implementation (one .cpp per module) + main.cpp
tests/              test_main.cpp, manual_verification.md
workloads/          hand_basic.txt, hand_security.txt, hand_config.ini,
                    none|ddos|stuffing|mixed_seed42.txt  (saved generated workloads)
results/            CSV output (--csv)
config.ini          thresholds, weights, quanta, generator settings
Makefile            all, test, run, scenarios, clean
```

Workload file format (`#` starts a comment):

```
# pid  source      arrival  burst  anomaly  label (L = legit, M = malicious)
1      TRADER-001  6        6      0.099    L
57     DDOS-IP-001 203      4      0.312    M
```

CSV output (`--csv`): `results/<workload>_<scheduler>_processes.csv` (one row
per process, including threat score, velocity, demotions, isolation tick),
`results/<workload>_summary.csv`, and `results/scenarios_summary.csv` for
`--scenarios`.

---

## 8. Suggested viva split (4 students)

| Student | Area | Files to know well |
|---|---|---|
| 1 | Process model, discrete-clock engine, baselines (FCFS/RR/MLFQ), hand calculations | `pcb.*`, `scheduler.*`, `baselines.*`, `tests/manual_verification.md` |
| 2 | Concurrency: producer/consumer, mutex/condvar, bounded buffer, why results are still deterministic | `ingestion.*` |
| 3 | Security auditor and adaptive MLFQ: threat score, queues, demotion/preemption/aging/ceiling | `security_auditor.*`, `adaptive_mlfq.*` |
| 4 | Metrics, scenarios, reporting, CLI and menu demo | `analytics.*`, `reporter.*`, `app.*`, `config.ini` |
