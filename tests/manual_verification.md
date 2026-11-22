# Manual Verification — hand calculations

Every number in this document is asserted in `tests/test_main.cpp`
(`make test`). You can also print the same Gantt charts and tables with

```
./cmlfq --examples
```

## Conventions used by the simulator (and in this document)

| Rule | Meaning |
|------|---------|
| Time | Integer ticks; 1 tick = 1 µs simulated. A process "running 0–2" executes during ticks 0 and 1 and is off the CPU at time 2. |
| Turnaround (TAT) | finish − arrival |
| Waiting (WT) | TAT − burst |
| Response (RT) | first start − arrival |
| Same-tick ordering | At time *t*, new arrivals are enqueued **before** a process whose quantum expired at *t* (standard RR convention). |
| Context switch | Counted whenever the CPU loads a process **different** from the one that ran last. The very first dispatch is not counted. Re-dispatching the same process (e.g. it is alone in the RR queue) is free. |
| Context-switch cost | 0 in every example except §A.4. |

Settings for all examples (`exampleConfig()` in `src/examples.cpp`, also
`workloads/hand_config.ini`): quantum 2 · classic-MLFQ Q1 quantum 4 ·
window W = 10 ticks · velocity cap 0.5 req/tick · frequency cap 5 ·
weights w1 = 0.5, w2 = 0.2, w3 = 0.3 · SUSPICIOUS ≥ 0.30 · MALICIOUS ≥ 0.55 ·
promotion aging K = 100 · anti-starvation off.

---

## Example A — 5 processes, no attack (`workloads/hand_basic.txt`)

| PID | Arrival | Burst |
|----:|--------:|------:|
| P1 | 0 | 5 |
| P2 | 1 | 3 |
| P3 | 2 | 1 |
| P4 | 3 | 2 |
| P5 | 4 | 4 |

Total work = 15 ticks, so every schedule ends at 15 (no idle time).

### A.1 FCFS

```
| P1          | P2      | P3 | P4    | P5         |
0             5         8    9       11           15
```

| PID | Finish | TAT = F − A | WT = TAT − B | RT |
|----:|------:|-----:|----:|----:|
| P1 | 5  | 5  | 0 | 0 |
| P2 | 8  | 7  | 4 | 4 |
| P3 | 9  | 7  | 6 | 6 |
| P4 | 11 | 8  | 6 | 6 |
| P5 | 15 | 11 | 7 | 7 |
| **Avg** | | **38/5 = 7.6** | **23/5 = 4.6** | **4.6** |

Context switches: P1→P2→P3→P4→P5 = **4**.

### A.2 Round Robin, quantum 2

Ready-queue trace (front on the left):

| Time | Event | Ready queue after event | CPU |
|-----:|-------|-------------------------|-----|
| 0  | P1 arrives | – | P1 runs 0–2 |
| 1  | P2 arrives | P2 | |
| 2  | P3 arrives, then P1 quantum expires (rem 3) | P2 P3 P1 | P2 runs 2–4 |
| 3  | P4 arrives | P3 P1 P4 | |
| 4  | P5 arrives, then P2 expires (rem 1) | P3 P1 P4 P5 P2 | P3 runs 4–5, **done** |
| 5  | | P1 P4 P5 P2 | P1 runs 5–7 (rem 1) |
| 7  | P1 expires | P4 P5 P2 P1 | P4 runs 7–9, **done** |
| 9  | | P5 P2 P1 | P5 runs 9–11 (rem 2) |
| 11 | P5 expires | P2 P1 P5 | P2 runs 11–12, **done** |
| 12 | | P1 P5 | P1 runs 12–13, **done** |
| 13 | | P5 | P5 runs 13–15, **done** |

```
| P1 | P2 | P3| P1 | P4 | P5 | P2| P1| P5 |
0    2    4   5    7    9    11  12  13   15
```

| PID | Start | Finish | TAT | WT | RT |
|----:|-----:|------:|----:|---:|---:|
| P1 | 0 | 13 | 13 | 8 | 0 |
| P2 | 2 | 12 | 11 | 8 | 1 |
| P3 | 4 | 5  | 3  | 2 | 2 |
| P4 | 7 | 9  | 6  | 4 | 4 |
| P5 | 9 | 15 | 11 | 7 | 5 |
| **Avg** | | | **44/5 = 8.8** | **29/5 = 5.8** | **12/5 = 2.4** |

Context switches: dispatch order P1 P2 P3 P1 P4 P5 P2 P1 P5 → **8**.

### A.3 Classic MLFQ (Q0 RR q=2 → Q1 RR q=4 → Q2 FCFS)

New processes enter Q0; using a full quantum demotes one level; a lower
queue runs only when every higher queue is empty.

| Time | Event | Q0 | Q1 | CPU |
|-----:|-------|----|----|-----|
| 0 | P1 arrives | – | – | P1 (Q0) 0–2 |
| 2 | P3 arrives; P1 used full quantum → Q1 (rem 3) | P2 P3 | P1 | P2 (Q0) 2–4 |
| 4 | P5 arrives; P2 used full quantum → Q1 (rem 1) | P3 P4 P5 | P1 P2 | P3 (Q0) 4–5 done |
| 5 | | P4 P5 | P1 P2 | P4 (Q0) 5–7 done |
| 7 | | P5 | P1 P2 | P5 (Q0) 7–9 |
| 9 | P5 used full quantum → Q1 (rem 2) | – | P1 P2 P5 | P1 (Q1) 9–12 done |
| 12 | | – | P2 P5 | P2 (Q1) 12–13 done |
| 13 | | – | P5 | P5 (Q1) 13–15 done |

| PID | Start | Finish | TAT | WT | RT |
|----:|-----:|------:|----:|---:|---:|
| P1 | 0 | 12 | 12 | 7 | 0 |
| P2 | 2 | 13 | 12 | 9 | 1 |
| P3 | 4 | 5  | 3  | 2 | 2 |
| P4 | 5 | 7  | 4  | 2 | 2 |
| P5 | 7 | 15 | 11 | 7 | 3 |
| **Avg** | | | **42/5 = 8.4** | **27/5 = 5.4** | **8/5 = 1.6** |

Context switches: P1 P2 P3 P4 P5 P1 P2 P5 → **7**. Demotions: P1, P2, P5 → **3**.

### A.4 FCFS with a context-switch cost of 1 tick

```
| P1        |cs| P2    |cs| P3 |cs| P4  |cs| P5      |
0           5  6       9  10   11 12    14 15        19
```

| PID | Start | Finish | TAT | WT |
|----:|-----:|------:|----:|---:|
| P1 | 0  | 5  | 5  | 0  |
| P2 | 6  | 9  | 8  | 5  |
| P3 | 10 | 11 | 9  | 8  |
| P4 | 12 | 14 | 11 | 9  |
| P5 | 15 | 19 | 15 | 11 |

4 switches × 1 tick = 4 overhead ticks; the CPU is busy 15 of 19 ticks (78.9 %).

---

## Security score formula

For a source at time *t*, with *n* = its arrivals in the window (t − 10, t]:

```
normVelocity  = min(1, (n / 10) / 0.5)
normFrequency = min(1, lifetimeRequests / 5)
anomaly       = mean payload anomaly of the requests in the window
threatScore   = 0.5·normVelocity + 0.2·normFrequency + 0.3·anomaly
```

For a source sending requests with anomaly 0.5 inside one window:

| Requests so far | normVel | normFreq | Score | Level |
|---:|---:|---:|---|---|
| 1 | 0.2 | 0.2 | 0.10 + 0.04 + 0.15 = **0.29** | CLEAN (< 0.30) → Q0 |
| 2 | 0.4 | 0.4 | 0.20 + 0.08 + 0.15 = **0.43** | SUSPICIOUS → Q1 |
| 3 | 0.6 | 0.6 | 0.30 + 0.12 + 0.15 = **0.57** | MALICIOUS (≥ 0.55) → Q2 |

A legit trader with a single request and anomaly 0 scores 0.10 + 0.04 + 0 = **0.14** (CLEAN).

---

## Example B — one bot among legit traders (`workloads/hand_security.txt`)

| PID | Source | Arrival | Burst | Anomaly | Truth |
|----:|--------|-------:|------:|-------:|-------|
| P1 | L1  | 0 | 4 | 0.0 | legit |
| P2 | BOT | 1 | 3 | 0.5 | malicious |
| P3 | BOT | 2 | 3 | 0.5 | malicious |
| P4 | L2  | 3 | 2 | 0.0 | legit |
| P5 | BOT | 4 | 2 | 0.5 | malicious |
| P6 | L3  | 5 | 3 | 0.0 | legit |

### B.1 Adaptive MLFQ — tick-by-tick

| Time | Event | Q0 | Q1 | Q2 | CPU |
|-----:|-------|----|----|----|-----|
| 0 | P1 arrives, L1 score 0.14 → Q0 | – | – | – | P1 (Q0) |
| 1 | P2 arrives, BOT score 0.29 → **Q0** | P2 | – | – | P1 |
| 2 | P3 arrives, BOT score 0.43 → Q1. Re-evaluation: BOT is SUSPICIOUS, so waiting P2 is demoted Q0 → Q1. P1's quantum expires; it is the only Q0 process, so it continues (no switch). | – | P2 P3 | – | P1 |
| 3 | P4 arrives (0.14) → Q0 | P4 | P2 P3 | – | P1 (finishes at 4) |
| 4 | P5 arrives, BOT score 0.57 → **Q2**. Re-evaluation: BOT is MALICIOUS, so P2 and P3 are moved Q1 → Q2. Q2 is ordered by original arrival. | P4 | – | P2 P3 P5 | P4 (switch 1) |
| 5 | P6 arrives (0.14) → Q0 | P6 | – | P2 P3 P5 | P4 (finishes at 6) |
| 6 | | – | – | P2 P3 P5 | P6 (switch 2) 6–9 |
| 9 | Q0 and Q1 empty, so quarantine may run | – | – | P3 P5 | P2 (switch 3) 9–12 |
| 12 | | – | – | P5 | P3 (switch 4) 12–15 |
| 15 | | – | – | – | P5 (switch 5) 15–17 |

(At t = 11 tick 1 leaves BOT's window, so its score falls to 0.47, SUSPICIOUS.
That is below Q2's level, but promotion needs K = 100 calm ticks, so nothing moves.)

```
| P1 (Q0)   | P4 | P6    | P2 (Q2)| P3 (Q2)| P5 |
0           4    6       9        12       15   17
```

| PID | Truth | Start | Finish | TAT | WT | RT | Demotions |
|----:|-------|-----:|------:|----:|---:|---:|----------:|
| P1 | legit | 0  | 4  | 4  | 0  | 0  | 0 |
| P2 | bot   | 9  | 12 | 11 | 8  | 8  | 2 (Q0→Q1→Q2) |
| P3 | bot   | 12 | 15 | 13 | 10 | 10 | 1 (Q1→Q2) |
| P4 | legit | 4  | 6  | 3  | 1  | 1  | 0 |
| P5 | bot   | 15 | 17 | 13 | 11 | 11 | 0 (placed in Q2) |
| P6 | legit | 6  | 9  | 4  | 1  | 1  | 0 |

* Legit avg WT = (0 + 1 + 1) / 3 = **0.667**
* Malicious avg WT = (8 + 10 + 11) / 3 = **9.667**
* Overall avg WT = 31 / 6 = **5.167**
* Context switches = **5**, of which **3** loaded a bot (P2, P3, P5)
* Time-to-isolate for BOT = first quarantine (t = 4) − first arrival (t = 1) = **3 ticks**

### B.2 Same workload under FCFS (for contrast)

```
| P1      | P2    | P3    | P4  | P5  | P6    |
0         4       7       10    12    14      17
```

WT = 0, 3, 5, 7, 8, 9, so **legit avg WT = (0 + 7 + 9) / 3 = 5.333**, which is
8× worse than the adaptive scheduler, because legit P4 and P6 queue behind the bot.

---

## Example C — forced preemption of a running bot

| PID | Source | Arrival | Burst | Anomaly |
|----:|--------|-------:|------:|-------:|
| P1 | BOT | 0 | 5 | 0.5 |
| P2 | BOT | 1 | 1 | 0.5 |
| P3 | BOT | 1 | 1 | 0.5 |
| P4 | L1  | 1 | 2 | 0.0 |

| Time | Event | CPU |
|-----:|-------|-----|
| 0 | P1: BOT score 0.29 → Q0 | P1 starts (Q0) |
| 1 | P2 arrives (0.43 → Q1), P3 arrives (0.57 → Q2), P4 arrives (0.14 → Q0). BOT is now MALICIOUS **while P1 is on the CPU** → P1 is **forcibly preempted** after only 1 of its 2 quantum ticks and goes to Q2; P2 is moved Q1 → Q2. Q2 = P1 P2 P3 (arrival order). | P4 (switch 1) 1–3 |
| 3 | Q0 empty | P1 (switch 2) 3–7 |
| 7 | | P2 (switch 3) 7–8 |
| 8 | | P3 (switch 4) 8–9 |

| PID | Finish | TAT | WT | RT |
|----:|------:|----:|---:|---:|
| P1 | 7 | 7 | 2 | 0 |
| P2 | 8 | 7 | 6 | 6 |
| P3 | 9 | 8 | 7 | 7 |
| P4 | 3 | 2 | 0 | 0 |

Forced preemptions = **1**, time-to-isolate = 1 − 0 = **1 tick**, switches = **4** (3 loading bots).

---

## Example D — aging and the rehabilitation ceiling

Workload: three BOT requests at t = 0 (burst 1, anomaly 0.5) and a legit
job L1 at t = 0 with burst 30. K = 5 here.

At t = 0 the BOT requests score 0.29, 0.43 and 0.57, so after
re-evaluation all three sit in Q2. L1 holds Q0 (re-dispatched every
quantum with no switch, since it is alone).

* t = 10: BOT's arrivals at tick 0 leave the window (0 ≤ 10 − 10), so its
  score falls to 0.2·(3/5) = **0.12**, CLEAN. The calm clock starts.
* t = 15: calm for K = 5 ticks, so the bots are **promoted Q2 → Q1**.
* t = 20: another 5 calm ticks.
  * `rehab_ceiling = 0` (full rehabilitation): promoted **Q1 → Q0** and
    they join L1's round robin. Schedule: `L1 0–20 | P1 20–21 | P2 21–22 | P3 22–23 | L1 23–33`.
    6 promotions.
  * `rehab_ceiling = 1` (default): BOT was once MALICIOUS, so it may not
    re-enter the Verified-Human queue. The bots wait in Q1 until Q0 is empty:
    `L1 0–30 | P1 30–31 | P2 31–32 | P3 32–33`. 3 promotions.

The default ceiling matters in the large scenarios. Without it, when an attack
stops the bots' queued backlog is promoted back into Q0 and legit wait under DDoS
rises from about 6 ticks to about 280.
