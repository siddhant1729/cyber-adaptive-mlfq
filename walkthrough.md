# Walkthrough — Cyber-Adaptive MLFQ

A guided tour for the team. The guide has three parts:

1. **Demo script**: what to type in the viva, in order, and what to point at.
2. **Life of a request**: one request followed through the code, function by function.
3. **Live experiments and likely questions**: config changes that show *why*
   the design works, plus answers to the questions examiners usually ask.

Every output shown here was produced by the real program
(`make && ./cmlfq ...`). For the hand-worked numbers, see
[`tests/manual_verification.md`](tests/manual_verification.md). For the
reference documentation, see [`README.md`](README.md).

---

## Part 1 — Demo script (about 10 minutes)

### Step 0. Build and prove correctness (1 min)

```bash
make clean && make        # point out: -Wall -Wextra, zero warnings
make test                 # 17 test cases, 1066 checks, 0 failed
```

> **Say:** "Every expected value in these tests was calculated by hand first.
> The working is in `tests/manual_verification.md`."

### Step 1. The textbook schedulers on a tiny workload (2 min)

```bash
./cmlfq --workload workloads/hand_basic.txt --compare --gantt --cs-cost 0
```

Five processes; the examiner can check them on paper. Point at:

* FCFS avg wait **4.6**, RR (q=2) **5.8**, classic MLFQ **5.4**
* RR has the best response time for short jobs but the most context switches (8)
* In the MLFQ Gantt, processes that used a full quantum drop from `Q0` to `Q1`

> **Say:** "All four schedulers share one engine, `Scheduler::run()`. They only
> differ in how they queue and pick processes."

### Step 2. The core idea in six processes (2 min)

```bash
./cmlfq --examples        # scroll to Example B, then Example C
```

**Example B**: one source `BOT` sends 3 rapid requests among 3 legit traders.

```
  +----+---+---+---+---+---+
  |P1  |P4 |P6 |P2 |P3 |P5 |        legit avg wait  0.67   (FCFS: 5.33)
  |Q0  |Q0 |Q0 |Q2 |Q2 |Q2 |        bot   avg wait  9.67
  +----+---+---+---+---+---+
  0    4   6   9   12  15  17
```

Walk through the threat score growing with each BOT request:
**0.29** (CLEAN, so Q0) → **0.43** (SUSPICIOUS, so Q1) → **0.57** (MALICIOUS, so Q2).

**Example C**: forced preemption. P1 (a bot) is *on the CPU* when its source
turns malicious at t = 1. It is kicked off after 1 tick instead of 2.

```
  +---+---+----+---+---+
  |P1 |P4 |P1  |P2 |P3 |
  |Q0 |Q0 |Q2  |Q2 |Q2 |
  +---+---+----+---+---+
  0   1   3    7   8   9         forced preemptions: 1
```

### Step 3. Threaded ingestion and a real attack (2 min)

```bash
./cmlfq --generate --attack ddos --seed 42 --scheduler adaptive
```

```
  Processes        : 250  (50 legit from 25 sources, 200 malicious from 4 sources)
  Ingestion        : 29 producer threads + 1 consumer, 250 requests
  ...
  Malicious sources isolated : 4 / 4
  Time-to-isolate (ticks)    : avg 19.75, min 16, max 22
  Legit procs throttled (Q1) : 0   quarantined (Q2): 0
```

> **Say:** "29 real threads, one per traffic source, push into a bounded buffer.
> Run it again with the same seed and you get exactly the same numbers, because
> arrival times are simulated ticks, not wall-clock time."

To show that live, run the command twice and compare the output.

### Step 4. The headline comparison (2 min)

```bash
./cmlfq --generate --scenarios
```

```
LEGIT average waiting time (ticks) — lower is better
  Scenario                 FCFS             RR           MLFQ  Adaptive-MLFQ
  none                     2.12           4.92           5.12           4.92
  ddos                   423.22         753.18         725.60           6.06
  stuffing               198.40         400.90         418.62           5.34
  mixed                  314.12         581.90         574.76           5.50
```

> **Say:** "Read down the last column: it stays flat. Every other column gets
> about 100 times worse once an attack starts. And there are zero false positives
> in every scenario."

### Step 5. Interactive menu (1 min, if asked)

```bash
./cmlfq
```

Use option **9** to change the quantum or the context-switch cost, then option **6**
to compare again, and option **8** to show the hand examples.

---

## Part 2 — Life of a request

We follow one DDoS request from creation to the final report. Function names
are the ones in the code, so you can jump straight to them.

```
produce()  ──push──▶  ArrivalBuffer  ──pop──▶  consumer  ──sort──▶  vector<PCB>
                                                                        │
         Reporter ◀── computeMetrics() ◀── SimResult ◀── Scheduler::run()┘
                                                           │   ▲
                                          enqueue/onTick/  │   │ assess()
                                          checkPreempt/    ▼   │
                                          dispatch     AdaptiveMLFQ ── SecurityAuditor
```

### 2.1 Birth: `src/ingestion.cpp`

1. **`Ingestion::generate()`** decides which sources exist. `addSources()`
   splits 200 DDoS requests across 4 sources (`DDOS-IP-001` … `004`), and each
   source gets its own RNG seed derived from `--seed`.
2. One `std::thread` per source runs **`produce()`**. A DDoS source picks
   arrival ticks starting at `attack_start` plus a gap of 2–6 ticks between
   requests. That is **simulated** time, and no thread ever sleeps.
3. **`ArrivalBuffer::push()`** locks the mutex. If the buffer is full, it waits
   on the `notFull_` condition variable, then pushes and signals `notEmpty_`.
4. The consumer thread loops on **`ArrivalBuffer::pop()`**. `pop()` returns `false`
   only when every producer has called `producerFinished()` **and** the buffer
   is empty, which is how the consumer knows to stop.
5. After `join()`, requests are **sorted** by (arrival, source, seq) and turned
   into PCBs with pids 1..N. This sort is what makes the output independent of
   thread scheduling.

**Viva hook:** this is the classic **bounded-buffer producer/consumer**
problem. Two condition variables avoid busy-waiting, and the predicate inside
`wait()` handles spurious wakeups.

### 2.2 The PCB: `include/pcb.h`

Our request is now a `PCB`: pid, `sourceId = "DDOS-IP-002"`, arrival, burst,
`payloadAnomaly`, plus empty security fields. It also carries
`groundTruthMalicious = true`, and **no scheduler ever reads that field**. Only
Analytics uses it.

### 2.3 Arrival: `Scheduler::run()` in `src/scheduler.cpp`

The engine loop runs once per tick:

```
admit(now) → onTick(now) → checkPreempt? → dispatch? → execute 1 tick
```

At the request's arrival tick, `admit()` calls the scheduler's `enqueue(p, ARRIVAL)`.

### 2.4 Scoring: `AdaptiveMLFQScheduler::enqueue()` and `SecurityAuditor`

1. **`SecurityAuditor::recordArrival()`** appends `(tick, anomaly)` to this
   source's `std::deque` inside the `unordered_map`.
2. **`SecurityAuditor::assess()`** pops entries older than the window, then computes:
   ```
   score = 0.45·min(1, velocity/0.12) + 0.20·min(1, total/20) + 0.35·meanAnomaly
   ```
3. `classify()` maps the score to CLEAN / SUSPICIOUS / MALICIOUS. **`place()`**
   then puts the PCB in Q0 (a deque), Q1 (a priority queue keyed on remaining
   burst) or Q2 (a deque kept sorted by arrival).

For a DDoS source, the first one or two requests score below 0.30 and land in
**Q0**, because the source hasn't built up velocity yet. That explains the
3 of 200 bots in the real runs that are never contained.

### 2.5 Re-evaluation every tick: `AdaptiveMLFQScheduler::onTick()`

For every live process, in pid order so the result is deterministic:

| Situation | Code path | Effect |
|---|---|---|
| Waiting, source got worse | `changeLevel(p, target)` | demoted at once, `demotionCount++` |
| **Running**, source is now MALICIOUS | sets `forcePreempt_` | `checkPreempt()` returns `SECURITY` this tick |
| Running, source is now SUSPICIOUS | sets `pendingLevel_` | applied when the quantum ends |
| Source calm for K ticks | `changeLevel(p, cur-1)` | promoted one level, but never above `rehab_ceiling` for an ex-malicious source |
| In Q2 for `starvation_limit` ticks | boost to Q1 + `agingShield` | anti-starvation |

If any level changed, **`rebuildQueues()`** re-places every waiting process.

Our DDoS request's source crosses 0.55 after about 6 requests (around 20 ticks).
From then on, every one of its waiting requests sits in Q2.

### 2.6 Running: `dispatch()` and `checkPreempt()`

* `dispatch()` tries Q0, then Q1, and only then Q2.
* `checkPreempt()` rules:
  * Q0: the quantum ran out.
  * Q1: Q0 has work (inside Q1 there is no preemption).
  * Q2: Q0 or Q1 has work.
* Back in `run()`: if the newly loaded process differs from the last one, that is
  a context switch, costing `context_switch_cost` ticks. Arrivals keep being
  admitted during the switch.

Our quarantined request runs only in gaps when no trader or suspicious request
is waiting, and the moment a trader arrives it gets preempted.

### 2.7 Finish and measure: `src/analytics.cpp`, `src/reporter.cpp`

* `run()` fills `finishTime`, and then turnaround = finish − arrival, waiting =
  turnaround − burst, response = start − arrival.
* **`computeMetrics()`** splits the processes by the ground-truth label into
  legit and malicious. It computes averages and P95. Time-to-isolate is
  computed per source as the first tick a request entered Q2 minus the source's
  first arrival.
* **`Reporter`** prints the tables, the ASCII Gantt chart and the CSV files.

---

## Part 3 — Live experiments

All of these use the DDoS workload with seed 42. The default legit avg wait
under the adaptive scheduler is **6.06**.

| Change | Command / config | Adaptive legit wait | Lesson |
|---|---|---:|---|
| Default | `./cmlfq --generate --attack ddos --compare` | **6.06** | baseline |
| No switch cost | add `--cs-cost 0` | **1.54** | switching overhead was most of the legit wait. Baselines also improve but stay at 270+ |
| Bigger quantum | add `--quantum 4` | **3.48** | fewer switches (310 → 277). RR drops from 753 to 526, still far worse |
| Shorter window | add `--window 20` | **5.42** | detection still works; velocity is measured over less history |
| Full rehabilitation | `rehab_ceiling = 0` in `config.ini` | **≈279** | after the attack, the bots' backlog is promoted back into Q0 and floods it. This is why the ceiling exists. |
| Malicious threshold too high | `malicious_threshold = 0.95` | **405.68** | bots are only ever SUSPICIOUS (0/4 isolated). Their Q1 backlog is aged back to Q0 after the attack, because the ceiling only covers ex-MALICIOUS sources |
| Suspicious threshold too low | `suspicious_threshold = 0.10` | **74.80** | **41 legit requests throttled**: false positives. Thresholds are a precision/recall trade-off |

The last three rows are the most useful in a viva. They show the thresholds
and the ceiling are not arbitrary: move them and the system visibly breaks.

To try a config change without editing the real file:

```bash
sed 's/^rehab_ceiling *= *1/rehab_ceiling = 0/' config.ini > /tmp/c.ini
./cmlfq --config /tmp/c.ini --generate --attack ddos --compare
```

---

## Likely viva questions

**Q: Why not use real threads for the scheduler itself?**
Real thread timing depends on the OS, CPU load and the machine, so results would
change on every run and could not be checked by hand. A discrete clock makes the
simulation deterministic and verifiable. Threads are used where concurrency is
the realistic part: many clients submitting requests at the same time.

**Q: If threads interleave randomly, how is the output deterministic?**
Each producer uses its own seeded RNG and stamps *simulated* ticks, so the
*content* each thread produces is fixed. Only the *order* items reach the
buffer varies, and we sort by (arrival, source, seq) afterwards.
`ingestion_is_deterministic` and `ingestion_tiny_buffer_stress` prove this.

**Q: How is this different from a normal MLFQ?**
Classic MLFQ demotes a process for *using a full quantum* (CPU-bound behaviour).
Ours never demotes for CPU usage: a Q0 process whose quantum expires goes back
to the tail of Q0. Demotion is driven only by the *source's* security
behaviour. That is why the classic MLFQ column degrades under attack: it can't
tell a bot from a trader.

**Q: Why is Q1 non-preemptive SJF?**
Suspicious requests are throttled but not condemned. SJF minimises their
average wait and clears many small suspicious requests quickly, which suits
credential-stuffing attempts with 1–3 tick bursts. Making it non-preemptive
inside Q1 avoids extra context switches among low-priority work. Q0 work still
preempts Q1.

**Q: Can Q2 starve?**
Yes. Under a sustained flood of Q0/Q1 work, Q2 could wait forever. The
optional anti-starvation boost moves a process that has waited
`starvation_limit` ticks to Q1. It can be turned off with
`--no-starvation-aging`, and `adaptive_anti_starvation` tests both modes.

**Q: Why does the adaptive scheduler have a higher *overall* average wait than FCFS?**
Because bots wait longer, on purpose. The goal is to protect legit latency,
not to minimise the average across attackers and traders. Legit wait drops
about 57× in the mixed scenario.

**Q: What does a wrong decision cost?**
A false negative is a bot left in Q0. That happens for the first one or two
requests of each source, before its velocity builds up (3 of 200 overall). A
false positive is a legit request throttled. That is zero with the default
thresholds, and 41 if the suspicious threshold is lowered to 0.10 (Part 3).

**Q: What is the time complexity per tick?**
`onTick` assesses each live process. Each source is assessed once per tick
(results are cached), and pruning the window is amortised O(1). Rebuilding the
queues is O(n log n) and only happens on a tick where some level changed. For
250 processes the whole four-scheduler sweep runs in well under a second.

**Q: What would you improve next?**
* Apply the rehabilitation ceiling to long-suspicious sources too (Part 3 shows why).
* Group sources by subnet, so a botnet rotating through many IPs is caught collectively.
* Multi-core simulation (one engine per core with a shared auditor).
* Make the source "record" decay over time instead of lasting forever.
