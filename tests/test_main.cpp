// =====================================================================
//  test_main.cpp — unit tests with hand-computed expected values
//
//  Every expected number below is derived step by step in
//  tests/manual_verification.md. A tiny assertion macro is used so the
//  project has no dependency beyond the STL.
// =====================================================================
#include <cmath>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "adaptive_mlfq.h"
#include "analytics.h"
#include "baselines.h"
#include "examples.h"
#include "security_auditor.h"
#include "ingestion.h"
#include "workload.h"

using namespace cmlfq;

// ----------------------------------------------------------------------
// Minimal test harness
// ----------------------------------------------------------------------
static int g_checks = 0, g_failures = 0;

#define CHECK_EQ(actual, expected)                                                   \
    do {                                                                             \
        ++g_checks;                                                                  \
        auto _a = (actual);                                                          \
        auto _e = (expected);                                                        \
        if (!(_a == _e)) {                                                           \
            ++g_failures;                                                            \
            std::cout << "    FAIL " << __FILE__ << ":" << __LINE__ << "  " #actual  \
                      << " = " << _a << ", expected " << _e << "\n";                 \
        }                                                                            \
    } while (0)

#define CHECK_NEAR(actual, expected, eps)                                            \
    do {                                                                             \
        ++g_checks;                                                                  \
        double _a = (actual);                                                        \
        double _e = (expected);                                                      \
        if (std::fabs(_a - _e) > (eps)) {                                            \
            ++g_failures;                                                            \
            std::cout << "    FAIL " << __FILE__ << ":" << __LINE__ << "  " #actual  \
                      << " = " << _a << ", expected " << _e << "\n";                 \
        }                                                                            \
    } while (0)

#define CHECK(cond) CHECK_EQ(static_cast<bool>(cond), true)

struct TestCase { std::string name; std::function<void()> fn; };
static std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
struct Registrar { Registrar(const std::string& n, std::function<void()> f) { registry().push_back({n, f}); } };
#define TEST(name) static void name(); static Registrar reg_##name(#name, name); static void name()

// Checks finish / waiting / turnaround / response of every process (pid order).
static void expectTimes(const SimResult& r,
                        const std::vector<Tick>& finish,
                        const std::vector<Tick>& wait,
                        const std::vector<Tick>& tat,
                        const std::vector<Tick>& resp) {
    CHECK_EQ(r.procs.size(), finish.size());
    for (size_t i = 0; i < r.procs.size() && i < finish.size(); ++i) {
        const PCB& p = r.procs[i];
        CHECK_EQ(p.finishTime, finish[i]);
        CHECK_EQ(p.waitingTime, wait[i]);
        CHECK_EQ(p.turnaroundTime, tat[i]);
        CHECK_EQ(p.responseTime, resp[i]);
    }
}

// ======================================================================
// Example A — FCFS
//   Gantt: | P1 0-5 | P2 5-8 | P3 8-9 | P4 9-11 | P5 11-15 |
//   finish      : 5  8  9 11 15
//   turnaround  : 5  7  7  8 11   (sum 38, avg 7.6)
//   waiting     : 0  4  6  6  7   (sum 23, avg 4.6)
//   response    : 0  4  6  6  7
//   context switches: 4
// ======================================================================
TEST(fcfs_example_A) {
    Config cfg = exampleConfig();
    FCFSScheduler s(cfg);
    SimResult r = s.run(exampleBasicWorkload());
    expectTimes(r, {5, 8, 9, 11, 15}, {0, 4, 6, 6, 7}, {5, 7, 7, 8, 11}, {0, 4, 6, 6, 7});
    CHECK_EQ(r.contextSwitches, 4LL);
    CHECK_EQ(r.makespan, 15LL);
    CHECK_EQ(r.busyTicks, 15LL);
}

// ======================================================================
// Example A — Round Robin, quantum 2
//   Gantt: P1 0-2 | P2 2-4 | P3 4-5 | P1 5-7 | P4 7-9 | P5 9-11 |
//          P2 11-12 | P1 12-13 | P5 13-15
//   finish      : 13 12  5  9 15
//   turnaround  : 13 11  3  6 11  (sum 44, avg 8.8)
//   waiting     :  8  8  2  4  7  (sum 29, avg 5.8)
//   response    :  0  1  2  4  5  (sum 12, avg 2.4)
//   context switches: 8
// ======================================================================
TEST(rr_example_A) {
    Config cfg = exampleConfig();
    RoundRobinScheduler s(cfg);
    SimResult r = s.run(exampleBasicWorkload());
    expectTimes(r, {13, 12, 5, 9, 15}, {8, 8, 2, 4, 7}, {13, 11, 3, 6, 11}, {0, 1, 2, 4, 5});
    CHECK_EQ(r.contextSwitches, 8LL);
    CHECK_EQ(r.makespan, 15LL);
}

// ======================================================================
// Example A — classic MLFQ (Q0 RR q=2, Q1 RR q=4, Q2 FCFS)
//   Gantt: P1 0-2 (Q0) | P2 2-4 (Q0) | P3 4-5 | P4 5-7 | P5 7-9 (Q0) |
//          P1 9-12 (Q1) | P2 12-13 (Q1) | P5 13-15 (Q1)
//   finish      : 12 13  5  7 15
//   turnaround  : 12 12  3  4 11  (sum 42, avg 8.4)
//   waiting     :  7  9  2  2  7  (sum 27, avg 5.4)
//   response    :  0  1  2  2  3  (sum  8, avg 1.6)
//   context switches: 7, demotions: 3 (P1, P2, P5 -> Q1)
// ======================================================================
TEST(mlfq_example_A) {
    Config cfg = exampleConfig();
    ClassicMLFQScheduler s(cfg);
    SimResult r = s.run(exampleBasicWorkload());
    expectTimes(r, {12, 13, 5, 7, 15}, {7, 9, 2, 2, 7}, {12, 12, 3, 4, 11}, {0, 1, 2, 2, 3});
    CHECK_EQ(r.contextSwitches, 7LL);
    CHECK_EQ(r.demotions, 3LL);
}

// ======================================================================
// Example A — FCFS with a context-switch cost of 1 tick
//   Gantt: P1 0-5 | cs | P2 6-9 | cs | P3 10-11 | cs | P4 12-14 | cs | P5 15-19
//   finish  : 5 9 11 14 19
//   waiting : 0 5  8  9 11
//   4 switches x 1 tick = 4 overhead ticks, CPU busy 15 of 19 ticks
// ======================================================================
TEST(fcfs_context_switch_cost) {
    Config cfg = exampleConfig();
    cfg.contextSwitchCost = 1;
    FCFSScheduler s(cfg);
    SimResult r = s.run(exampleBasicWorkload());
    expectTimes(r, {5, 9, 11, 14, 19}, {0, 5, 8, 9, 11}, {5, 8, 9, 11, 15}, {0, 5, 8, 9, 11});
    CHECK_EQ(r.contextSwitches, 4LL);
    CHECK_EQ(r.csOverheadTicks, 4LL);
    CHECK_EQ(r.busyTicks, 15LL);
    CHECK_EQ(r.makespan, 19LL);
}

// The CPU must idle (and the clock jump) when nothing has arrived yet.
TEST(idle_gap_handling) {
    Config cfg = exampleConfig();
    std::vector<PCB> w = {makePCB(1, "A", 0, 2, 0, false), makePCB(2, "B", 10, 3, 0, false)};
    FCFSScheduler s(cfg);
    SimResult r = s.run(w);
    expectTimes(r, {2, 13}, {0, 0}, {2, 3}, {0, 0});
    CHECK_EQ(r.idleTicks, 8LL);
    CHECK_EQ(r.makespan, 13LL);
}

// The sample file must describe exactly Example A.
TEST(workload_file_matches_example_A) {
    std::vector<PCB> fromFile;
    std::string err;
    bool ok = loadWorkload("workloads/hand_basic.txt", fromFile, err);
    CHECK(ok);
    if (!ok) { std::cout << "    " << err << "\n"; return; }
    auto expected = exampleBasicWorkload();
    CHECK_EQ(fromFile.size(), expected.size());
    for (size_t i = 0; i < fromFile.size() && i < expected.size(); ++i) {
        CHECK_EQ(fromFile[i].pid, expected[i].pid);
        CHECK_EQ(fromFile[i].arrival, expected[i].arrival);
        CHECK_EQ(fromFile[i].burst, expected[i].burst);
    }
}

// ======================================================================
// Phase 2 — threaded ingestion
// ======================================================================
static bool sameWorkload(const std::vector<PCB>& a, const std::vector<PCB>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].pid != b[i].pid || a[i].sourceId != b[i].sourceId || a[i].arrival != b[i].arrival ||
            a[i].burst != b[i].burst || a[i].payloadAnomaly != b[i].payloadAnomaly ||
            a[i].groundTruthMalicious != b[i].groundTruthMalicious)
            return false;
    }
    return true;
}

// Same seed => byte-identical workload, even though threads interleave differently.
TEST(ingestion_is_deterministic) {
    Config cfg;
    Ingestion ing(cfg);
    GenerationParams gp;
    gp.legit = 50; gp.bots = 200; gp.seed = 42; gp.attack = AttackType::MIXED;
    auto first = ing.generate(gp);
    for (int run = 0; run < 5; ++run) CHECK(sameWorkload(first, ing.generate(gp)));
    gp.seed = 43;
    CHECK(!sameWorkload(first, ing.generate(gp)));
}

TEST(ingestion_counts_and_labels) {
    Config cfg;
    Ingestion ing(cfg);
    for (AttackType a : {AttackType::NONE, AttackType::DDOS, AttackType::STUFFING, AttackType::MIXED}) {
        GenerationParams gp;
        gp.legit = 30; gp.bots = 90; gp.seed = 7; gp.attack = a;
        IngestionStats st;
        auto w = ing.generate(gp, &st);
        int legit = 0, mal = 0;
        for (const auto& p : w) (p.groundTruthMalicious ? mal : legit)++;
        CHECK_EQ(legit, 30);
        CHECK_EQ(mal, a == AttackType::NONE ? 0 : 90);
        CHECK_EQ(st.requests, w.size());
        // pids are 1..N in arrival order
        for (size_t i = 0; i < w.size(); ++i) {
            CHECK_EQ(w[i].pid, static_cast<int>(i) + 1);
            if (i) CHECK(w[i - 1].arrival <= w[i].arrival);
        }
    }
}

// A capacity-1 buffer forces producers to block constantly: nothing may be lost.
TEST(ingestion_tiny_buffer_stress) {
    Config cfg;
    cfg.bufferCapacity = 1;
    Ingestion ing(cfg);
    GenerationParams gp;
    gp.legit = 100; gp.bots = 400; gp.seed = 99; gp.attack = AttackType::MIXED;
    IngestionStats st;
    auto w = ing.generate(gp, &st);
    CHECK_EQ(w.size(), static_cast<size_t>(500));
    CHECK_EQ(st.peakBuffer, static_cast<size_t>(1));
    Config big;
    CHECK(sameWorkload(w, Ingestion(big).generate(gp)));  // buffer size must not change the result
}

// ======================================================================
// Phase 3 — Security auditor
//   window 10, velocityCap 0.5, frequencyCap 5, weights 0.5/0.2/0.3
//   score = 0.5*min(1,(n/10)/0.5) + 0.2*min(1,total/5) + 0.3*meanAnomaly
// ======================================================================
TEST(auditor_scores) {
    Config cfg = exampleConfig();
    SecurityAuditor aud(cfg);

    aud.recordArrival("BOT", 1, 0.5);
    ThreatAssessment a = aud.assess("BOT", 1);       // 0.5*0.2 + 0.2*0.2 + 0.3*0.5 = 0.29
    CHECK_NEAR(a.velocity, 0.1, 1e-9);
    CHECK_NEAR(a.score, 0.29, 1e-9);
    CHECK(a.level == ThreatLevel::CLEAN);

    aud.recordArrival("BOT", 2, 0.5);
    a = aud.assess("BOT", 2);                         // 0.5*0.4 + 0.2*0.4 + 0.15 = 0.43
    CHECK_NEAR(a.score, 0.43, 1e-9);
    CHECK(a.level == ThreatLevel::SUSPICIOUS);

    aud.recordArrival("BOT", 4, 0.5);
    a = aud.assess("BOT", 4);                         // 0.5*0.6 + 0.2*0.6 + 0.15 = 0.57
    CHECK_NEAR(a.score, 0.57, 1e-9);
    CHECK(a.level == ThreatLevel::MALICIOUS);

    a = aud.assess("BOT", 11);                        // tick 1 left the window (1 <= 11-10)
    CHECK_NEAR(a.velocity, 0.2, 1e-9);                // 0.5*0.4 + 0.2*0.6 + 0.15 = 0.47
    CHECK_NEAR(a.score, 0.47, 1e-9);
    CHECK(a.level == ThreatLevel::SUSPICIOUS);

    a = aud.assess("BOT", 14);                        // window empty; only lifetime frequency left
    CHECK_NEAR(a.score, 0.12, 1e-9);
    CHECK(a.level == ThreatLevel::CLEAN);

    a = aud.assess("NEVER-SEEN", 14);
    CHECK_NEAR(a.score, 0.0, 1e-12);
}

// ======================================================================
// Example B — Adaptive MLFQ (see manual_verification.md, section B)
//   Gantt: P1 0-4 (Q0) | P4 4-6 (Q0) | P6 6-9 (Q0) | P2 9-12 | P3 12-15 | P5 15-17 (Q2)
//   finish     : 4 12 15  6 17  9
//   waiting    : 0  8 10  1 11  1      legit avg 0.667, malicious avg 9.667
//   turnaround : 4 11 13  3 13  4
//   response   : 0  8 10  1 11  1
//   switches 5 (3 of them loading bots), demotions 3, time-to-isolate BOT = 3
// ======================================================================
TEST(adaptive_example_B) {
    Config cfg = exampleConfig();
    AdaptiveMLFQScheduler s(cfg);
    SimResult r = s.run(exampleSecurityWorkload());
    expectTimes(r, {4, 12, 15, 6, 17, 9}, {0, 8, 10, 1, 11, 1}, {4, 11, 13, 3, 13, 4}, {0, 8, 10, 1, 11, 1});
    CHECK_EQ(r.contextSwitches, 5LL);
    CHECK_EQ(r.csOnMalicious, 3LL);
    CHECK_EQ(r.demotions, 3LL);
    CHECK_EQ(r.forcedPreemptions, 0LL);
    // P2: Q0 -> Q1 (t=2) -> Q2 (t=4); P3: Q1 -> Q2 (t=4); P5 placed in Q2 on arrival
    CHECK_EQ(r.procs[1].demotionCount, 2);
    CHECK_EQ(r.procs[2].demotionCount, 1);
    CHECK_EQ(r.procs[4].demotionCount, 0);
    for (int i : {1, 2, 4}) { CHECK_EQ(r.procs[i].isolatedAt, 4LL); CHECK_EQ(r.procs[i].maxLevelReached, 2); }
    for (int i : {0, 3, 5}) CHECK_EQ(r.procs[i].maxLevelReached, 0);   // legit never demoted

    Metrics m = computeMetrics(r);
    CHECK_NEAR(m.legit.avgWait, 2.0 / 3.0, 1e-9);
    CHECK_NEAR(m.malicious.avgWait, 29.0 / 3.0, 1e-9);
    CHECK_NEAR(m.all.avgWait, 31.0 / 6.0, 1e-9);
    CHECK_EQ(m.botSources, 1);
    CHECK_EQ(m.botSourcesIsolated, 1);
    CHECK_NEAR(m.avgTimeToIsolate, 3.0, 1e-9);
    CHECK_EQ(m.legitFalseQuarantine, 0);
}

// Same workload under FCFS: legit P4 and P6 queue behind the bots.
//   Gantt: P1 0-4 | P2 4-7 | P3 7-10 | P4 10-12 | P5 12-14 | P6 14-17
//   waiting: 0 3 5 7 8 9  -> legit avg (0+7+9)/3 = 5.333
TEST(fcfs_example_B) {
    Config cfg = exampleConfig();
    FCFSScheduler s(cfg);
    SimResult r = s.run(exampleSecurityWorkload());
    expectTimes(r, {4, 7, 10, 12, 14, 17}, {0, 3, 5, 7, 8, 9}, {4, 6, 8, 9, 10, 12}, {0, 3, 5, 7, 8, 9});
    Metrics m = computeMetrics(r);
    CHECK_NEAR(m.legit.avgWait, 16.0 / 3.0, 1e-9);
}

// ======================================================================
// Example C — forced preemption
//   t=0  P1(BOT) score 0.29 -> Q0, starts running
//   t=1  P2(BOT) 0.43, P3(BOT) 0.57 -> MALICIOUS; P1 is ON the CPU -> kicked off
//   Gantt: P1 0-1 (Q0) | P4 1-3 (Q0) | P1 3-7 | P2 7-8 | P3 8-9 (Q2)
//   finish 7 8 9 3, waiting 2 6 7 0
// ======================================================================
TEST(adaptive_forced_preemption_example_C) {
    Config cfg = exampleConfig();
    AdaptiveMLFQScheduler s(cfg);
    SimResult r = s.run(exampleForcedPreemptionWorkload());
    expectTimes(r, {7, 8, 9, 3}, {2, 6, 7, 0}, {7, 7, 8, 2}, {0, 6, 7, 0});
    CHECK_EQ(r.forcedPreemptions, 1LL);
    CHECK_EQ(r.procs[0].demotionCount, 1);
    CHECK_EQ(r.procs[0].isolatedAt, 1LL);
    CHECK_EQ(r.contextSwitches, 4LL);
    CHECK_EQ(r.csOnMalicious, 3LL);
    Metrics m = computeMetrics(r);
    CHECK_NEAR(m.avgTimeToIsolate, 1.0, 1e-9);
}

// ======================================================================
// Aging / promotion. Three BOT requests at t=0 (scores 0.29, 0.43, 0.57)
// all end up in Q2; a legit 30-tick job L1 holds Q0.
//   t=10 the window empties -> BOT score 0.12 (CLEAN), calm clock starts
//   t=15 calm for K=5 ticks -> promoted Q2 -> Q1
//   t=20 calm for another 5 -> promoted Q1 -> Q0, join RR behind L1
//   Gantt: L1 0-20 | P1 20-21 | P2 21-22 | P3 22-23 | L1 23-33
// ======================================================================
static std::vector<PCB> agingWorkload() {
    return {makePCB(1, "BOT", 0, 1, 0.5, true), makePCB(2, "BOT", 0, 1, 0.5, true),
            makePCB(3, "BOT", 0, 1, 0.5, true), makePCB(4, "L1", 0, 30, 0.0, false)};
}

TEST(adaptive_promotion_aging) {
    Config cfg = exampleConfig();
    cfg.promotionAgingTicks = 5;
    cfg.rehabCeiling = 0;                    // allow full rehabilitation back to Q0
    AdaptiveMLFQScheduler s(cfg);
    SimResult r = s.run(agingWorkload());
    CHECK_EQ(r.promotions, 6LL);
    CHECK_EQ(r.demotions, 2LL);              // P1 (Q0->Q2) and P2 (Q1->Q2) at t=0
    for (int i = 0; i < 3; ++i) {
        CHECK_EQ(r.procs[i].finishTime, static_cast<Tick>(21 + i));
        CHECK_EQ(r.procs[i].lastPromotionTick, 20LL);
        CHECK_EQ(r.procs[i].isolatedAt, 0LL);
    }
    CHECK_EQ(r.procs[3].finishTime, 33LL);
}

// Same, with the default rehabilitation ceiling (Q1): BOT was MALICIOUS, so it
// is promoted Q2 -> Q1 at t=15 but never back into Q0. Q1 waits for Q0 to
// empty, so the bots run after L1: L1 0-30 | P1 30-31 | P2 31-32 | P3 32-33.
TEST(adaptive_rehab_ceiling) {
    Config cfg = exampleConfig();
    cfg.promotionAgingTicks = 5;
    cfg.rehabCeiling = 1;
    AdaptiveMLFQScheduler s(cfg);
    SimResult r = s.run(agingWorkload());
    CHECK_EQ(r.promotions, 3LL);
    CHECK_EQ(r.procs[3].finishTime, 30LL);
    for (int i = 0; i < 3; ++i) {
        CHECK_EQ(r.procs[i].finishTime, static_cast<Tick>(31 + i));
        CHECK_EQ(r.procs[i].lastPromotionTick, 15LL);
    }
}

// Anti-starvation: K is huge so no aging; after 8 ticks in Q2 the bots are
// boosted to Q1 (and shielded from re-demotion). Q1 still yields to Q0, so
// they run right after L1: 30-31, 31-32, 32-33.
TEST(adaptive_anti_starvation) {
    Config cfg = exampleConfig();
    cfg.starvationAging = true;
    cfg.starvationLimit = 8;
    AdaptiveMLFQScheduler s(cfg);
    SimResult r = s.run(agingWorkload());
    CHECK_EQ(r.starvationBoosts, 3LL);
    CHECK_EQ(r.promotions, 0LL);
    CHECK_EQ(r.procs[3].finishTime, 30LL);
    for (int i = 0; i < 3; ++i) {
        CHECK_EQ(r.procs[i].finishTime, static_cast<Tick>(31 + i));
        CHECK_EQ(r.procs[i].lastPromotionTick, 8LL);
    }

    cfg.starvationAging = false;                       // and it can be switched off
    AdaptiveMLFQScheduler off(cfg);
    CHECK_EQ(off.run(agingWorkload()).starvationBoosts, 0LL);
}

// With no attackers the adaptive scheduler is just Round Robin with the
// same quantum: identical schedule on Example A.
TEST(adaptive_equals_rr_without_threats) {
    Config cfg = exampleConfig();
    AdaptiveMLFQScheduler a(cfg);
    RoundRobinScheduler rr(cfg);
    SimResult ra = a.run(exampleBasicWorkload()), rr_ = rr.run(exampleBasicWorkload());
    for (size_t i = 0; i < ra.procs.size(); ++i) CHECK_EQ(ra.procs[i].finishTime, rr_.procs[i].finishTime);
    CHECK_EQ(ra.contextSwitches, rr_.contextSwitches);
}

// ----------------------------------------------------------------------
int main() {
    std::cout << "Running " << registry().size() << " test cases\n";
    int failedCases = 0;
    for (auto& t : registry()) {
        int before = g_failures;
        t.fn();
        bool ok = g_failures == before;
        if (!ok) ++failedCases;
        std::cout << (ok ? "  [PASS] " : "  [FAIL] ") << t.name << "\n";
    }
    std::cout << "\n" << g_checks << " checks, " << g_failures << " failed, "
              << failedCases << "/" << registry().size() << " test cases failed\n";
    return g_failures == 0 ? 0 : 1;
}
