// =====================================================================
//  adaptive_mlfq.h  —  Cyber-Adaptive MLFQ (the project's main idea)
//
//  Three queues, chosen by the SECURITY behaviour of a request's source
//  rather than by how much CPU it has used:
//
//    Q0  Verified-Human       Round Robin, micro-quantum (cfg.quantum)
//    Q1  Suspicious-Throttled non-preemptive SJF (std::priority_queue on
//                             remaining burst)
//    Q2  Quarantine           FCFS by original arrival; runs ONLY when
//                             Q0 and Q1 are both empty
//
//  Between queues the policy is priority-preemptive: work appearing in a
//  higher queue preempts a running lower-queue process (so legit traders
//  never wait behind quarantined bots). Inside Q1 there is no preemption.
//
//  Feedback rules (re-evaluated EVERY tick for every live process):
//    * Arrival      : placed in the queue matching its source's level.
//    * MALICIOUS    : immediate demotion to Q2. If the process is on the
//                     CPU it is forcibly preempted at once.
//    * SUSPICIOUS   : a Q0 process moves to Q1. If it is running it
//                     finishes its current quantum first.
//    * Aging        : if the source stays below the current queue's
//                     threshold for K ticks (cfg.promotionAgingTicks),
//                     the process is promoted ONE level. Rehabilitation
//                     ceiling: a source that was EVER malicious can climb
//                     back only to cfg.rehabCeiling (default Q1), so an
//                     attacker's queued backlog never floods the fast lane
//                     after the attack stops.
//    * Anti-starvation (optional): a process that waited in Q2 for
//                     cfg.starvationLimit ticks is boosted to Q1 and is
//                     shielded from re-demotion until it next leaves the CPU.
//
//  A Q0 process whose quantum expires simply goes back to the tail of
//  Q0 — CPU usage alone NEVER demotes a process here. That is the key
//  difference from the classic MLFQ.
// =====================================================================
#pragma once

#include <deque>
#include <map>
#include <queue>
#include <vector>

#include "scheduler.h"
#include "security_auditor.h"

namespace cmlfq {

class AdaptiveMLFQScheduler : public Scheduler {
public:
    explicit AdaptiveMLFQScheduler(const Config& cfg) : Scheduler(cfg), auditor_(cfg) {}
    std::string name() const override { return "Adaptive-MLFQ"; }

protected:
    void reset() override;
    void enqueue(PCB* p, Reason why, Tick now) override;
    bool hasReady() const override;
    PCB* dispatch(Tick now) override;
    std::optional<Reason> checkPreempt(PCB& running, Tick sliceUsed, Tick now) override;
    void onTick(Tick now, PCB* running) override;
    void onFinish(PCB* p, Tick now) override;
    void decorate(SimResult& r) const override { r.multiLevel = true; r.securityAware = true; }

private:
    static constexpr int Q0 = 0, Q1 = 1, Q2 = 2;

    // Q1 ordering: shortest remaining burst first, ties by arrival then pid.
    struct ShorterJobFirst {
        bool operator()(const PCB* a, const PCB* b) const {   // true => a has LOWER priority
            if (a->remaining != b->remaining) return a->remaining > b->remaining;
            if (a->arrival != b->arrival) return a->arrival > b->arrival;
            return a->pid > b->pid;
        }
    };

    void place(PCB* p, Tick now);                     // push into the queue for p->queueLevel
    void changeLevel(PCB* p, int newLevel, Tick now, const char* kind = nullptr); // bookkeeping for demotion/promotion
    void applyAssessment(PCB* p, const ThreatAssessment& a);
    void rebuildQueues(Tick now);                     // re-place every ready process

    SecurityAuditor auditor_;
    std::deque<PCB*> q0_;
    std::priority_queue<PCB*, std::vector<PCB*>, ShorterJobFirst> q1_;
    std::deque<PCB*> q2_;                             // kept sorted by (arrival, pid)
    std::map<int, PCB*> live_;                        // arrived, unfinished processes by pid

    bool forcePreempt_ = false;                       // running process became MALICIOUS
    int  pendingLevel_ = -1;                          // running process became SUSPICIOUS
};

}  // namespace cmlfq
