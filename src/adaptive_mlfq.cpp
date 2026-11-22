// adaptive_mlfq.cpp — the security-driven MLFQ (see adaptive_mlfq.h).
#include "adaptive_mlfq.h"

#include <algorithm>
#include <unordered_map>

namespace cmlfq {

void AdaptiveMLFQScheduler::reset() {
    auditor_.reset();
    q0_.clear();
    q1_ = decltype(q1_)();
    q2_.clear();
    live_.clear();
    forcePreempt_ = false;
    pendingLevel_ = -1;
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------
void AdaptiveMLFQScheduler::applyAssessment(PCB* p, const ThreatAssessment& a) {
    p->requestVelocity = a.velocity;
    p->requestFrequency = a.frequency;
    p->threatScore = a.score;
    p->peakThreatScore = std::max(p->peakThreatScore, a.score);
}

void AdaptiveMLFQScheduler::changeLevel(PCB* p, int newLevel, Tick now) {
    if (newLevel > p->queueLevel) {           // moving DOWN in priority
        ++p->demotionCount;
        ++result_->demotions;
    }
    p->queueLevel = newLevel;
    p->lastLevelChangeTick = now;
    p->readySinceTick = now;
    p->maxLevelReached = std::max(p->maxLevelReached, newLevel);
    if (newLevel == Q2 && p->isolatedAt < 0) p->isolatedAt = now;
}

void AdaptiveMLFQScheduler::place(PCB* p, Tick /*now*/) {
    switch (p->queueLevel) {
        case Q0:
            p->state = ProcState::READY;
            q0_.push_back(p);
            break;
        case Q1:
            p->state = ProcState::READY;
            q1_.push(p);
            break;
        default: {
            // Quarantine is FCFS by ORIGINAL arrival time (ties by pid).
            p->state = ProcState::WAITING;
            auto pos = std::upper_bound(q2_.begin(), q2_.end(), p, [](const PCB* a, const PCB* b) {
                return a->arrival != b->arrival ? a->arrival < b->arrival : a->pid < b->pid;
            });
            q2_.insert(pos, p);
            break;
        }
    }
}

void AdaptiveMLFQScheduler::rebuildQueues(Tick now) {
    // Collect every ready process in current queue order, then re-place each
    // one according to its (possibly new) level. Processes staying in Q0 keep
    // their relative order; processes promoted into Q0 join at the tail.
    std::vector<PCB*> all(q0_.begin(), q0_.end());
    while (!q1_.empty()) { all.push_back(q1_.top()); q1_.pop(); }
    all.insert(all.end(), q2_.begin(), q2_.end());
    q0_.clear();
    q2_.clear();
    for (PCB* p : all) place(p, now);
}

// ---------------------------------------------------------------------
// scheduler hooks
// ---------------------------------------------------------------------
void AdaptiveMLFQScheduler::enqueue(PCB* p, Reason why, Tick now) {
    switch (why) {
        case Reason::ARRIVAL: {
            // Every new request updates its source's history and is placed
            // straight into the queue its source currently deserves.
            auditor_.recordArrival(p->sourceId, p->arrival, p->payloadAnomaly);
            ThreatAssessment a = auditor_.assess(p->sourceId, now);
            applyAssessment(p, a);
            p->queueLevel = static_cast<int>(a.level);
            p->maxLevelReached = p->queueLevel;
            p->lastLevelChangeTick = now;
            if (p->queueLevel == Q2) p->isolatedAt = now;
            live_[p->pid] = p;
            break;
        }
        case Reason::SECURITY:
            changeLevel(p, Q2, now);             // forced off the CPU -> quarantine
            break;
        case Reason::QUANTUM_EXPIRED:
        case Reason::PREEMPTED:
            // A SUSPICIOUS verdict reached while running is applied now.
            if (pendingLevel_ > p->queueLevel) changeLevel(p, pendingLevel_, now);
            break;
    }
    if (why != Reason::ARRIVAL) p->agingShield = false;   // shield lasts one CPU visit
    pendingLevel_ = -1;
    p->readySinceTick = now;
    place(p, now);
}

bool AdaptiveMLFQScheduler::hasReady() const {
    return !q0_.empty() || !q1_.empty() || !q2_.empty();
}

PCB* AdaptiveMLFQScheduler::dispatch(Tick /*now*/) {
    forcePreempt_ = false;
    pendingLevel_ = -1;
    PCB* p = nullptr;
    if (!q0_.empty())      { p = q0_.front(); q0_.pop_front(); }
    else if (!q1_.empty()) { p = q1_.top();   q1_.pop(); }
    else                   { p = q2_.front(); q2_.pop_front(); }   // only when Q0 and Q1 are empty
    return p;
}

std::optional<Scheduler::Reason>
AdaptiveMLFQScheduler::checkPreempt(PCB& running, Tick sliceUsed, Tick /*now*/) {
    if (forcePreempt_) {                       // source turned MALICIOUS while on the CPU
        forcePreempt_ = false;
        ++result_->forcedPreemptions;
        return Reason::SECURITY;
    }
    switch (running.queueLevel) {
        case Q0:  // Round Robin micro-quantum
            if (sliceUsed >= cfg_.quantum) return Reason::QUANTUM_EXPIRED;
            break;
        case Q1:  // non-preemptive SJF inside Q1, but Q0 work always wins
            if (!q0_.empty()) return Reason::PREEMPTED;
            break;
        default:  // quarantine runs only while Q0 and Q1 are empty
            if (!q0_.empty() || !q1_.empty()) return Reason::PREEMPTED;
            break;
    }
    return std::nullopt;
}

void AdaptiveMLFQScheduler::onTick(Tick now, PCB* running) {
    // Re-assess every live process's source once per tick. Iterating live_
    // (a std::map keyed by pid) keeps the order deterministic.
    std::unordered_map<std::string, ThreatAssessment> cache;
    bool queuesChanged = false;

    for (auto& entry : live_) {
        PCB* p = entry.second;
        auto it = cache.find(p->sourceId);
        if (it == cache.end()) it = cache.emplace(p->sourceId, auditor_.assess(p->sourceId, now)).first;
        const ThreatAssessment& a = it->second;
        applyAssessment(p, a);

        const int target = static_cast<int>(a.level);
        const int cur = p->queueLevel;

        // ---- the process on the CPU ----
        if (p == running) {
            if (p->agingShield) continue;
            if (target == Q2 && cur < Q2) forcePreempt_ = true;          // kick it off NOW
            else if (target > cur) pendingLevel_ = std::max(pendingLevel_, target);  // after quantum
            continue;
        }

        // ---- a process waiting in a queue ----
        if (target > cur) {                                  // source got worse: demote now
            p->calmSinceTick = -1;
            if (!p->agingShield) {
                changeLevel(p, target, now);
                queuesChanged = true;
            }
            continue;
        }
        // A source that was ever MALICIOUS may only climb back to rehabCeiling
        // (default Q1): its queued backlog must never re-enter the fast lane.
        const int ceiling = auditor_.worstLevel(p->sourceId) == ThreatLevel::MALICIOUS
                                ? std::clamp(cfg_.rehabCeiling, Q0, Q2) : Q0;
        if (target < cur && cur - 1 >= ceiling) {            // source calmer than this queue
            if (p->calmSinceTick < 0) p->calmSinceTick = now;
            if (now - p->calmSinceTick >= cfg_.promotionAgingTicks) {
                changeLevel(p, cur - 1, now);                // promote ONE level
                p->lastPromotionTick = now;
                p->calmSinceTick = now;                      // restart the clock for the next level
                ++result_->promotions;
                queuesChanged = true;
                continue;
            }
        } else {
            p->calmSinceTick = -1;
        }

        // ---- anti-starvation for the quarantine queue ----
        if (cfg_.starvationAging && p->queueLevel == Q2 &&
            now - p->readySinceTick >= cfg_.starvationLimit) {
            changeLevel(p, Q1, now);
            p->lastPromotionTick = now;
            p->agingShield = true;
            ++result_->starvationBoosts;
            queuesChanged = true;
        }
    }

    if (queuesChanged) rebuildQueues(now);
}

void AdaptiveMLFQScheduler::onFinish(PCB* p, Tick /*now*/) {
    live_.erase(p->pid);
    pendingLevel_ = -1;
    forcePreempt_ = false;
}

}  // namespace cmlfq
