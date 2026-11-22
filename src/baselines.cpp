// baselines.cpp — FCFS, Round Robin and classic (CPU-burst) MLFQ.
#include "baselines.h"

namespace cmlfq {

// ============================ FCFS ===================================
void FCFSScheduler::enqueue(PCB* p, Reason /*why*/, Tick /*now*/) {
    ready_.push_back(p);   // never preempted, so only ARRIVAL reaches here
}

PCB* FCFSScheduler::dispatch(Tick /*now*/) {
    PCB* p = ready_.front();
    ready_.pop_front();
    return p;
}

// ============================ Round Robin ============================
void RoundRobinScheduler::enqueue(PCB* p, Reason /*why*/, Tick /*now*/) {
    ready_.push_back(p);   // arrivals and expired processes both go to the tail
}

PCB* RoundRobinScheduler::dispatch(Tick /*now*/) {
    PCB* p = ready_.front();
    ready_.pop_front();
    return p;
}

std::optional<Scheduler::Reason>
RoundRobinScheduler::checkPreempt(PCB& /*running*/, Tick sliceUsed, Tick /*now*/) {
    if (sliceUsed >= cfg_.quantum) return Reason::QUANTUM_EXPIRED;
    return std::nullopt;
}

// ============================ Classic MLFQ ===========================
void ClassicMLFQScheduler::reset() {
    for (auto& q : q_) q.clear();
}

Tick ClassicMLFQScheduler::quantumFor(int level) const {
    return level == 0 ? cfg_.quantum : cfg_.mlfqQuantum1;   // level 2 is FCFS (no quantum)
}

void ClassicMLFQScheduler::enqueue(PCB* p, Reason why, Tick /*now*/) {
    switch (why) {
        case Reason::ARRIVAL:
            p->queueLevel = 0;
            q_[0].push_back(p);
            break;
        case Reason::QUANTUM_EXPIRED:
            // Used the full slice -> looks CPU-bound -> demote one level.
            if (p->queueLevel < kLevels - 1) {
                ++p->queueLevel;
                ++p->demotionCount;
                ++result_->demotions;
            }
            q_[p->queueLevel].push_back(p);
            break;
        case Reason::PREEMPTED:
        case Reason::SECURITY:   // not used by this scheduler
            if (p->queueLevel == kLevels - 1) q_[p->queueLevel].push_front(p);  // keep FCFS order
            else                              q_[p->queueLevel].push_back(p);
            break;
    }
    if (p->queueLevel > p->maxLevelReached) p->maxLevelReached = p->queueLevel;
}

bool ClassicMLFQScheduler::hasReady() const {
    for (const auto& q : q_) if (!q.empty()) return true;
    return false;
}

PCB* ClassicMLFQScheduler::dispatch(Tick /*now*/) {
    for (auto& q : q_) {
        if (!q.empty()) {
            PCB* p = q.front();
            q.pop_front();
            return p;
        }
    }
    return nullptr;  // unreachable: engine checks hasReady() first
}

std::optional<Scheduler::Reason>
ClassicMLFQScheduler::checkPreempt(PCB& running, Tick sliceUsed, Tick /*now*/) {
    int lvl = running.queueLevel;
    if (lvl < kLevels - 1 && sliceUsed >= quantumFor(lvl)) return Reason::QUANTUM_EXPIRED;
    for (int higher = 0; higher < lvl; ++higher)
        if (!q_[higher].empty()) return Reason::PREEMPTED;
    return std::nullopt;
}

void ClassicMLFQScheduler::onTick(Tick now, PCB* running) {
    // Optional periodic priority boost (classic anti-starvation rule).
    if (cfg_.mlfqBoostPeriod <= 0 || now == 0 || now % cfg_.mlfqBoostPeriod != 0) return;
    for (int lvl = 1; lvl < kLevels; ++lvl) {
        for (PCB* p : q_[lvl]) { p->queueLevel = 0; q_[0].push_back(p); }
        q_[lvl].clear();
    }
    if (running) running->queueLevel = 0;
}

}  // namespace cmlfq
