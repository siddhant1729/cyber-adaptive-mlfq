// =====================================================================
//  baselines.h  —  the three "standard" schedulers we compare against
//
//    FCFS        : one FIFO queue, non-preemptive.
//    RoundRobin  : one FIFO queue, preemptive with a fixed quantum.
//    ClassicMLFQ : textbook 3-level MLFQ driven ONLY by CPU usage
//                  (no security awareness):
//                    Q0  RR, quantum = cfg.quantum
//                    Q1  RR, quantum = cfg.mlfqQuantum1
//                    Q2  FCFS
//                  New processes enter Q0. Using a full quantum demotes
//                  one level. A higher queue getting work preempts a
//                  lower-level process, which goes back to the TAIL of
//                  its own queue (front of Q2, to keep FCFS order).
//                  Optional periodic boost moves everything back to Q0.
// =====================================================================
#pragma once

#include <deque>

#include "scheduler.h"

namespace cmlfq {

class FCFSScheduler : public Scheduler {
public:
    using Scheduler::Scheduler;
    std::string name() const override { return "FCFS"; }

protected:
    void reset() override { ready_.clear(); }
    void enqueue(PCB* p, Reason why, Tick now) override;
    bool hasReady() const override { return !ready_.empty(); }
    PCB* dispatch(Tick now) override;
    std::optional<Reason> checkPreempt(PCB&, Tick, Tick) override { return std::nullopt; }

private:
    std::deque<PCB*> ready_;
};

class RoundRobinScheduler : public Scheduler {
public:
    using Scheduler::Scheduler;
    std::string name() const override { return "RR"; }

protected:
    void reset() override { ready_.clear(); }
    void enqueue(PCB* p, Reason why, Tick now) override;
    bool hasReady() const override { return !ready_.empty(); }
    PCB* dispatch(Tick now) override;
    std::optional<Reason> checkPreempt(PCB& running, Tick sliceUsed, Tick now) override;

private:
    std::deque<PCB*> ready_;
};

class ClassicMLFQScheduler : public Scheduler {
public:
    using Scheduler::Scheduler;
    std::string name() const override { return "MLFQ"; }

protected:
    void reset() override;
    void enqueue(PCB* p, Reason why, Tick now) override;
    bool hasReady() const override;
    PCB* dispatch(Tick now) override;
    std::optional<Reason> checkPreempt(PCB& running, Tick sliceUsed, Tick now) override;
    void onTick(Tick now, PCB* running) override;
    void decorate(SimResult& r) const override { r.multiLevel = true; }

private:
    static constexpr int kLevels = 3;
    Tick quantumFor(int level) const;
    std::deque<PCB*> q_[kLevels];
};

}  // namespace cmlfq
