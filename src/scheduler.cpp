// scheduler.cpp — the shared discrete-clock engine (see scheduler.h).
#include "scheduler.h"

#include <algorithm>
#include <cassert>

namespace cmlfq {

void Scheduler::addSegment(SegmentKind kind, int pid, int level, Tick start, Tick end) {
    auto& g = result_->gantt;
    // Merge with the previous block if it is the same thing and contiguous.
    if (!g.empty()) {
        GanttSegment& last = g.back();
        if (last.kind == kind && last.end == start &&
            (kind != SegmentKind::RUN || (last.pid == pid && last.level == level))) {
            last.end = end;
            return;
        }
    }
    g.push_back({kind, pid, level, start, end});
}

SimResult Scheduler::run(const std::vector<PCB>& workload) {
    SimResult res;
    res.name = name();
    res.procs = workload;
    for (auto& p : res.procs) resetRuntimeFields(p);
    std::sort(res.procs.begin(), res.procs.end(),
              [](const PCB& a, const PCB& b) { return a.pid < b.pid; });
    decorate(res);
    result_ = &res;
    reset();

    // Arrival order: by arrival tick, ties broken by pid.
    std::vector<PCB*> order;
    for (auto& p : res.procs) order.push_back(&p);
    std::stable_sort(order.begin(), order.end(),
                     [](const PCB* a, const PCB* b) {
                         return a->arrival != b->arrival ? a->arrival < b->arrival : a->pid < b->pid;
                     });

    const size_t n = order.size();
    size_t nextArrival = 0;   // index into `order`
    size_t done = 0;
    Tick now = 0;
    PCB* running = nullptr;   // process on the CPU
    PCB* lastRan = nullptr;   // last process that was loaded on the CPU
    Tick slice = 0;           // ticks the running process has used in its current slice

    // Move every process with arrival <= t from "not yet arrived" into the scheduler.
    auto admit = [&](Tick t) {
        while (nextArrival < n && order[nextArrival]->arrival <= t) {
            PCB* p = order[nextArrival++];
            p->state = ProcState::READY;
            enqueue(p, Reason::ARRIVAL, t);
        }
    };

    while (done < n) {
        // 1. arrivals
        admit(now);

        // 2. per-tick hook (security re-evaluation in the adaptive scheduler)
        onTick(now, running);

        // 3. preemption check for the running process
        if (running) {
            if (auto why = checkPreempt(*running, slice, now)) {
                running->state = ProcState::READY;
                enqueue(running, *why, now);
                running = nullptr;
            }
        }

        // 4. dispatch if the CPU is free
        if (!running) {
            if (!hasReady()) {
                // Nothing to do: jump the clock to the next arrival (CPU idle).
                assert(nextArrival < n);
                Tick next = order[nextArrival]->arrival;
                addSegment(SegmentKind::IDLE, -1, -1, now, next);
                res.idleTicks += next - now;
                now = next;
                continue;
            }
            running = dispatch(now);
            running->state = ProcState::RUNNING;
            slice = 0;

            if (lastRan != nullptr && lastRan != running) {
                ++res.contextSwitches;
                // ground truth used ONLY for statistics, never for the decision
                if (running->groundTruthMalicious) {
                    ++res.csOnMalicious;
                    res.csMaliciousTicks += cfg_.contextSwitchCost;
                }
                if (cfg_.contextSwitchCost > 0) {
                    addSegment(SegmentKind::SWITCH, -1, -1, now, now + cfg_.contextSwitchCost);
                    res.csOverheadTicks += cfg_.contextSwitchCost;
                    // The clock keeps running during the switch; requests keep arriving.
                    for (Tick k = 0; k < cfg_.contextSwitchCost; ++k) admit(++now);
                }
            }
            lastRan = running;
            if (running->startTime < 0) running->startTime = now;
        }

        // 5. execute one tick
        addSegment(SegmentKind::RUN, running->pid, running->queueLevel, now, now + 1);
        --running->remaining;
        ++slice;
        ++res.busyTicks;
        ++now;

        if (running->remaining == 0) {
            running->finishTime = now;
            running->state = ProcState::TERMINATED;
            ++done;
            onFinish(running, now);
            running = nullptr;
        }
    }

    res.makespan = now;
    for (auto& p : res.procs) {
        p.turnaroundTime = p.finishTime - p.arrival;
        p.waitingTime = p.turnaroundTime - p.burst;
        p.responseTime = p.startTime - p.arrival;
    }
    result_ = nullptr;
    return res;
}

}  // namespace cmlfq
