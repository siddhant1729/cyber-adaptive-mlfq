// =====================================================================
//  scheduler.h  —  the discrete-clock simulation engine
//
//  All schedulers (FCFS, RR, classic MLFQ, Adaptive MLFQ) share ONE
//  tick-by-tick engine: Scheduler::run(). A concrete scheduler only
//  supplies its queue policy through a few virtual "hooks":
//
//      enqueue()       put a process into a ready queue
//      hasReady()      is any process waiting?
//      dispatch()      pick + remove the next process to run
//      checkPreempt()  should the running process be kicked off now?
//      onTick()        called every tick (the adaptive scheduler runs
//                      its security re-evaluation here)
//
//  Engine loop, for every tick `now`:
//      1. admit every process whose arrival == now   (enqueue ARRIVAL)
//      2. onTick(now)
//      3. if the running process must be preempted -> enqueue it again
//      4. if the CPU is free -> dispatch (paying the context-switch cost
//         if a DIFFERENT process than the last one is loaded)
//      5. execute the running process for exactly one tick
//
//  Conventions (important for hand calculation):
//    * New arrivals at tick t are enqueued BEFORE a process preempted
//      at tick t (the textbook Round-Robin convention).
//    * A context switch is counted whenever the CPU loads a process
//      different from the one that ran last. The very first dispatch
//      is not counted. Re-dispatching the same process is free.
//    * waiting = turnaround - burst, turnaround = finish - arrival,
//      response = first start - arrival.
// =====================================================================
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.h"
#include "pcb.h"

namespace cmlfq {

enum class SegmentKind { RUN, IDLE, SWITCH };

// One contiguous block of the Gantt chart.
struct GanttSegment {
    SegmentKind kind;
    int  pid;     // valid only for RUN
    int  level;   // queue level the process ran at (RUN only)
    Tick start;
    Tick end;     // exclusive
};

// One security decision taken by the adaptive scheduler (for the web UI log).
struct SecurityEvent {
    Tick        tick;
    int         pid;
    int         fromLevel;
    int         toLevel;
    std::string kind;    // "arrive" | "demote" | "promote" | "boost" | "forced-preempt"
    double      score;   // source threat score at that moment
};

// Everything one simulation run produces. Analytics turns this into metrics.
struct SimResult {
    std::string name;                 // e.g. "FCFS", "Adaptive-MLFQ"
    bool multiLevel = false;          // show queue levels in reports?
    bool securityAware = false;       // true only for the adaptive scheduler
    std::vector<PCB> procs;           // final PCBs (sorted by pid)
    std::vector<GanttSegment> gantt;

    long long contextSwitches  = 0;   // number of switches
    long long csOnMalicious    = 0;   // switches that loaded a malicious process
    Tick      csOverheadTicks  = 0;   // ticks lost to switching
    Tick      csMaliciousTicks = 0;   // ... of which spent loading malicious processes
    Tick      busyTicks = 0;          // ticks spent executing processes
    Tick      idleTicks = 0;          // ticks with nothing to run
    Tick      makespan  = 0;          // tick at which the last process finished

    // adaptive-only counters
    long long forcedPreemptions = 0;  // running process kicked off for being MALICIOUS
    long long demotions  = 0;
    long long promotions = 0;
    long long starvationBoosts = 0;
    std::vector<SecurityEvent> events; // adaptive only: every queue-level decision
};

class Scheduler {
public:
    explicit Scheduler(const Config& cfg) : cfg_(cfg) {}
    virtual ~Scheduler() = default;

    virtual std::string name() const = 0;

    // Simulate the whole workload. The input vector is copied, so the
    // same workload can be passed to every scheduler.
    SimResult run(const std::vector<PCB>& workload);

protected:
    // Why a process is being (re-)inserted into a ready queue.
    enum class Reason {
        ARRIVAL,          // brand new
        QUANTUM_EXPIRED,  // used its whole time slice
        PREEMPTED,        // a higher-priority queue got work
        SECURITY          // forced off the CPU by the security auditor
    };

    virtual void reset() = 0;                                   // clear queues before a run
    virtual void enqueue(PCB* p, Reason why, Tick now) = 0;
    virtual bool hasReady() const = 0;
    virtual PCB* dispatch(Tick now) = 0;
    virtual std::optional<Reason> checkPreempt(PCB& running, Tick sliceUsed, Tick now) = 0;
    virtual void onTick(Tick /*now*/, PCB* /*running*/) {}
    virtual void onFinish(PCB* /*p*/, Tick /*now*/) {}
    virtual void decorate(SimResult& /*r*/) const {}            // set name/flags on the result

    const Config& cfg_;
    SimResult* result_ = nullptr;     // valid during run(); lets hooks bump counters

private:
    void addSegment(SegmentKind kind, int pid, int level, Tick start, Tick end);
};

}  // namespace cmlfq
