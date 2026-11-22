// =====================================================================
//  pcb.h  —  Process Control Block
//
//  Every incoming trading request (an order, a login, an API call) is
//  modelled as one "process". The PCB holds three groups of fields:
//    1. Classic OS scheduling fields (arrival, burst, state, times ...)
//    2. Security metadata filled in by the SecurityAuditor
//    3. Bookkeeping used only by the adaptive scheduler
//
//  TIME MODEL: everything is measured in integer "ticks" of a simulated
//  discrete clock. 1 tick = 1 simulated microsecond. No wall-clock time
//  is ever used for scheduling, so every run is deterministic.
// =====================================================================
#pragma once

#include <string>
#include <vector>

namespace cmlfq {

using Tick = long long;   // 1 tick = 1 simulated microsecond

// Classic five-state process model.
//   NEW        : created by ingestion, not yet arrived in the simulation
//   READY      : sitting in a ready queue (Q0 / Q1 or a baseline queue)
//   RUNNING    : currently on the (single) CPU
//   WAITING    : parked in the Quarantine queue (Q2) — it cannot be
//                dispatched while any normal work (Q0/Q1) exists
//   TERMINATED : finished its CPU burst
enum class ProcState { NEW, READY, RUNNING, WAITING, TERMINATED };

const char* toString(ProcState s);

struct PCB {
    // ---------------- identity ----------------
    int         pid = 0;
    std::string sourceId;          // simulated client IP / API token

    // ---------------- scheduling input ----------------
    Tick arrival   = 0;            // tick at which the request arrives
    Tick burst     = 0;            // CPU ticks needed
    Tick remaining = 0;            // CPU ticks still needed

    // ---------------- scheduling state ----------------
    int       queueLevel = 0;      // 0 = highest priority
    ProcState state      = ProcState::NEW;

    // ---------------- results (filled by the engine) ----------------
    Tick startTime      = -1;      // first tick on the CPU
    Tick finishTime     = -1;      // tick at which it completed
    Tick waitingTime    = 0;       // turnaround - burst
    Tick turnaroundTime = 0;       // finish - arrival
    Tick responseTime   = 0;       // start - arrival

    // ---------------- security metadata (SecurityAuditor) ----------------
    double requestVelocity  = 0.0; // requests/tick from this source in the sliding window
    double requestFrequency = 0.0; // lifetime number of requests from this source
    double payloadAnomaly   = 0.0; // 0..1, how "odd" this request's payload looks
    double threatScore      = 0.0; // weighted score, 0..1 (latest evaluation)
    double peakThreatScore  = 0.0; // highest score ever seen while alive
    int    demotionCount    = 0;   // times moved to a LOWER priority queue
    Tick   lastPromotionTick = -1; // last tick it was promoted (-1 = never)

    // ---------------- adaptive-scheduler bookkeeping ----------------
    Tick lastLevelChangeTick = 0;  // when queueLevel last changed
    Tick calmSinceTick  = -1;      // since when its source has been below its level's threshold
    Tick readySinceTick = 0;       // when it last entered a ready queue (anti-starvation)
    Tick isolatedAt     = -1;      // first tick it was placed in quarantine (Q2)
    int  maxLevelReached = 0;      // lowest-priority queue it ever sat in
    bool agingShield    = false;   // set by anti-starvation boost: no re-demotion until it runs

    // ---------------- ground truth ----------------
    // Whether the workload generator created this request as an attack.
    // The SCHEDULERS NEVER READ THIS FIELD — it is used only by Analytics
    // to split metrics into legit vs malicious and to score detection.
    bool groundTruthMalicious = false;

    bool finished() const { return state == ProcState::TERMINATED; }
};

// Convenience constructor used by the loader, the generator and the tests.
PCB makePCB(int pid, const std::string& source, Tick arrival, Tick burst,
            double payloadAnomaly, bool malicious);

// Reset every runtime/result field so the same workload can be fed to
// several schedulers one after another (each gets a fresh copy).
void resetRuntimeFields(PCB& p);

}  // namespace cmlfq
