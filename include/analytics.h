// =====================================================================
//  analytics.h  —  turn a SimResult into comparable metrics
//
//  Definitions (all in ticks unless stated):
//    waiting time    = turnaround - burst      (time spent not running)
//    turnaround time = finish - arrival
//    response time   = first start - arrival
//    throughput      = completed processes per 1000 ticks of makespan
//    CPU utilisation = busy ticks / makespan * 100 %
//                      (context-switch and idle ticks are NOT busy)
//    P95 wait        = 95th percentile waiting time (nearest-rank)
//    time-to-isolate = for each malicious source: first tick any of its
//                      processes entered Q2  -  first arrival of that source
//
//  Every metric is reported for ALL processes and separately for the
//  LEGIT and MALICIOUS classes (ground-truth labels from the workload).
// =====================================================================
#pragma once

#include <string>

#include "scheduler.h"

namespace cmlfq {

struct ClassMetrics {
    int    count = 0;
    double avgWait = 0.0;
    double avgTurnaround = 0.0;
    double avgResponse = 0.0;
    double p95Wait = 0.0;
    Tick   maxWait = 0;
    Tick   lastFinish = 0;
};

struct Metrics {
    std::string scheduler;
    bool securityAware = false;

    ClassMetrics all, legit, malicious;

    double throughput = 0.0;        // processes / 1000 ticks
    double legitThroughput = 0.0;   // legit processes / 1000 ticks
    double cpuUtilization = 0.0;    // percent
    long long contextSwitches = 0;
    long long csOnMalicious = 0;
    Tick csOverheadTicks = 0;
    Tick csMaliciousTicks = 0;
    Tick makespan = 0;

    // security (meaningful for the adaptive scheduler only)
    int    botSources = 0;
    int    botSourcesIsolated = 0;
    double avgTimeToIsolate = 0.0;
    Tick   minTimeToIsolate = 0;
    Tick   maxTimeToIsolate = 0;
    int    maliciousQuarantined = 0;   // malicious processes that reached Q2
    int    maliciousContained = 0;     // malicious processes that reached Q1 or Q2 (throttled or quarantined)
    int    legitThrottled = 0;         // legit processes that ever left Q0 (false positive, mild)
    int    legitFalseQuarantine = 0;   // legit processes that reached Q2 (false positive, severe)
    long long forcedPreemptions = 0;
    long long demotions = 0;
    long long promotions = 0;
    long long starvationBoosts = 0;
};

Metrics computeMetrics(const SimResult& r);

}  // namespace cmlfq
