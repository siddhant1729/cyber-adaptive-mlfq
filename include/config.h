// =====================================================================
//  config.h  —  all tunable parameters in one place
//
//  Defaults live here; config.ini can override any of them. The INI
//  parser is deliberately tiny: "key = value" lines, ';' or '#' start a
//  comment, and [section] headers are only for human readability.
// =====================================================================
#pragma once

#include <cstddef>
#include <string>

#include "pcb.h"

namespace cmlfq {

struct Config {
    // ---------------- scheduler ----------------
    Tick quantum            = 2;     // Q0 micro-quantum (adaptive) + RR baseline quantum
    Tick mlfqQuantum1       = 4;     // classic MLFQ: quantum of its middle queue
    Tick contextSwitchCost  = 1;     // ticks the CPU loses on every context switch
    Tick promotionAgingTicks = 100;  // K: source must stay calm this long to be promoted one level
    int  rehabCeiling       = 1;     // best queue a once-MALICIOUS source can be promoted back to
                                     // (1 = never back to Q0; 0 = full rehabilitation)
    bool starvationAging    = true;  // anti-starvation boost for Q2
    Tick starvationLimit    = 400;   // ticks a Q2 process may wait before a boost to Q1
    Tick mlfqBoostPeriod    = 0;     // classic MLFQ periodic priority boost (0 = off)

    // ---------------- security auditor ----------------
    Tick   windowTicks         = 50;    // sliding window length for velocity
    double velocityCap         = 0.12;  // req/tick that counts as "maximum" velocity (normVelocity = 1)
    double frequencyCap        = 20.0;  // lifetime requests that count as "maximum" frequency
    double wVelocity           = 0.45;  // w1
    double wFrequency          = 0.20;  // w2
    double wAnomaly            = 0.35;  // w3
    double suspiciousThreshold = 0.30;
    double maliciousThreshold  = 0.55;

    // ---------------- workload generator ----------------
    Tick   horizon                = 1000; // legit traffic is spread over [0, horizon)
    int    legitRequestsPerTrader = 2;
    Tick   legitBurstMin = 3, legitBurstMax = 8;
    double legitAnomalyMax = 0.15;
    Tick   attackStart = 200;             // first tick of the attack
    int    ddosSources = 4;               // few source IPs, very high velocity
    Tick   ddosGapMin = 2,  ddosGapMax = 6;
    Tick   ddosBurstMin = 2, ddosBurstMax = 5;
    double ddosAnomalyMin = 0.10, ddosAnomalyMax = 0.40;
    int    stuffingTokens = 40;           // many tokens, each retrying rapidly
    Tick   stuffingSpread = 300;          // tokens start within [attackStart, attackStart+spread)
    Tick   stuffingGapMin = 1, stuffingGapMax = 3;
    Tick   stuffingBurstMin = 1, stuffingBurstMax = 3;
    double stuffingAnomalyMin = 0.60, stuffingAnomalyMax = 0.95;

    // ---------------- ingestion ----------------
    std::size_t bufferCapacity = 64;      // bounded arrival buffer size

    // ---------------- reporting ----------------
    int         ganttMaxSegments = 60;
    int         tableMaxRows     = 25;
    std::string resultsDir       = "results";
};

// Load "key = value" pairs from an INI file into cfg. Unknown keys and
// malformed values are reported in `err` (loading continues). Returns
// false only if the file cannot be opened.
bool loadConfig(const std::string& path, Config& cfg, std::string& err);

// Multi-line human-readable dump (used by the interactive menu).
std::string describeConfig(const Config& cfg);

}  // namespace cmlfq
