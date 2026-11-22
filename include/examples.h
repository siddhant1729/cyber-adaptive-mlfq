// =====================================================================
//  examples.h  —  small hand-computable workloads
//
//  These are used by tests/test_main.cpp (which asserts the exact
//  numbers worked out in tests/manual_verification.md) and by the
//  interactive menu's "hand verification" option for the viva.
// =====================================================================
#pragma once

#include <vector>

#include "config.h"
#include "pcb.h"

namespace cmlfq {

// Example A — 5 processes, no attack. Used for FCFS / RR / classic MLFQ.
//   pid source arrival burst
//    1   A      0       5
//    2   B      1       3
//    3   C      2       1
//    4   D      3       2
//    5   E      4       4
std::vector<PCB> exampleBasicWorkload();

// Example B — 6 processes, one bot source "BOT" sending 3 rapid requests.
std::vector<PCB> exampleSecurityWorkload();

// Example C — 4 processes; a bot is RUNNING when its source turns
// malicious, demonstrating forced preemption.
std::vector<PCB> exampleForcedPreemptionWorkload();

// The small, round-number configuration used for all hand examples:
//   quantum 2, context-switch cost 0, window 10 ticks, velocity cap
//   0.5 req/tick, frequency cap 5, weights 0.5/0.2/0.3, thresholds
//   0.30 (suspicious) / 0.55 (malicious), promotion aging K = 100,
//   anti-starvation off.
Config exampleConfig();

}  // namespace cmlfq
