// examples.cpp — hand-computable workloads (see examples.h and
// tests/manual_verification.md for the worked solutions).
#include "examples.h"

namespace cmlfq {

std::vector<PCB> exampleBasicWorkload() {
    return {
        makePCB(1, "A", 0, 5, 0.0, false),
        makePCB(2, "B", 1, 3, 0.0, false),
        makePCB(3, "C", 2, 1, 0.0, false),
        makePCB(4, "D", 3, 2, 0.0, false),
        makePCB(5, "E", 4, 4, 0.0, false),
    };
}

std::vector<PCB> exampleSecurityWorkload() {
    return {
        makePCB(1, "L1",  0, 4, 0.0, false),
        makePCB(2, "BOT", 1, 3, 0.5, true),
        makePCB(3, "BOT", 2, 3, 0.5, true),
        makePCB(4, "L2",  3, 2, 0.0, false),
        makePCB(5, "BOT", 4, 2, 0.5, true),
        makePCB(6, "L3",  5, 3, 0.0, false),
    };
}

std::vector<PCB> exampleForcedPreemptionWorkload() {
    return {
        makePCB(1, "BOT", 0, 5, 0.5, true),
        makePCB(2, "BOT", 1, 1, 0.5, true),
        makePCB(3, "BOT", 1, 1, 0.5, true),
        makePCB(4, "L1",  1, 2, 0.0, false),
    };
}

Config exampleConfig() {
    Config c;
    c.quantum = 2;
    c.mlfqQuantum1 = 4;
    c.contextSwitchCost = 0;
    c.promotionAgingTicks = 100;
    c.starvationAging = false;
    c.mlfqBoostPeriod = 0;
    c.windowTicks = 10;
    c.velocityCap = 0.5;
    c.frequencyCap = 5.0;
    c.wVelocity = 0.5;
    c.wFrequency = 0.2;
    c.wAnomaly = 0.3;
    c.suspiciousThreshold = 0.30;
    c.maliciousThreshold = 0.55;
    return c;
}

}  // namespace cmlfq
