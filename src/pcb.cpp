// pcb.cpp — helpers for the Process Control Block.
#include "pcb.h"

namespace cmlfq {

const char* toString(ProcState s) {
    switch (s) {
        case ProcState::NEW:        return "NEW";
        case ProcState::READY:      return "READY";
        case ProcState::RUNNING:    return "RUNNING";
        case ProcState::WAITING:    return "WAITING";
        case ProcState::TERMINATED: return "TERMINATED";
    }
    return "?";
}

PCB makePCB(int pid, const std::string& source, Tick arrival, Tick burst,
            double payloadAnomaly, bool malicious) {
    PCB p;
    p.pid = pid;
    p.sourceId = source;
    p.arrival = arrival;
    p.burst = burst;
    p.remaining = burst;
    p.payloadAnomaly = payloadAnomaly;
    p.groundTruthMalicious = malicious;
    return p;
}

void resetRuntimeFields(PCB& p) {
    p.remaining = p.burst;
    p.queueLevel = 0;
    p.state = ProcState::NEW;
    p.startTime = -1;
    p.finishTime = -1;
    p.waitingTime = p.turnaroundTime = p.responseTime = 0;
    p.requestVelocity = p.requestFrequency = 0.0;
    p.threatScore = p.peakThreatScore = 0.0;
    p.demotionCount = 0;
    p.lastPromotionTick = -1;
    p.lastLevelChangeTick = 0;
    p.calmSinceTick = -1;
    p.readySinceTick = 0;
    p.isolatedAt = -1;
    p.maxLevelReached = 0;
    p.agingShield = false;
    // payloadAnomaly and groundTruthMalicious are INPUTS — keep them.
}

}  // namespace cmlfq
