// json_export.cpp — tiny hand-written JSON writer (no external library).
#include "json_export.h"

#include <cmath>
#include <iomanip>
#include <sstream>

namespace cmlfq {
namespace {

std::string esc(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) { o += ' '; } else o += c;
        }
    }
    return o + "\"";
}

std::string num(double v) {
    if (!std::isfinite(v)) return "0";
    std::ostringstream ss;
    ss << std::setprecision(6) << v;
    return ss.str();
}

void classJson(std::ostream& os, const ClassMetrics& c) {
    os << "{\"count\":" << c.count << ",\"avgWait\":" << num(c.avgWait)
       << ",\"avgTurnaround\":" << num(c.avgTurnaround) << ",\"avgResponse\":" << num(c.avgResponse)
       << ",\"p95Wait\":" << num(c.p95Wait) << ",\"maxWait\":" << c.maxWait
       << ",\"lastFinish\":" << c.lastFinish << "}";
}

void metricsJson(std::ostream& os, const Metrics& m) {
    os << "{\"scheduler\":" << esc(m.scheduler) << ",\"securityAware\":" << (m.securityAware ? "true" : "false")
       << ",\"all\":";       classJson(os, m.all);
    os << ",\"legit\":";     classJson(os, m.legit);
    os << ",\"malicious\":"; classJson(os, m.malicious);
    os << ",\"throughput\":" << num(m.throughput) << ",\"legitThroughput\":" << num(m.legitThroughput)
       << ",\"cpuUtilization\":" << num(m.cpuUtilization) << ",\"contextSwitches\":" << m.contextSwitches
       << ",\"csOnMalicious\":" << m.csOnMalicious << ",\"csOverheadTicks\":" << m.csOverheadTicks
       << ",\"makespan\":" << m.makespan << ",\"botSources\":" << m.botSources
       << ",\"botSourcesIsolated\":" << m.botSourcesIsolated << ",\"avgTimeToIsolate\":" << num(m.avgTimeToIsolate)
       << ",\"minTimeToIsolate\":" << m.minTimeToIsolate << ",\"maxTimeToIsolate\":" << m.maxTimeToIsolate
       << ",\"maliciousQuarantined\":" << m.maliciousQuarantined << ",\"maliciousContained\":" << m.maliciousContained
       << ",\"legitThrottled\":" << m.legitThrottled << ",\"legitFalseQuarantine\":" << m.legitFalseQuarantine
       << ",\"forcedPreemptions\":" << m.forcedPreemptions << ",\"demotions\":" << m.demotions
       << ",\"promotions\":" << m.promotions << ",\"starvationBoosts\":" << m.starvationBoosts << "}";
}

void configJson(std::ostream& os, const Config& c) {
    os << "{\"quantum\":" << c.quantum << ",\"mlfqQuantum1\":" << c.mlfqQuantum1
       << ",\"contextSwitchCost\":" << c.contextSwitchCost << ",\"promotionAgingTicks\":" << c.promotionAgingTicks
       << ",\"rehabCeiling\":" << c.rehabCeiling << ",\"starvationAging\":" << (c.starvationAging ? "true" : "false")
       << ",\"starvationLimit\":" << c.starvationLimit << ",\"windowTicks\":" << c.windowTicks
       << ",\"velocityCap\":" << num(c.velocityCap) << ",\"frequencyCap\":" << num(c.frequencyCap)
       << ",\"wVelocity\":" << num(c.wVelocity) << ",\"wFrequency\":" << num(c.wFrequency)
       << ",\"wAnomaly\":" << num(c.wAnomaly) << ",\"suspiciousThreshold\":" << num(c.suspiciousThreshold)
       << ",\"maliciousThreshold\":" << num(c.maliciousThreshold) << "}";
}

const char* segKind(SegmentKind k) {
    switch (k) {
        case SegmentKind::RUN: return "run";
        case SegmentKind::IDLE: return "idle";
        default: return "switch";
    }
}

}  // namespace

void writeCompareJson(std::ostream& os, const std::string& label, const Config& cfg,
                      const std::vector<PCB>& workload, const IngestionStats* ing,
                      const std::vector<SimResult>& results, const std::vector<Metrics>& metrics) {
    os << "{\"mode\":\"compare\",\"label\":" << esc(label) << ",\"config\":";
    configJson(os, cfg);
    if (ing) {
        os << ",\"ingestion\":{\"producerThreads\":" << ing->producerThreads << ",\"legitSources\":" << ing->legitSources
           << ",\"botSources\":" << ing->botSources << ",\"requests\":" << ing->requests
           << ",\"peakBuffer\":" << ing->peakBuffer << ",\"producerWaits\":" << ing->producerWaits
           << ",\"wallMillis\":" << num(ing->wallMillis) << "}";
    }
    os << ",\"workload\":[";
    for (size_t i = 0; i < workload.size(); ++i) {
        const PCB& p = workload[i];
        os << (i ? "," : "") << "{\"pid\":" << p.pid << ",\"source\":" << esc(p.sourceId)
           << ",\"arrival\":" << p.arrival << ",\"burst\":" << p.burst
           << ",\"anomaly\":" << num(p.payloadAnomaly) << ",\"malicious\":" << (p.groundTruthMalicious ? "true" : "false") << "}";
    }
    os << "],\"results\":[";
    for (size_t r = 0; r < results.size(); ++r) {
        const SimResult& s = results[r];
        os << (r ? "," : "") << "{\"name\":" << esc(s.name) << ",\"multiLevel\":" << (s.multiLevel ? "true" : "false")
           << ",\"securityAware\":" << (s.securityAware ? "true" : "false") << ",\"metrics\":";
        metricsJson(os, metrics[r]);
        os << ",\"gantt\":[";
        for (size_t g = 0; g < s.gantt.size(); ++g) {
            const GanttSegment& seg = s.gantt[g];
            os << (g ? "," : "") << "[" << esc(segKind(seg.kind)) << "," << seg.pid << "," << seg.level << ","
               << seg.start << "," << seg.end << "]";
        }
        os << "],\"procs\":[";
        for (size_t i = 0; i < s.procs.size(); ++i) {
            const PCB& p = s.procs[i];
            os << (i ? "," : "") << "{\"pid\":" << p.pid << ",\"start\":" << p.startTime << ",\"finish\":" << p.finishTime
               << ",\"wait\":" << p.waitingTime << ",\"tat\":" << p.turnaroundTime << ",\"resp\":" << p.responseTime
               << ",\"level\":" << p.queueLevel << ",\"maxLevel\":" << p.maxLevelReached
               << ",\"peakThreat\":" << num(p.peakThreatScore) << ",\"demotions\":" << p.demotionCount << "}";
        }
        os << "],\"events\":[";
        for (size_t e = 0; e < s.events.size(); ++e) {
            const SecurityEvent& ev = s.events[e];
            os << (e ? "," : "") << "[" << ev.tick << "," << ev.pid << "," << ev.fromLevel << "," << ev.toLevel << ","
               << esc(ev.kind) << "," << num(ev.score) << "]";
        }
        os << "]}";
    }
    os << "]}\n";
}

void writeScenariosJson(std::ostream& os, const GenerationParams& gp, const Config& cfg,
                        const std::vector<std::string>& scenarios,
                        const std::vector<std::vector<Metrics>>& results) {
    os << "{\"mode\":\"scenarios\",\"legit\":" << gp.legit << ",\"bots\":" << gp.bots << ",\"seed\":" << gp.seed
       << ",\"config\":";
    configJson(os, cfg);
    os << ",\"scenarios\":[";
    for (size_t i = 0; i < scenarios.size(); ++i) {
        os << (i ? "," : "") << "{\"attack\":" << esc(scenarios[i]) << ",\"metrics\":[";
        for (size_t j = 0; j < results[i].size(); ++j) {
            if (j) os << ",";
            metricsJson(os, results[i][j]);
        }
        os << "]}";
    }
    os << "]}\n";
}

}  // namespace cmlfq
