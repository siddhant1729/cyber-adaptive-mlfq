// security_auditor.cpp — sliding-window threat scoring (see header).
#include "security_auditor.h"

#include <algorithm>

namespace cmlfq {

const char* toString(ThreatLevel t) {
    switch (t) {
        case ThreatLevel::CLEAN:      return "CLEAN";
        case ThreatLevel::SUSPICIOUS: return "SUSPICIOUS";
        case ThreatLevel::MALICIOUS:  return "MALICIOUS";
    }
    return "?";
}

void SecurityAuditor::recordArrival(const std::string& source, Tick t, double payloadAnomaly) {
    SourceHistory& h = sources_[source];
    h.window.emplace_back(t, payloadAnomaly);
    h.windowAnomalySum += payloadAnomaly;
    ++h.total;
}

ThreatLevel SecurityAuditor::classify(double score) const {
    if (score >= cfg_.maliciousThreshold) return ThreatLevel::MALICIOUS;
    if (score >= cfg_.suspiciousThreshold) return ThreatLevel::SUSPICIOUS;
    return ThreatLevel::CLEAN;
}

ThreatAssessment SecurityAuditor::assess(const std::string& source, Tick now) {
    ThreatAssessment a;
    auto it = sources_.find(source);
    if (it == sources_.end()) return a;   // never seen: clean
    SourceHistory& h = it->second;

    // 1. slide the window: keep only arrivals in (now - W, now]
    const Tick W = std::max<Tick>(1, cfg_.windowTicks);
    while (!h.window.empty() && h.window.front().first <= now - W) {
        h.windowAnomalySum -= h.window.front().second;
        h.window.pop_front();
    }
    if (h.window.empty()) h.windowAnomalySum = 0.0;   // avoid floating-point drift

    // 2-4. raw and normalised features
    const double inWindow = static_cast<double>(h.window.size());
    a.velocity = inWindow / static_cast<double>(W);
    a.normVelocity = cfg_.velocityCap > 0 ? std::min(1.0, a.velocity / cfg_.velocityCap) : 0.0;
    a.frequency = static_cast<double>(h.total);
    a.normFrequency = cfg_.frequencyCap > 0 ? std::min(1.0, a.frequency / cfg_.frequencyCap) : 0.0;
    a.anomaly = h.window.empty() ? 0.0 : std::clamp(h.windowAnomalySum / inWindow, 0.0, 1.0);

    // 5. weighted threat score
    a.score = cfg_.wVelocity * a.normVelocity + cfg_.wFrequency * a.normFrequency + cfg_.wAnomaly * a.anomaly;
    a.level = classify(a.score);
    if (a.level > h.worst) h.worst = a.level;
    return a;
}

ThreatLevel SecurityAuditor::worstLevel(const std::string& source) const {
    auto it = sources_.find(source);
    return it == sources_.end() ? ThreatLevel::CLEAN : it->second.worst;
}

}  // namespace cmlfq
