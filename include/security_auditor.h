// =====================================================================
//  security_auditor.h  —  per-source behaviour tracking
//
//  For every source (IP / token) the auditor keeps a sliding window
//  (std::deque) of recent arrival ticks plus a lifetime request count:
//
//      sources_ : unordered_map< sourceId, { deque<(tick, anomaly)>, total } >
//
//  Assessment of a source at tick `now`:
//      1. drop window entries with tick <= now - W          (W = window)
//      2. velocity     = |window| / W                       requests per tick
//         normVelocity = min(1, velocity / velocityCap)
//      3. frequency    = lifetime requests from the source
//         normFreq     = min(1, frequency / frequencyCap)
//      4. anomaly      = mean payload anomaly of requests in the window
//      5. threatScore  = w1*normVelocity + w2*normFreq + w3*anomaly
//
//      threatScore >= MALICIOUS threshold  -> MALICIOUS  (quarantine Q2)
//      threatScore >= SUSPICIOUS threshold -> SUSPICIOUS (throttle  Q1)
//      otherwise                           -> CLEAN      (fast lane Q0)
//
//  Velocity catches short bursts (DDoS, rapid retries); frequency is a
//  slowly-saturating reputation term; anomaly catches odd payloads such
//  as failed-login patterns in credential stuffing.
// =====================================================================
#pragma once

#include <deque>
#include <string>
#include <unordered_map>
#include <utility>

#include "config.h"
#include "pcb.h"

namespace cmlfq {

enum class ThreatLevel { CLEAN = 0, SUSPICIOUS = 1, MALICIOUS = 2 };

const char* toString(ThreatLevel t);

struct ThreatAssessment {
    double velocity = 0.0;        // requests per tick in the window
    double normVelocity = 0.0;
    double frequency = 0.0;       // lifetime request count
    double normFrequency = 0.0;
    double anomaly = 0.0;         // mean anomaly in the window
    double score = 0.0;
    ThreatLevel level = ThreatLevel::CLEAN;
};

class SecurityAuditor {
public:
    explicit SecurityAuditor(const Config& cfg) : cfg_(cfg) {}

    void reset() { sources_.clear(); }

    // Record one request arriving from `source` at tick `t`.
    void recordArrival(const std::string& source, Tick t, double payloadAnomaly);

    // Evaluate a source at tick `now` (prunes its window as a side effect).
    // Calls must use non-decreasing `now`.
    ThreatAssessment assess(const std::string& source, Tick now);

    ThreatLevel classify(double score) const;

    // Worst level this source has ever been assessed at (its "record").
    ThreatLevel worstLevel(const std::string& source) const;

    std::size_t trackedSources() const { return sources_.size(); }

private:
    struct SourceHistory {
        std::deque<std::pair<Tick, double>> window;  // (arrival tick, payload anomaly)
        double windowAnomalySum = 0.0;
        long long total = 0;                         // lifetime requests
        ThreatLevel worst = ThreatLevel::CLEAN;      // worst verdict so far
    };

    const Config& cfg_;
    std::unordered_map<std::string, SourceHistory> sources_;
};

}  // namespace cmlfq
