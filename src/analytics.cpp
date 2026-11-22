// analytics.cpp — metric computation (definitions in analytics.h).
#include "analytics.h"

#include <algorithm>
#include <cmath>
#include <map>
#include <vector>

namespace cmlfq {

namespace {

ClassMetrics summarise(const std::vector<const PCB*>& ps) {
    ClassMetrics c;
    c.count = static_cast<int>(ps.size());
    if (ps.empty()) return c;
    double w = 0, t = 0, r = 0;
    std::vector<Tick> waits;
    for (const PCB* p : ps) {
        w += static_cast<double>(p->waitingTime);
        t += static_cast<double>(p->turnaroundTime);
        r += static_cast<double>(p->responseTime);
        waits.push_back(p->waitingTime);
        c.maxWait = std::max(c.maxWait, p->waitingTime);
        c.lastFinish = std::max(c.lastFinish, p->finishTime);
    }
    const double n = static_cast<double>(ps.size());
    c.avgWait = w / n;
    c.avgTurnaround = t / n;
    c.avgResponse = r / n;
    std::sort(waits.begin(), waits.end());
    size_t rank = static_cast<size_t>(std::ceil(0.95 * n));        // nearest-rank percentile
    c.p95Wait = static_cast<double>(waits[std::max<size_t>(rank, 1) - 1]);
    return c;
}

}  // namespace

Metrics computeMetrics(const SimResult& r) {
    Metrics m;
    m.scheduler = r.name;
    m.securityAware = r.securityAware;

    std::vector<const PCB*> all, legit, mal;
    for (const auto& p : r.procs) {
        all.push_back(&p);
        (p.groundTruthMalicious ? mal : legit).push_back(&p);
    }
    m.all = summarise(all);
    m.legit = summarise(legit);
    m.malicious = summarise(mal);

    m.makespan = r.makespan;
    if (r.makespan > 0) {
        const double span = static_cast<double>(r.makespan);
        m.throughput = 1000.0 * static_cast<double>(all.size()) / span;
        m.legitThroughput = 1000.0 * static_cast<double>(legit.size()) / span;
        m.cpuUtilization = 100.0 * static_cast<double>(r.busyTicks) / span;
    }
    m.contextSwitches = r.contextSwitches;
    m.csOnMalicious = r.csOnMalicious;
    m.csOverheadTicks = r.csOverheadTicks;
    m.csMaliciousTicks = r.csMaliciousTicks;
    m.forcedPreemptions = r.forcedPreemptions;
    m.demotions = r.demotions;
    m.promotions = r.promotions;
    m.starvationBoosts = r.starvationBoosts;

    // ---- detection quality / time-to-isolate (per malicious source) ----
    struct SourceInfo { Tick firstArrival = -1; Tick firstIsolation = -1; };
    std::map<std::string, SourceInfo> bots;
    for (const auto& p : r.procs) {
        if (!p.groundTruthMalicious) continue;
        SourceInfo& s = bots[p.sourceId];
        if (s.firstArrival < 0 || p.arrival < s.firstArrival) s.firstArrival = p.arrival;
        if (p.isolatedAt >= 0 && (s.firstIsolation < 0 || p.isolatedAt < s.firstIsolation))
            s.firstIsolation = p.isolatedAt;
    }
    m.botSources = static_cast<int>(bots.size());

    if (r.securityAware) {
        for (const auto& p : r.procs) {
            if (p.groundTruthMalicious) {
                if (p.maxLevelReached >= 1) ++m.maliciousContained;
                if (p.maxLevelReached >= 2) ++m.maliciousQuarantined;
            }
            else {
                if (p.maxLevelReached >= 1) ++m.legitThrottled;
                if (p.maxLevelReached >= 2) ++m.legitFalseQuarantine;
            }
        }
        double sum = 0;
        bool firstSeen = true;
        for (const auto& kv : bots) {
            const SourceInfo& s = kv.second;
            if (s.firstIsolation < 0) continue;
            Tick tti = s.firstIsolation - s.firstArrival;
            ++m.botSourcesIsolated;
            sum += static_cast<double>(tti);
            if (firstSeen || tti < m.minTimeToIsolate) m.minTimeToIsolate = tti;
            if (firstSeen || tti > m.maxTimeToIsolate) m.maxTimeToIsolate = tti;
            firstSeen = false;
        }
        if (m.botSourcesIsolated > 0) m.avgTimeToIsolate = sum / m.botSourcesIsolated;
    }
    return m;
}

}  // namespace cmlfq
