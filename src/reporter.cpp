// reporter.cpp — all terminal / CSV output.
#include "reporter.h"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>

namespace cmlfq {

namespace {

// Format a number; NaN means "not applicable" and prints as "-".
std::string fmt(double v, int prec = 2) {
    if (std::isnan(v)) return "-";
    std::ostringstream o;
    o << std::fixed << std::setprecision(prec) << v;
    return o.str();
}

std::string line(int width, char c = '-') { return std::string(static_cast<size_t>(width), c); }

}  // namespace

std::string slug(const std::string& s) {
    std::string out;
    for (char c : s) out += (c == '-' || c == ' ') ? '_' : static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

void Reporter::banner() const {
    std::cout <<
        "==================================================================\n"
        "  CYBER-ADAPTIVE MLFQ  —  Adaptive Anti-Fraud Scheduling for HFT\n"
        "  Discrete-clock OS scheduling simulator (1 tick = 1 us simulated)\n"
        "==================================================================\n";
}

void Reporter::section(const std::string& title) const {
    std::cout << "\n" << title << "\n" << line(static_cast<int>(title.size()), '=') << "\n";
}

// ---------------------------------------------------------------------
void Reporter::workloadSummary(const std::vector<PCB>& w, const std::string& label,
                               const IngestionStats* ing) const {
    section("Workload: " + label);
    int legit = 0, mal = 0;
    Tick legitWork = 0, malWork = 0, first = -1, last = 0;
    std::set<std::string> legitSrc, malSrc;
    for (const auto& p : w) {
        if (p.groundTruthMalicious) { ++mal; malWork += p.burst; malSrc.insert(p.sourceId); }
        else                        { ++legit; legitWork += p.burst; legitSrc.insert(p.sourceId); }
        if (first < 0 || p.arrival < first) first = p.arrival;
        last = std::max(last, p.arrival);
    }
    std::cout << std::left
              << "  Processes        : " << w.size() << "  (" << legit << " legit from " << legitSrc.size()
              << " sources, " << mal << " malicious from " << malSrc.size() << " sources)\n"
              << "  Arrival span     : tick " << first << " .. " << last << "\n"
              << "  Total CPU work   : " << (legitWork + malWork) << " ticks  (legit " << legitWork
              << ", malicious " << malWork << ")\n";
    if (ing) {
        std::cout << "  Ingestion        : " << ing->producerThreads << " producer threads + 1 consumer, "
                  << ing->requests << " requests\n"
                  << "                     bounded buffer cap " << cfg_.bufferCapacity
                  << ", peak occupancy " << ing->peakBuffer << ", producer blocks " << ing->producerWaits
                  << ", " << fmt(ing->wallMillis, 1) << " ms wall\n";
    }
}

// ---------------------------------------------------------------------
void Reporter::processTable(const SimResult& r) const {
    section("Per-process results — " + r.name);
    const bool sec = r.securityAware;
    std::cout << std::right
              << std::setw(5) << "PID" << "  " << std::left << std::setw(12) << "Source" << std::right
              << std::setw(4) << "Cls" << std::setw(7) << "Arr" << std::setw(6) << "Burst"
              << std::setw(7) << "Start" << std::setw(7) << "Finish" << std::setw(7) << "Wait"
              << std::setw(6) << "TAT" << std::setw(6) << "Resp";
    if (r.multiLevel) std::cout << std::setw(6) << "MaxQ" << std::setw(6) << "Dem";
    if (sec) std::cout << std::setw(8) << "Threat" << std::setw(7) << "Isol";
    std::cout << "\n" << line(sec ? 104 : (r.multiLevel ? 89 : 77)) << "\n";

    const int maxRows = std::max(1, cfg_.tableMaxRows);
    int shown = 0;
    for (const auto& p : r.procs) {
        if (shown++ >= maxRows) break;
        std::cout << std::right << std::setw(5) << p.pid << "  " << std::left << std::setw(12)
                  << p.sourceId.substr(0, 11) << std::right << std::setw(4)
                  << (p.groundTruthMalicious ? "M" : "L") << std::setw(7) << p.arrival << std::setw(6)
                  << p.burst << std::setw(7) << p.startTime << std::setw(7) << p.finishTime
                  << std::setw(7) << p.waitingTime << std::setw(6) << p.turnaroundTime
                  << std::setw(6) << p.responseTime;
        if (r.multiLevel) std::cout << std::setw(5) << "Q" << p.maxLevelReached << std::setw(6) << p.demotionCount;
        if (sec) std::cout << std::setw(8) << fmt(p.peakThreatScore) << std::setw(7)
                           << (p.isolatedAt >= 0 ? std::to_string(p.isolatedAt) : "-");
        std::cout << "\n";
    }
    if (static_cast<int>(r.procs.size()) > maxRows)
        std::cout << "  ... " << (r.procs.size() - static_cast<size_t>(maxRows))
                  << " more rows (use --csv for the full table)\n";
    if (sec) std::cout << "  Threat = peak threat score seen while alive; Isol = tick it entered quarantine\n";
}

// ---------------------------------------------------------------------
void Reporter::metrics(const Metrics& m) const {
    section("Metrics — " + m.scheduler);
    std::cout << std::left << std::setw(26) << "" << std::right << std::setw(12) << "All"
              << std::setw(12) << "Legit" << std::setw(12) << "Malicious" << "\n"
              << "  " << line(60) << "\n";
    auto row = [](const std::string& name, double a, double l, double mm, int lc, int mc) {
        std::cout << "  " << std::left << std::setw(24) << name << std::right << std::setw(12) << fmt(a)
                  << std::setw(12) << (lc ? fmt(l) : "-") << std::setw(12) << (mc ? fmt(mm) : "-") << "\n";
    };
    const int lc = m.legit.count, mc = m.malicious.count;
    row("Processes", m.all.count, lc, mc, 1, 1);
    row("Avg waiting time", m.all.avgWait, m.legit.avgWait, m.malicious.avgWait, lc, mc);
    row("Avg turnaround time", m.all.avgTurnaround, m.legit.avgTurnaround, m.malicious.avgTurnaround, lc, mc);
    row("Avg response time", m.all.avgResponse, m.legit.avgResponse, m.malicious.avgResponse, lc, mc);
    row("P95 waiting time", m.all.p95Wait, m.legit.p95Wait, m.malicious.p95Wait, lc, mc);
    row("Max waiting time", static_cast<double>(m.all.maxWait), static_cast<double>(m.legit.maxWait),
        static_cast<double>(m.malicious.maxWait), lc, mc);
    std::cout << "  " << line(60) << "\n"
              << "  Throughput            : " << fmt(m.throughput) << " proc / 1000 ticks\n"
              << "  CPU utilisation       : " << fmt(m.cpuUtilization) << " %\n"
              << "  Context switches      : " << m.contextSwitches << "  (" << m.csOnMalicious
              << " loading malicious processes)\n"
              << "  Switch overhead       : " << m.csOverheadTicks << " ticks  (" << m.csMaliciousTicks
              << " on malicious)\n"
              << "  Makespan              : " << m.makespan << " ticks\n";
    if (m.securityAware) securityReport(m);
}

void Reporter::securityReport(const Metrics& m) const {
    std::cout << "  Security --------------------------------------------------\n";
    std::cout << "  Malicious sources isolated : " << m.botSourcesIsolated << " / " << m.botSources << "\n";
    if (m.botSourcesIsolated > 0)
        std::cout << "  Time-to-isolate (ticks)    : avg " << fmt(m.avgTimeToIsolate) << ", min "
                  << m.minTimeToIsolate << ", max " << m.maxTimeToIsolate << "\n";
    std::cout << "  Malicious procs contained  : " << m.maliciousContained << " / " << m.malicious.count
              << "  (" << m.maliciousQuarantined << " reached quarantine Q2)\n"
              << "  Legit procs throttled (Q1) : " << m.legitThrottled << "   quarantined (Q2): "
              << m.legitFalseQuarantine << "\n"
              << "  Forced preemptions         : " << m.forcedPreemptions << "\n"
              << "  Demotions / promotions     : " << m.demotions << " / " << m.promotions
              << "   anti-starvation boosts: " << m.starvationBoosts << "\n";
}

// ---------------------------------------------------------------------
void Reporter::comparison(const std::vector<Metrics>& ms) const {
    section("Scheduler comparison (same workload)");
    const int nameW = 30, colW = 15;
    std::cout << "  " << std::left << std::setw(nameW) << "Metric";
    for (const auto& m : ms) std::cout << std::right << std::setw(colW) << m.scheduler;
    std::cout << "\n  " << line(nameW + colW * static_cast<int>(ms.size())) << "\n";

    auto row = [&](const std::string& name, auto getter, int prec = 2) {
        std::cout << "  " << std::left << std::setw(nameW) << name;
        for (const auto& m : ms) std::cout << std::right << std::setw(colW) << fmt(getter(m), prec);
        std::cout << "\n";
    };
    auto rule = [&] { std::cout << "  " << line(nameW + colW * static_cast<int>(ms.size()), '.') << "\n"; };

    // NaN -> printed as "-" when a class has no processes
    auto L = [](const Metrics& m, double v) { return m.legit.count ? v : std::nan(""); };
    auto M = [](const Metrics& m, double v) { return m.malicious.count ? v : std::nan(""); };
    row("Avg wait  (all)",        [](const Metrics& m) { return m.all.avgWait; });
    row("Avg wait  (LEGIT)",      [&](const Metrics& m) { return L(m, m.legit.avgWait); });
    row("Avg wait  (malicious)",  [&](const Metrics& m) { return M(m, m.malicious.avgWait); });
    row("P95 wait  (LEGIT)",      [&](const Metrics& m) { return L(m, m.legit.p95Wait); });
    rule();
    row("Avg TAT   (all)",        [](const Metrics& m) { return m.all.avgTurnaround; });
    row("Avg TAT   (LEGIT)",      [&](const Metrics& m) { return L(m, m.legit.avgTurnaround); });
    row("Avg TAT   (malicious)",  [&](const Metrics& m) { return M(m, m.malicious.avgTurnaround); });
    rule();
    row("Avg resp  (all)",        [](const Metrics& m) { return m.all.avgResponse; });
    row("Avg resp  (LEGIT)",      [&](const Metrics& m) { return L(m, m.legit.avgResponse); });
    row("Avg resp  (malicious)",  [&](const Metrics& m) { return M(m, m.malicious.avgResponse); });
    rule();
    row("Throughput (/1000 ticks)", [](const Metrics& m) { return m.throughput; });
    row("CPU utilisation %",      [](const Metrics& m) { return m.cpuUtilization; });
    row("Context switches",       [](const Metrics& m) { return static_cast<double>(m.contextSwitches); }, 0);
    row("  ...loading malicious", [](const Metrics& m) { return static_cast<double>(m.csOnMalicious); }, 0);
    row("Switch overhead (ticks)", [](const Metrics& m) { return static_cast<double>(m.csOverheadTicks); }, 0);
    row("Makespan (ticks)",       [](const Metrics& m) { return static_cast<double>(m.makespan); }, 0);
    row("Last legit finish",      [](const Metrics& m) { return static_cast<double>(m.legit.lastFinish); }, 0);

    // Highlight how much the adaptive scheduler protects legit traffic.
    const Metrics* adaptive = nullptr;
    for (const auto& m : ms) if (m.securityAware) adaptive = &m;
    if (adaptive && adaptive->malicious.count > 0) {
        std::cout << "\n  Legit avg wait vs Adaptive-MLFQ:";
        for (const auto& m : ms) {
            if (&m == adaptive) continue;
            if (adaptive->legit.avgWait > 0)
                std::cout << "  " << m.scheduler << " " << fmt(m.legit.avgWait / adaptive->legit.avgWait, 1) << "x";
        }
        std::cout << "\n";
    }
}

// ---------------------------------------------------------------------
void Reporter::gantt(const SimResult& r) const {
    const auto& g = r.gantt;
    const size_t limit = std::min(g.size(), static_cast<size_t>(std::max(1, cfg_.ganttMaxSegments)));
    section("Gantt chart — " + r.name);
    if (g.empty()) { std::cout << "  (empty)\n"; return; }

    // Build one "cell" per segment.
    struct Cell { std::string label, level; Tick start, end; size_t width; };
    std::vector<Cell> cells;
    for (size_t i = 0; i < limit; ++i) {
        const auto& s = g[i];
        Cell c;
        c.start = s.start;
        c.end = s.end;
        switch (s.kind) {
            case SegmentKind::RUN:    c.label = "P" + std::to_string(s.pid); c.level = "Q" + std::to_string(s.level); break;
            case SegmentKind::IDLE:   c.label = "idle"; break;
            case SegmentKind::SWITCH: c.label = "cs"; break;
        }
        // Roughly proportional to duration (capped), but always wide enough for the text.
        size_t dur = static_cast<size_t>(std::min<Tick>(s.end - s.start, 8));
        c.width = std::max({c.label.size() + 1, std::to_string(c.start).size() + 1, dur});
        cells.push_back(c);
    }

    // Print in rows that fit ~100 columns.
    const size_t maxWidth = 100;
    size_t i = 0;
    while (i < cells.size()) {
        size_t j = i, w = 1;
        while (j < cells.size() && (j == i || w + cells[j].width + 1 <= maxWidth)) w += cells[j++].width + 1;

        std::string border = "  +", labels = "  |", levels = "  |", times = "  ";
        for (size_t k = i; k < j; ++k) {
            const Cell& c = cells[k];
            border += line(static_cast<int>(c.width)) + "+";
            labels += c.label + std::string(c.width - c.label.size(), ' ') + "|";
            levels += c.level + std::string(c.width - c.level.size(), ' ') + "|";
            std::string t = std::to_string(c.start);
            times += t + std::string(c.width + 1 - t.size(), ' ');
        }
        times += std::to_string(cells[j - 1].end);
        std::cout << border << "\n" << labels << "\n";
        if (r.multiLevel) std::cout << levels << "\n";
        std::cout << border << "\n" << times << "\n";
        i = j;
    }
    if (g.size() > limit)
        std::cout << "  ... truncated: showing " << limit << " of " << g.size() << " segments (ticks 0-"
                  << cells.back().end << " of " << r.makespan << ")\n";
    std::cout << "  Legend: Pn = process n, cs = context switch, idle = CPU idle"
              << (r.multiLevel ? ", Qk = queue level" : "") << "\n";
}

// ---------------------------------------------------------------------
void Reporter::scenarioTables(const std::vector<std::string>& scenarios,
                              const std::vector<std::vector<Metrics>>& results) const {
    if (results.empty() || results[0].empty()) return;
    const int nameW = 14, colW = 15;
    const auto& cols = results[0];

    auto table = [&](const std::string& title, auto getter) {
        section(title);
        std::cout << "  " << std::left << std::setw(nameW) << "Scenario";
        for (const auto& m : cols) std::cout << std::right << std::setw(colW) << m.scheduler;
        std::cout << "\n  " << line(nameW + colW * static_cast<int>(cols.size())) << "\n";
        for (size_t s = 0; s < scenarios.size(); ++s) {
            std::cout << "  " << std::left << std::setw(nameW) << scenarios[s];
            for (const auto& m : results[s]) std::cout << std::right << std::setw(colW) << fmt(getter(m));
            std::cout << "\n";
        }
    };

    table("LEGIT average waiting time (ticks) — lower is better",
          [](const Metrics& m) { return m.legit.avgWait; });
    table("LEGIT P95 waiting time (ticks) — tail latency",
          [](const Metrics& m) { return m.legit.p95Wait; });
    table("LEGIT average response time (ticks)",
          [](const Metrics& m) { return m.legit.avgResponse; });
    table("MALICIOUS average waiting time (ticks) — higher = attack contained",
          [](const Metrics& m) { return m.malicious.count ? m.malicious.avgWait : std::nan(""); });

    section("Adaptive-MLFQ detection per scenario");
    std::cout << "  " << std::left << std::setw(nameW) << "Scenario" << std::right << std::setw(12) << "Isolated"
              << std::setw(12) << "Mal>=Q1" << std::setw(12) << "AvgTTI" << std::setw(12) << "MaxTTI" << std::setw(12) << "LegitQ1"
              << std::setw(12) << "LegitQ2" << std::setw(12) << "Forced" << std::setw(12) << "CS->mal" << "\n"
              << "  " << line(nameW + 96) << "\n";
    for (size_t s = 0; s < scenarios.size(); ++s) {
        for (const auto& m : results[s]) {
            if (!m.securityAware) continue;
            std::cout << "  " << std::left << std::setw(nameW) << scenarios[s] << std::right << std::setw(12)
                      << (std::to_string(m.botSourcesIsolated) + "/" + std::to_string(m.botSources))
                      << std::setw(12) << (std::to_string(m.maliciousContained) + "/" + std::to_string(m.malicious.count))
                      << std::setw(12) << fmt(m.avgTimeToIsolate) << std::setw(12) << m.maxTimeToIsolate
                      << std::setw(12) << m.legitThrottled << std::setw(12) << m.legitFalseQuarantine
                      << std::setw(12) << m.forcedPreemptions << std::setw(12) << m.csOnMalicious << "\n";
        }
    }
    std::cout << "  Isolated = bot sources quarantined; Mal>=Q1 = bot requests throttled or quarantined;\n"
                 "  TTI = time-to-isolate (ticks from a bot source's first request to quarantine);\n"
                 "  LegitQ1/LegitQ2 = legit requests wrongly throttled/quarantined (false positives)\n";
}

// ---------------------------------------------------------------------
std::string Reporter::resultsPath(const std::string& fileName) const {
    return (std::filesystem::path(cfg_.resultsDir) / fileName).string();
}

bool Reporter::writeProcessCsv(const SimResult& r, const std::string& fileName, std::string& err) const {
    std::error_code ec;
    std::filesystem::create_directories(cfg_.resultsDir, ec);
    std::ofstream o(resultsPath(fileName));
    if (!o) { err = "cannot write " + resultsPath(fileName); return false; }
    o << "scheduler,pid,source,class,arrival,burst,start,finish,waiting,turnaround,response,"
         "max_queue,demotions,peak_threat,final_threat,velocity,frequency,payload_anomaly,isolated_at\n";
    for (const auto& p : r.procs) {
        o << r.name << ',' << p.pid << ',' << p.sourceId << ',' << (p.groundTruthMalicious ? "malicious" : "legit")
          << ',' << p.arrival << ',' << p.burst << ',' << p.startTime << ',' << p.finishTime << ','
          << p.waitingTime << ',' << p.turnaroundTime << ',' << p.responseTime << ',' << p.maxLevelReached
          << ',' << p.demotionCount << ',' << fmt(p.peakThreatScore, 4) << ',' << fmt(p.threatScore, 4) << ','
          << fmt(p.requestVelocity, 4) << ',' << fmt(p.requestFrequency, 0) << ','
          << fmt(p.payloadAnomaly, 3) << ',' << p.isolatedAt << '\n';
    }
    return true;
}

bool Reporter::writeSummaryCsv(const std::vector<std::pair<std::string, Metrics>>& rows,
                               const std::string& fileName, std::string& err) const {
    std::error_code ec;
    std::filesystem::create_directories(cfg_.resultsDir, ec);
    std::ofstream o(resultsPath(fileName));
    if (!o) { err = "cannot write " + resultsPath(fileName); return false; }
    o << "scenario,scheduler,processes,legit,malicious,"
         "avg_wait_all,avg_wait_legit,avg_wait_malicious,p95_wait_legit,"
         "avg_tat_all,avg_tat_legit,avg_tat_malicious,"
         "avg_resp_all,avg_resp_legit,avg_resp_malicious,"
         "throughput_per_1000,cpu_util_pct,context_switches,cs_malicious,cs_overhead_ticks,makespan,"
         "bot_sources,bot_sources_isolated,malicious_contained,avg_time_to_isolate,max_time_to_isolate,"
         "legit_throttled,legit_quarantined,forced_preemptions,demotions,promotions\n";
    for (const auto& [scenario, m] : rows) {
        o << scenario << ',' << m.scheduler << ',' << m.all.count << ',' << m.legit.count << ','
          << m.malicious.count << ',' << fmt(m.all.avgWait, 3) << ',' << fmt(m.legit.avgWait, 3) << ','
          << fmt(m.malicious.avgWait, 3) << ',' << fmt(m.legit.p95Wait, 1) << ','
          << fmt(m.all.avgTurnaround, 3) << ',' << fmt(m.legit.avgTurnaround, 3) << ','
          << fmt(m.malicious.avgTurnaround, 3) << ',' << fmt(m.all.avgResponse, 3) << ','
          << fmt(m.legit.avgResponse, 3) << ',' << fmt(m.malicious.avgResponse, 3) << ','
          << fmt(m.throughput, 3) << ',' << fmt(m.cpuUtilization, 2) << ',' << m.contextSwitches << ','
          << m.csOnMalicious << ',' << m.csOverheadTicks << ',' << m.makespan << ',' << m.botSources << ','
          << m.botSourcesIsolated << ',' << m.maliciousContained << ',' << fmt(m.avgTimeToIsolate, 2) << ',' << m.maxTimeToIsolate << ','
          << m.legitThrottled << ',' << m.legitFalseQuarantine << ',' << m.forcedPreemptions << ','
          << m.demotions << ',' << m.promotions << '\n';
    }
    return true;
}

}  // namespace cmlfq
