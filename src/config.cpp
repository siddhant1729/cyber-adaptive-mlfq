// config.cpp — minimal INI loader for Config.
#include "config.h"

#include <fstream>
#include <functional>
#include <map>
#include <sstream>

namespace cmlfq {

namespace {

std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

bool parseBool(const std::string& v, bool& out) {
    if (v == "1" || v == "true" || v == "yes" || v == "on")  { out = true;  return true; }
    if (v == "0" || v == "false" || v == "no" || v == "off") { out = false; return true; }
    return false;
}

}  // namespace

bool loadConfig(const std::string& path, Config& cfg, std::string& err) {
    std::ifstream in(path);
    if (!in) { err = "cannot open config file '" + path + "'"; return false; }

    // Table of setters: key -> function that parses the value into cfg.
    // Each setter returns false if the value is malformed.
    using Setter = std::function<bool(const std::string&)>;
    auto tick = [](Tick& field) {
        return Setter([&field](const std::string& v) {
            try { size_t pos; long long x = std::stoll(v, &pos); if (pos != v.size()) return false; field = x; return true; }
            catch (...) { return false; }
        });
    };
    auto integer = [](int& field) {
        return Setter([&field](const std::string& v) {
            try { size_t pos; int x = std::stoi(v, &pos); if (pos != v.size()) return false; field = x; return true; }
            catch (...) { return false; }
        });
    };
    auto real = [](double& field) {
        return Setter([&field](const std::string& v) {
            try { size_t pos; double x = std::stod(v, &pos); if (pos != v.size()) return false; field = x; return true; }
            catch (...) { return false; }
        });
    };
    auto boolean = [](bool& field) {
        return Setter([&field](const std::string& v) { return parseBool(v, field); });
    };

    std::map<std::string, Setter> setters = {
        {"quantum", tick(cfg.quantum)},
        {"mlfq_quantum1", tick(cfg.mlfqQuantum1)},
        {"context_switch_cost", tick(cfg.contextSwitchCost)},
        {"promotion_aging_ticks", tick(cfg.promotionAgingTicks)},
        {"rehab_ceiling", integer(cfg.rehabCeiling)},
        {"starvation_aging", boolean(cfg.starvationAging)},
        {"starvation_limit", tick(cfg.starvationLimit)},
        {"mlfq_boost_period", tick(cfg.mlfqBoostPeriod)},

        {"window_ticks", tick(cfg.windowTicks)},
        {"velocity_cap", real(cfg.velocityCap)},
        {"frequency_cap", real(cfg.frequencyCap)},
        {"w_velocity", real(cfg.wVelocity)},
        {"w_frequency", real(cfg.wFrequency)},
        {"w_anomaly", real(cfg.wAnomaly)},
        {"suspicious_threshold", real(cfg.suspiciousThreshold)},
        {"malicious_threshold", real(cfg.maliciousThreshold)},

        {"horizon", tick(cfg.horizon)},
        {"legit_requests_per_trader", integer(cfg.legitRequestsPerTrader)},
        {"legit_burst_min", tick(cfg.legitBurstMin)},
        {"legit_burst_max", tick(cfg.legitBurstMax)},
        {"legit_anomaly_max", real(cfg.legitAnomalyMax)},
        {"attack_start", tick(cfg.attackStart)},
        {"ddos_sources", integer(cfg.ddosSources)},
        {"ddos_gap_min", tick(cfg.ddosGapMin)},
        {"ddos_gap_max", tick(cfg.ddosGapMax)},
        {"ddos_burst_min", tick(cfg.ddosBurstMin)},
        {"ddos_burst_max", tick(cfg.ddosBurstMax)},
        {"ddos_anomaly_min", real(cfg.ddosAnomalyMin)},
        {"ddos_anomaly_max", real(cfg.ddosAnomalyMax)},
        {"stuffing_tokens", integer(cfg.stuffingTokens)},
        {"stuffing_spread", tick(cfg.stuffingSpread)},
        {"stuffing_gap_min", tick(cfg.stuffingGapMin)},
        {"stuffing_gap_max", tick(cfg.stuffingGapMax)},
        {"stuffing_burst_min", tick(cfg.stuffingBurstMin)},
        {"stuffing_burst_max", tick(cfg.stuffingBurstMax)},
        {"stuffing_anomaly_min", real(cfg.stuffingAnomalyMin)},
        {"stuffing_anomaly_max", real(cfg.stuffingAnomalyMax)},

        {"buffer_capacity", Setter([&cfg](const std::string& v) {
             try { long long x = std::stoll(v); if (x <= 0) return false; cfg.bufferCapacity = static_cast<std::size_t>(x); return true; }
             catch (...) { return false; } })},

        {"gantt_max_segments", integer(cfg.ganttMaxSegments)},
        {"table_max_rows", integer(cfg.tableMaxRows)},
        {"results_dir", Setter([&cfg](const std::string& v) { cfg.resultsDir = v; return !v.empty(); })},
    };

    std::ostringstream problems;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        // strip comments
        auto c = line.find_first_of(";#");
        if (c != std::string::npos) line = line.substr(0, c);
        line = trim(line);
        if (line.empty() || line.front() == '[') continue;  // blank or [section]

        auto eq = line.find('=');
        if (eq == std::string::npos) {
            problems << "  line " << lineNo << ": expected key = value\n";
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        auto it = setters.find(key);
        if (it == setters.end()) {
            problems << "  line " << lineNo << ": unknown key '" << key << "'\n";
        } else if (!it->second(val)) {
            problems << "  line " << lineNo << ": bad value '" << val << "' for '" << key << "'\n";
        }
    }
    err = problems.str();
    return true;
}

std::string describeConfig(const Config& c) {
    std::ostringstream o;
    o << "Scheduler\n"
      << "  Q0 quantum (and RR quantum) : " << c.quantum << " ticks\n"
      << "  Classic MLFQ Q1 quantum     : " << c.mlfqQuantum1 << " ticks\n"
      << "  Context-switch cost         : " << c.contextSwitchCost << " ticks\n"
      << "  Promotion aging K           : " << c.promotionAgingTicks << " ticks\n"
      << "  Rehab ceiling (ex-malicious): Q" << c.rehabCeiling << "\n"
      << "  Q2 anti-starvation          : " << (c.starvationAging ? "on" : "off")
      << " (limit " << c.starvationLimit << " ticks)\n"
      << "Security auditor\n"
      << "  Sliding window              : " << c.windowTicks << " ticks\n"
      << "  Velocity cap                : " << c.velocityCap << " req/tick\n"
      << "  Frequency cap               : " << c.frequencyCap << " requests\n"
      << "  Weights (vel, freq, anomaly): " << c.wVelocity << ", " << c.wFrequency << ", " << c.wAnomaly << "\n"
      << "  Thresholds (susp, mal)      : " << c.suspiciousThreshold << ", " << c.maliciousThreshold << "\n";
    return o.str();
}

}  // namespace cmlfq
