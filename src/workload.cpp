// workload.cpp — reading/writing workload files (see workload.h for format).
#include "workload.h"

#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

namespace cmlfq {

bool loadWorkload(const std::string& path, std::vector<PCB>& out, std::string& err) {
    std::ifstream in(path);
    if (!in) { err = "cannot open workload file '" + path + "'"; return false; }

    out.clear();
    std::set<int> seenPids;
    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        auto hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        std::istringstream ss(line);
        int pid;
        std::string source, label;
        Tick arrival, burst;
        double anomaly;
        if (!(ss >> pid)) continue;  // blank / comment-only line
        if (!(ss >> source >> arrival >> burst >> anomaly >> label)) {
            err = path + ":" + std::to_string(lineNo) + ": expected 'pid source arrival burst anomaly label'";
            return false;
        }
        if (arrival < 0 || burst <= 0 || anomaly < 0.0 || anomaly > 1.0) {
            err = path + ":" + std::to_string(lineNo) + ": need arrival>=0, burst>0, 0<=anomaly<=1";
            return false;
        }
        if (label != "L" && label != "M") {
            err = path + ":" + std::to_string(lineNo) + ": label must be L or M";
            return false;
        }
        if (!seenPids.insert(pid).second) {
            err = path + ":" + std::to_string(lineNo) + ": duplicate pid " + std::to_string(pid);
            return false;
        }
        out.push_back(makePCB(pid, source, arrival, burst, anomaly, label == "M"));
    }
    if (out.empty()) { err = "workload file '" + path + "' contains no processes"; return false; }
    return true;
}

bool saveWorkload(const std::string& path, const std::vector<PCB>& procs, std::string& err) {
    std::ofstream o(path);
    if (!o) { err = "cannot write workload file '" + path + "'"; return false; }
    o << "# Cyber-Adaptive MLFQ workload\n"
      << "# pid  source  arrival  burst  anomaly  label(L=legit,M=malicious)\n";
    for (const auto& p : procs) {
        o << p.pid << ' ' << p.sourceId << ' ' << p.arrival << ' ' << p.burst << ' '
          << std::fixed << std::setprecision(3) << p.payloadAnomaly << ' '
          << (p.groundTruthMalicious ? 'M' : 'L') << '\n';
    }
    return true;
}

}  // namespace cmlfq
