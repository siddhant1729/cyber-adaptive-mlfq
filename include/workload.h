// =====================================================================
//  workload.h  —  load / save a fixed workload file
//
//  File format (one process per line, whitespace separated):
//
//      # pid  source      arrival  burst  anomaly  label
//        1    TRADER-01   0        5      0.05     L
//        2    DDOS-IP-1   3        2      0.30     M
//
//  label: L = legitimate, M = malicious (ground truth, analytics only).
//  Lines starting with '#' and blank lines are ignored.
// =====================================================================
#pragma once

#include <string>
#include <vector>

#include "pcb.h"

namespace cmlfq {

// Returns false (with a message in err) on I/O or parse error.
bool loadWorkload(const std::string& path, std::vector<PCB>& out, std::string& err);

bool saveWorkload(const std::string& path, const std::vector<PCB>& procs, std::string& err);

}  // namespace cmlfq
