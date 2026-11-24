// =====================================================================
//  json_export.h  —  machine-readable results for the web UI (ui/)
//
//  ./cmlfq ... --compare   --json out.json   -> workload + all 4 schedulers
//  ./cmlfq ... --scenarios --json out.json   -> scenario sweep metrics
//
//  The JSON carries everything the browser needs to draw Gantt charts,
//  per-process tables, comparison charts and the security event log.
// =====================================================================
#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "analytics.h"
#include "config.h"
#include "ingestion.h"
#include "scheduler.h"

namespace cmlfq {

void writeCompareJson(std::ostream& os, const std::string& label, const Config& cfg,
                      const std::vector<PCB>& workload, const IngestionStats* ingestion,
                      const std::vector<SimResult>& results, const std::vector<Metrics>& metrics);

void writeScenariosJson(std::ostream& os, const GenerationParams& gp, const Config& cfg,
                        const std::vector<std::string>& scenarios,
                        const std::vector<std::vector<Metrics>>& results);

}  // namespace cmlfq
