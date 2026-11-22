// =====================================================================
//  reporter.h  —  terminal tables, ASCII Gantt charts and CSV export
// =====================================================================
#pragma once

#include <string>
#include <vector>

#include "analytics.h"
#include "config.h"
#include "ingestion.h"
#include "scheduler.h"

namespace cmlfq {

class Reporter {
public:
    explicit Reporter(const Config& cfg) : cfg_(cfg) {}

    void banner() const;
    void section(const std::string& title) const;

    // Workload overview (counts, sources, arrival span, total work).
    void workloadSummary(const std::vector<PCB>& w, const std::string& label,
                         const IngestionStats* ingestion = nullptr) const;

    // Per-process table (truncated to cfg.tableMaxRows rows).
    void processTable(const SimResult& r) const;

    // Detailed metrics of one scheduler (overall / legit / malicious).
    void metrics(const Metrics& m) const;

    // Side-by-side comparison of several schedulers on the same workload.
    void comparison(const std::vector<Metrics>& ms) const;

    // Security-specific numbers for the adaptive scheduler.
    void securityReport(const Metrics& m) const;

    // ASCII Gantt chart (first cfg.ganttMaxSegments blocks).
    void gantt(const SimResult& r) const;

    // Scenario sweep: rows = scenarios, columns = schedulers.
    void scenarioTables(const std::vector<std::string>& scenarios,
                        const std::vector<std::vector<Metrics>>& results) const;

    // CSV export. Paths are created inside cfg.resultsDir.
    bool writeProcessCsv(const SimResult& r, const std::string& fileName, std::string& err) const;
    bool writeSummaryCsv(const std::vector<std::pair<std::string, Metrics>>& rows,
                         const std::string& fileName, std::string& err) const;

    std::string resultsPath(const std::string& fileName) const;

private:
    const Config& cfg_;
};

// "Adaptive-MLFQ" -> "adaptive_mlfq" (for file names)
std::string slug(const std::string& s);

}  // namespace cmlfq
