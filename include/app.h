// =====================================================================
//  app.h  —  command-line front end + interactive menu
//
//  Batch usage (see --help):
//    ./cmlfq --workload workloads/hand_basic.txt --compare --gantt
//    ./cmlfq --generate --legit 50 --bots 200 --seed 42 --attack ddos --compare --csv
//    ./cmlfq --generate --scenarios
//  Running ./cmlfq with no arguments opens the interactive menu.
// =====================================================================
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "analytics.h"
#include "config.h"
#include "ingestion.h"
#include "reporter.h"
#include "scheduler.h"

namespace cmlfq {

struct Options {
    std::string configPath = "config.ini";
    bool        configExplicit = false;
    std::string workloadFile;
    std::string saveWorkloadFile;
    bool        generate = false;
    GenerationParams gen;            // legit, bots, seed, attack
    std::string scheduler = "adaptive";
    bool compare = false, scenarios = false, gantt = false, csv = false, examples = false;
    bool verbose = false;            // per-process table in --compare mode
    bool help = false;
    // command-line overrides of config.ini (-1 = not given)
    Tick quantum = -1, csCost = -1, window = -1;
    int  noStarvation = -1;
};

// Build a scheduler by short name: adaptive | fcfs | rr | mlfq.
std::unique_ptr<Scheduler> makeScheduler(const std::string& key, const Config& cfg);

class App {
public:
    App() : reporter_(cfg_) {}
    int run(int argc, char** argv);

private:
    // setup
    bool parseArgs(int argc, char** argv, std::string& err);
    bool loadConfiguration();
    void applyOverrides();
    void printHelp() const;

    // workload
    bool loadWorkloadFile(const std::string& path);
    void generateWorkload(const GenerationParams& gp);

    // actions (shared by batch mode and the menu)
    void runSingle(const std::string& key);
    void runCompare();
    void runScenarios();
    void runHandExamples();

    // interactive menu
    int interactive();
    void settingsMenu();

    Config cfg_;                 // must be declared before reporter_ (reporter keeps a reference)
    Options opt_;
    Reporter reporter_;
    std::vector<PCB> workload_;
    std::string workloadLabel_;  // used in titles and CSV file names
    IngestionStats ingestion_;
    bool haveIngestion_ = false;
};

}  // namespace cmlfq
