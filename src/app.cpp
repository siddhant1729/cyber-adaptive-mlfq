// app.cpp — CLI parsing, batch runs and the interactive menu.
#include "app.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "adaptive_mlfq.h"
#include "baselines.h"
#include "examples.h"
#include "json_export.h"
#include "workload.h"

namespace cmlfq {

const std::vector<std::string> kAllSchedulers = {"fcfs", "rr", "mlfq", "adaptive"};

std::unique_ptr<Scheduler> makeScheduler(const std::string& key, const Config& cfg) {
    if (key == "fcfs")     return std::make_unique<FCFSScheduler>(cfg);
    if (key == "rr")       return std::make_unique<RoundRobinScheduler>(cfg);
    if (key == "mlfq")     return std::make_unique<ClassicMLFQScheduler>(cfg);
    if (key == "adaptive") return std::make_unique<AdaptiveMLFQScheduler>(cfg);
    return nullptr;
}

// =====================================================================
// argument parsing
// =====================================================================
namespace {

bool toInt(const std::string& s, long long& out) {
    try { size_t pos; out = std::stoll(s, &pos); return pos == s.size(); }
    catch (...) { return false; }
}

}  // namespace

bool App::parseArgs(int argc, char** argv, std::string& err) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        // fetch the value that follows a flag
        auto value = [&](std::string& out) {
            if (i + 1 >= argc) { err = a + " needs a value"; return false; }
            out = argv[++i];
            return true;
        };
        auto number = [&](long long& out, long long min) {
            std::string v;
            if (!value(v)) return false;
            if (!toInt(v, out) || out < min) { err = a + ": expected an integer >= " + std::to_string(min); return false; }
            return true;
        };
        long long n = 0;
        std::string v;

        if (a == "--help" || a == "-h")      opt_.help = true;
        else if (a == "--config")            { if (!value(opt_.configPath)) return false; opt_.configExplicit = true; }
        else if (a == "--workload")          { if (!value(opt_.workloadFile)) return false; }
        else if (a == "--save-workload")     { if (!value(opt_.saveWorkloadFile)) return false; }
        else if (a == "--json")              { if (!value(opt_.jsonFile)) return false; }
        else if (a == "--generate")          opt_.generate = true;
        else if (a == "--legit")             { if (!number(n, 0)) return false; opt_.gen.legit = static_cast<int>(n); }
        else if (a == "--bots")              { if (!number(n, 0)) return false; opt_.gen.bots = static_cast<int>(n); }
        else if (a == "--seed")              { if (!number(n, 0)) return false; opt_.gen.seed = static_cast<unsigned>(n); }
        else if (a == "--attack") {
            if (!value(v)) return false;
            if (!parseAttackType(v, opt_.gen.attack)) { err = "--attack must be none|ddos|stuffing|mixed"; return false; }
        }
        else if (a == "--scheduler") {
            if (!value(v)) return false;
            if (!makeScheduler(v, cfg_)) { err = "--scheduler must be adaptive|fcfs|rr|mlfq"; return false; }
            opt_.scheduler = v;
        }
        else if (a == "--quantum")           { if (!number(n, 1)) return false; opt_.quantum = n; }
        else if (a == "--cs-cost")           { if (!number(n, 0)) return false; opt_.csCost = n; }
        else if (a == "--window")            { if (!number(n, 1)) return false; opt_.window = n; }
        else if (a == "--no-starvation-aging") opt_.noStarvation = 1;
        else if (a == "--compare")           opt_.compare = true;
        else if (a == "--scenarios")         opt_.scenarios = true;
        else if (a == "--gantt")             opt_.gantt = true;
        else if (a == "--csv")               opt_.csv = true;
        else if (a == "--verbose" || a == "-v") opt_.verbose = true;
        else if (a == "--examples")          opt_.examples = true;
        else { err = "unknown option '" + a + "' (try --help)"; return false; }
    }
    return true;
}

void App::printHelp() const {
    std::cout <<
R"(Usage: ./cmlfq [options]          (no options = interactive menu)

Workload (choose one):
  --workload FILE          load a fixed workload file (see workloads/)
  --generate               generate one with the multi-threaded ingestion layer
      --legit N            legit trader requests            (default 50)
      --bots N             attack requests                  (default 200)
      --seed N             RNG seed (same seed = same run)  (default 42)
      --attack TYPE        none | ddos | stuffing | mixed   (default mixed)
  --save-workload FILE     write the workload used to FILE (reproducibility)

What to run:
  --scheduler NAME         adaptive | fcfs | rr | mlfq      (default adaptive)
  --compare                run all four schedulers on the same workload
  --scenarios              sweep none/ddos/stuffing/mixed with all schedulers
  --examples               print the hand-verification examples (A, B, C)

Output:
  --gantt                  ASCII Gantt chart(s)
  --csv                    write CSV files to results/
  --verbose, -v            per-process tables in --compare mode
  --json FILE              also write full results as JSON (used by the web UI in ui/)

Overrides of config.ini:
  --config FILE            settings file (default ./config.ini)
  --quantum N              Q0 / RR quantum in ticks
  --cs-cost N              context-switch cost in ticks
  --window N               security sliding window in ticks
  --no-starvation-aging    disable the Q2 anti-starvation boost

Examples:
  ./cmlfq --workload workloads/hand_basic.txt --compare --gantt --cs-cost 0
  ./cmlfq --generate --legit 50 --bots 200 --seed 42 --attack ddos --compare --csv
  ./cmlfq --generate --scenarios --csv
)";
}

// =====================================================================
// configuration + workload
// =====================================================================
bool App::loadConfiguration() {
    std::string err;
    if (!std::filesystem::exists(opt_.configPath)) {
        if (opt_.configExplicit) { std::cerr << "error: config file '" << opt_.configPath << "' not found\n"; return false; }
        return true;   // silently use the built-in defaults
    }
    loadConfig(opt_.configPath, cfg_, err);
    if (!err.empty()) std::cerr << "warning: problems in " << opt_.configPath << ":\n" << err;
    return true;
}

void App::applyOverrides() {
    if (opt_.quantum >= 1) cfg_.quantum = opt_.quantum;
    if (opt_.csCost >= 0) cfg_.contextSwitchCost = opt_.csCost;
    if (opt_.window >= 1) cfg_.windowTicks = opt_.window;
    if (opt_.noStarvation == 1) cfg_.starvationAging = false;
}

bool App::loadWorkloadFile(const std::string& path) {
    std::vector<PCB> w;
    std::string err;
    if (!loadWorkload(path, w, err)) { std::cerr << "error: " << err << "\n"; return false; }
    workload_ = std::move(w);
    workloadLabel_ = std::filesystem::path(path).stem().string();
    haveIngestion_ = false;
    return true;
}

void App::generateWorkload(const GenerationParams& gp) {
    Ingestion ing(cfg_);
    workload_ = ing.generate(gp, &ingestion_);
    haveIngestion_ = true;
    workloadLabel_ = std::string(toString(gp.attack)) + "_s" + std::to_string(gp.seed);
}

// =====================================================================
// actions
// =====================================================================
void App::runSingle(const std::string& key) {
    auto sched = makeScheduler(key, cfg_);
    SimResult r = sched->run(workload_);
    Metrics m = computeMetrics(r);
    reporter_.processTable(r);
    if (opt_.gantt) reporter_.gantt(r);
    reporter_.metrics(m);
    if (opt_.csv) {
        std::string err;
        std::string base = workloadLabel_ + "_" + slug(r.name);
        if (reporter_.writeProcessCsv(r, base + "_processes.csv", err) &&
            reporter_.writeSummaryCsv({{workloadLabel_, m}}, base + "_summary.csv", err))
            std::cout << "\n  CSV written: " << reporter_.resultsPath(base + "_processes.csv") << ", "
                      << reporter_.resultsPath(base + "_summary.csv") << "\n";
        else
            std::cerr << "error: " << err << "\n";
    }
}

void App::runCompare() {
    std::vector<Metrics> all;
    std::vector<SimResult> sims;
    std::vector<std::pair<std::string, Metrics>> rows;
    std::string err;
    for (const auto& key : kAllSchedulers) {
        auto sched = makeScheduler(key, cfg_);
        SimResult r = sched->run(workload_);
        Metrics m = computeMetrics(r);
        if (opt_.verbose) reporter_.processTable(r);
        if (opt_.gantt) reporter_.gantt(r);
        if (opt_.csv && !reporter_.writeProcessCsv(r, workloadLabel_ + "_" + slug(r.name) + "_processes.csv", err))
            std::cerr << "error: " << err << "\n";
        all.push_back(m);
        rows.emplace_back(workloadLabel_, m);
        if (!opt_.jsonFile.empty()) sims.push_back(std::move(r));
    }
    if (!opt_.jsonFile.empty()) {
        std::ofstream js(opt_.jsonFile);
        if (js) writeCompareJson(js, workloadLabel_, cfg_, workload_, haveIngestion_ ? &ingestion_ : nullptr, sims, all);
        else std::cerr << "error: cannot write " << opt_.jsonFile << "\n";
    }
    reporter_.comparison(all);
    for (const auto& m : all) if (m.securityAware) { std::cout << "\n"; reporter_.securityReport(m); }
    if (opt_.csv) {
        if (reporter_.writeSummaryCsv(rows, workloadLabel_ + "_summary.csv", err))
            std::cout << "\n  CSV written to " << cfg_.resultsDir << "/ (" << workloadLabel_
                      << "_<scheduler>_processes.csv, " << workloadLabel_ << "_summary.csv)\n";
        else
            std::cerr << "error: " << err << "\n";
    }
}

void App::runScenarios() {
    const std::vector<AttackType> attacks = {AttackType::NONE, AttackType::DDOS, AttackType::STUFFING, AttackType::MIXED};
    std::vector<std::string> names;
    std::vector<std::vector<Metrics>> results;
    std::vector<std::pair<std::string, Metrics>> rows;

    reporter_.section("Scenario sweep: legit=" + std::to_string(opt_.gen.legit) + ", bots=" +
                      std::to_string(opt_.gen.bots) + ", seed=" + std::to_string(opt_.gen.seed));
    for (AttackType a : attacks) {
        GenerationParams gp = opt_.gen;
        gp.attack = a;
        IngestionStats st;
        auto w = Ingestion(cfg_).generate(gp, &st);
        std::cout << "  " << std::left;
        std::cout.width(10);
        std::cout << toString(a) << w.size() << " processes from " << st.producerThreads << " producer threads\n";

        std::vector<Metrics> row;
        for (const auto& key : kAllSchedulers) {
            Metrics m = computeMetrics(makeScheduler(key, cfg_)->run(w));
            row.push_back(m);
            rows.emplace_back(toString(a), m);
        }
        names.push_back(toString(a));
        results.push_back(row);
    }
    reporter_.scenarioTables(names, results);
    if (!opt_.jsonFile.empty()) {
        std::ofstream js(opt_.jsonFile);
        if (js) writeScenariosJson(js, opt_.gen, cfg_, names, results);
        else std::cerr << "error: cannot write " << opt_.jsonFile << "\n";
    }
    if (opt_.csv) {
        std::string err;
        if (reporter_.writeSummaryCsv(rows, "scenarios_summary.csv", err))
            std::cout << "\n  CSV written: " << reporter_.resultsPath("scenarios_summary.csv") << "\n";
        else
            std::cerr << "error: " << err << "\n";
    }
}

void App::runHandExamples() {
    Config ex = exampleConfig();
    Reporter rep(ex);
    rep.section("HAND-VERIFICATION EXAMPLES  (see tests/manual_verification.md)");
    std::cout << "  Settings: quantum 2, context-switch cost 0, window 10, velocity cap 0.5,\n"
                 "  frequency cap 5, weights 0.5/0.2/0.3, thresholds 0.30 / 0.55\n";

    std::cout << "\n##### Example A — 5 processes, no attack #####\n";
    for (const char* key : {"fcfs", "rr", "mlfq"}) {
        SimResult r = makeScheduler(key, ex)->run(exampleBasicWorkload());
        rep.gantt(r);
        Metrics m = computeMetrics(r);
        std::cout << "  avg wait " << m.all.avgWait << ", avg TAT " << m.all.avgTurnaround
                  << ", avg response " << m.all.avgResponse << ", context switches " << m.contextSwitches << "\n";
    }

    std::cout << "\n##### Example B — bot source 'BOT' among 3 legit traders #####\n";
    for (const char* key : {"fcfs", "adaptive"}) {
        SimResult r = makeScheduler(key, ex)->run(exampleSecurityWorkload());
        rep.processTable(r);
        rep.gantt(r);
        Metrics m = computeMetrics(r);
        std::cout << "  legit avg wait " << m.legit.avgWait << ", malicious avg wait " << m.malicious.avgWait << "\n";
    }

    std::cout << "\n##### Example C — forced preemption of a running bot #####\n";
    SimResult r = makeScheduler("adaptive", ex)->run(exampleForcedPreemptionWorkload());
    rep.processTable(r);
    rep.gantt(r);
    std::cout << "  forced preemptions: " << r.forcedPreemptions << "\n";
}

// =====================================================================
// interactive menu
// =====================================================================
namespace {

bool readLine(const std::string& prompt, std::string& out) {
    std::cout << prompt << std::flush;
    if (!std::getline(std::cin, out)) return false;
    auto b = out.find_first_not_of(" \t\r");
    auto e = out.find_last_not_of(" \t\r");
    out = (b == std::string::npos) ? "" : out.substr(b, e - b + 1);
    return true;
}

// Ask for an integer; empty input keeps `current`.
long long askInt(const std::string& what, long long current, long long min) {
    for (;;) {
        std::string s;
        if (!readLine("  " + what + " [" + std::to_string(current) + "]: ", s) || s.empty()) return current;
        long long v;
        if (toInt(s, v) && v >= min) return v;
        std::cout << "  please enter an integer >= " << min << "\n";
    }
}

}  // namespace

void App::settingsMenu() {
    reporter_.section("Settings (press Enter to keep the current value)");
    cfg_.quantum = askInt("Q0 / RR quantum (ticks)", cfg_.quantum, 1);
    cfg_.contextSwitchCost = askInt("Context-switch cost (ticks)", cfg_.contextSwitchCost, 0);
    cfg_.windowTicks = askInt("Security window (ticks)", cfg_.windowTicks, 1);
    cfg_.promotionAgingTicks = askInt("Promotion aging K (ticks)", cfg_.promotionAgingTicks, 0);
    cfg_.starvationAging = askInt("Q2 anti-starvation (1 = on, 0 = off)", cfg_.starvationAging ? 1 : 0, 0) != 0;
    opt_.gantt = askInt("Show Gantt charts (1/0)", opt_.gantt ? 1 : 0, 0) != 0;
    opt_.csv = askInt("Write CSV files (1/0)", opt_.csv ? 1 : 0, 0) != 0;
    opt_.verbose = askInt("Per-process tables in compare (1/0)", opt_.verbose ? 1 : 0, 0) != 0;
}

int App::interactive() {
    reporter_.banner();
    std::cout << "Interactive mode. Generating a default workload (mixed attack, 50 legit, 200 bots, seed 42)...\n";
    generateWorkload(opt_.gen);

    for (;;) {
        std::cout << "\n------------------------------------------------------------------\n"
                  << " Workload: " << workloadLabel_ << " (" << workload_.size() << " processes)"
                  << "   quantum=" << cfg_.quantum << "  cs-cost=" << cfg_.contextSwitchCost
                  << "  gantt=" << (opt_.gantt ? "on" : "off") << "  csv=" << (opt_.csv ? "on" : "off") << "\n"
                  << "------------------------------------------------------------------\n"
                  << "  1. Load workload from file\n"
                  << "  2. Generate workload (multi-threaded ingestion)\n"
                  << "  3. Show workload summary\n"
                  << "  4. Run Adaptive MLFQ (detailed)\n"
                  << "  5. Run a baseline scheduler (FCFS / RR / MLFQ)\n"
                  << "  6. Compare all schedulers\n"
                  << "  7. Run all attack scenarios\n"
                  << "  8. Hand-verification examples (A, B, C)\n"
                  << "  9. Settings\n"
                  << " 10. Show configuration\n"
                  << " 11. Save current workload to file\n"
                  << "  0. Exit\n";
        std::string choice;
        if (!readLine("Choice: ", choice)) { std::cout << "\n"; return 0; }

        if (choice == "0" || choice == "q") return 0;
        else if (choice == "1") {
            std::string path;
            if (readLine("  Workload file path: ", path) && !path.empty() && loadWorkloadFile(path))
                reporter_.workloadSummary(workload_, workloadLabel_);
        } else if (choice == "2") {
            GenerationParams gp = opt_.gen;
            gp.legit = static_cast<int>(askInt("Legit requests", gp.legit, 0));
            gp.bots = static_cast<int>(askInt("Attack requests", gp.bots, 0));
            gp.seed = static_cast<unsigned>(askInt("Seed", gp.seed, 0));
            std::string a;
            readLine(std::string("  Attack type none|ddos|stuffing|mixed [") + toString(gp.attack) + "]: ", a);
            if (!a.empty() && !parseAttackType(a, gp.attack)) std::cout << "  unknown attack type, keeping "
                                                                        << toString(gp.attack) << "\n";
            opt_.gen = gp;
            generateWorkload(gp);
            reporter_.workloadSummary(workload_, workloadLabel_, &ingestion_);
        } else if (choice == "3") {
            reporter_.workloadSummary(workload_, workloadLabel_, haveIngestion_ ? &ingestion_ : nullptr);
        } else if (choice == "4") {
            runSingle("adaptive");
        } else if (choice == "5") {
            std::string k;
            readLine("  Which baseline (fcfs / rr / mlfq): ", k);
            if (k == "fcfs" || k == "rr" || k == "mlfq") runSingle(k);
            else std::cout << "  unknown scheduler\n";
        } else if (choice == "6") {
            runCompare();
        } else if (choice == "7") {
            runScenarios();
        } else if (choice == "8") {
            runHandExamples();
        } else if (choice == "9") {
            settingsMenu();
        } else if (choice == "10") {
            reporter_.section("Configuration");
            std::cout << describeConfig(cfg_);
        } else if (choice == "11") {
            std::string path, err;
            if (readLine("  Save to: ", path) && !path.empty()) {
                if (saveWorkload(path, workload_, err)) std::cout << "  saved " << workload_.size() << " processes\n";
                else std::cerr << "  error: " << err << "\n";
            }
        } else {
            std::cout << "  unknown choice\n";
        }
    }
}

// =====================================================================
// entry point
// =====================================================================
int App::run(int argc, char** argv) {
    std::string err;
    if (!parseArgs(argc, argv, err)) { std::cerr << "error: " << err << "\n"; return 2; }
    if (opt_.help) { printHelp(); return 0; }
    if (!loadConfiguration()) return 2;
    applyOverrides();

    if (argc == 1) return interactive();

    reporter_.banner();
    if (opt_.examples) { runHandExamples(); if (!opt_.generate && opt_.workloadFile.empty()) return 0; }

    if (opt_.scenarios) { runScenarios(); return 0; }

    if (!opt_.workloadFile.empty()) {
        if (!loadWorkloadFile(opt_.workloadFile)) return 1;
    } else if (opt_.generate) {
        generateWorkload(opt_.gen);
    } else {
        std::cerr << "error: give --workload FILE or --generate (or run with no arguments for the menu)\n";
        return 2;
    }
    reporter_.workloadSummary(workload_, workloadLabel_, haveIngestion_ ? &ingestion_ : nullptr);

    if (!opt_.saveWorkloadFile.empty()) {
        if (saveWorkload(opt_.saveWorkloadFile, workload_, err))
            std::cout << "  Workload saved to " << opt_.saveWorkloadFile << "\n";
        else
            std::cerr << "error: " << err << "\n";
    }

    if (opt_.compare) runCompare();
    else              runSingle(opt_.scheduler);
    return 0;
}

}  // namespace cmlfq
