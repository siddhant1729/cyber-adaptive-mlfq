// ingestion.cpp — threaded producer/consumer request generation.
#include "ingestion.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <thread>

namespace cmlfq {

const char* toString(AttackType a) {
    switch (a) {
        case AttackType::NONE:     return "none";
        case AttackType::DDOS:     return "ddos";
        case AttackType::STUFFING: return "stuffing";
        case AttackType::MIXED:    return "mixed";
    }
    return "?";
}

bool parseAttackType(const std::string& s, AttackType& out) {
    if (s == "none")     { out = AttackType::NONE;     return true; }
    if (s == "ddos")     { out = AttackType::DDOS;     return true; }
    if (s == "stuffing") { out = AttackType::STUFFING; return true; }
    if (s == "mixed")    { out = AttackType::MIXED;    return true; }
    return false;
}

// ============================ ArrivalBuffer ==========================
ArrivalBuffer::ArrivalBuffer(std::size_t capacity, int producers)
    : capacity_(capacity == 0 ? 1 : capacity), activeProducers_(producers) {}

void ArrivalBuffer::push(Request r) {
    std::unique_lock<std::mutex> lock(m_);
    if (q_.size() >= capacity_) ++fullWaits_;
    notFull_.wait(lock, [this] { return q_.size() < capacity_; });
    q_.push_back(std::move(r));
    peak_ = std::max(peak_, q_.size());
    lock.unlock();
    notEmpty_.notify_one();
}

bool ArrivalBuffer::pop(Request& out) {
    std::unique_lock<std::mutex> lock(m_);
    notEmpty_.wait(lock, [this] { return !q_.empty() || activeProducers_ == 0; });
    if (q_.empty()) return false;  // all producers done and nothing left
    out = std::move(q_.front());
    q_.pop_front();
    lock.unlock();
    notFull_.notify_one();
    return true;
}

void ArrivalBuffer::producerFinished() {
    {
        std::lock_guard<std::mutex> lock(m_);
        --activeProducers_;
    }
    notEmpty_.notify_all();  // wake the consumer so it can notice the end
}

std::size_t ArrivalBuffer::peakOccupancy() const {
    std::lock_guard<std::mutex> lock(m_);
    return peak_;
}

long long ArrivalBuffer::producerWaits() const {
    std::lock_guard<std::mutex> lock(m_);
    return fullWaits_;
}

// ============================ producers ==============================
namespace {

enum class SourceKind { LEGIT_TRADER, DDOS_BOT, STUFFING_TOKEN };

struct SourceSpec {
    SourceKind kind;
    std::string id;
    int requests;      // how many requests this source will send
    unsigned seed;     // private RNG seed -> deterministic per source
};

Tick randTick(std::mt19937& rng, Tick lo, Tick hi) {
    if (hi < lo) std::swap(lo, hi);
    return std::uniform_int_distribution<Tick>(lo, hi)(rng);
}

double randReal(std::mt19937& rng, double lo, double hi) {
    if (hi < lo) std::swap(lo, hi);
    return std::uniform_real_distribution<double>(lo, hi)(rng);
}

// Body of one producer thread. All "timing" here is simulated ticks.
void produce(const SourceSpec& s, const Config& cfg, ArrivalBuffer& buf) {
    std::mt19937 rng(s.seed);
    Tick t = 0;
    for (int i = 0; i < s.requests; ++i) {
        Request r;
        r.sourceId = s.id;
        r.seq = i;
        switch (s.kind) {
            case SourceKind::LEGIT_TRADER: {
                // Low rate: requests evenly spaced over the horizon with random jitter.
                Tick spacing = std::max<Tick>(1, cfg.horizon / std::max(1, s.requests));
                t = i * spacing + randTick(rng, 0, spacing - 1);
                r.burst = randTick(rng, cfg.legitBurstMin, cfg.legitBurstMax);
                r.anomaly = randReal(rng, 0.0, cfg.legitAnomalyMax);
                r.malicious = false;
                break;
            }
            case SourceKind::DDOS_BOT: {
                // Few sources, each firing a high-velocity burst of requests.
                t = (i == 0) ? cfg.attackStart + randTick(rng, 0, 20)
                             : t + randTick(rng, cfg.ddosGapMin, cfg.ddosGapMax);
                r.burst = randTick(rng, cfg.ddosBurstMin, cfg.ddosBurstMax);
                r.anomaly = randReal(rng, cfg.ddosAnomalyMin, cfg.ddosAnomalyMax);
                r.malicious = true;
                break;
            }
            case SourceKind::STUFFING_TOKEN: {
                // Many tokens; each makes a few rapid login retries with odd payloads.
                t = (i == 0) ? cfg.attackStart + randTick(rng, 0, std::max<Tick>(0, cfg.stuffingSpread - 1))
                             : t + randTick(rng, cfg.stuffingGapMin, cfg.stuffingGapMax);
                r.burst = randTick(rng, cfg.stuffingBurstMin, cfg.stuffingBurstMax);
                r.anomaly = randReal(rng, cfg.stuffingAnomalyMin, cfg.stuffingAnomalyMax);
                r.malicious = true;
                break;
            }
        }
        r.arrival = t;
        buf.push(std::move(r));
    }
    buf.producerFinished();
}

std::string makeId(const char* prefix, int index, int width) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%s%0*d", prefix, width, index);
    return buf;
}

// Split `total` requests across `sources` sources as evenly as possible.
void addSources(std::vector<SourceSpec>& out, SourceKind kind, const char* prefix,
                int total, int sources, unsigned baseSeed) {
    if (total <= 0) return;
    sources = std::max(1, std::min(sources, total));
    for (int i = 0; i < sources; ++i) {
        int share = total / sources + (i < total % sources ? 1 : 0);
        unsigned seed = baseSeed * 1000003u + static_cast<unsigned>(out.size()) * 7919u + 17u;
        out.push_back({kind, makeId(prefix, i + 1, 3), share, seed});
    }
}

}  // namespace

// ============================ Ingestion ==============================
std::vector<PCB> Ingestion::generate(const GenerationParams& params, IngestionStats* stats) const {
    auto wallStart = std::chrono::steady_clock::now();

    // ---- 1. decide which traffic sources exist ----
    std::vector<SourceSpec> specs;
    int perTrader = std::max(1, cfg_.legitRequestsPerTrader);
    int traders = (params.legit + perTrader - 1) / perTrader;
    addSources(specs, SourceKind::LEGIT_TRADER, "TRADER-", params.legit, traders, params.seed);
    int legitSources = static_cast<int>(specs.size());

    switch (params.attack) {
        case AttackType::NONE:
            break;
        case AttackType::DDOS:
            addSources(specs, SourceKind::DDOS_BOT, "DDOS-IP-", params.bots, cfg_.ddosSources, params.seed);
            break;
        case AttackType::STUFFING:
            addSources(specs, SourceKind::STUFFING_TOKEN, "TOKEN-", params.bots, cfg_.stuffingTokens, params.seed);
            break;
        case AttackType::MIXED: {
            int ddosBots = params.bots / 2;
            addSources(specs, SourceKind::DDOS_BOT, "DDOS-IP-", ddosBots,
                       std::max(1, cfg_.ddosSources / 2), params.seed);
            addSources(specs, SourceKind::STUFFING_TOKEN, "TOKEN-", params.bots - ddosBots,
                       std::max(1, cfg_.stuffingTokens / 2), params.seed);
            break;
        }
    }

    // ---- 2. start the consumer, then one producer thread per source ----
    ArrivalBuffer buffer(cfg_.bufferCapacity, static_cast<int>(specs.size()));
    std::vector<Request> collected;

    std::thread consumer([&buffer, &collected] {
        Request r;
        while (buffer.pop(r)) collected.push_back(std::move(r));
    });

    std::vector<std::thread> producers;
    producers.reserve(specs.size());
    for (const auto& spec : specs)
        producers.emplace_back(produce, std::cref(spec), std::cref(cfg_), std::ref(buffer));

    for (auto& t : producers) t.join();
    consumer.join();   // returns once every producer finished and the buffer is empty

    // ---- 3. make the result independent of thread interleaving ----
    std::sort(collected.begin(), collected.end(), [](const Request& a, const Request& b) {
        if (a.arrival != b.arrival) return a.arrival < b.arrival;
        if (a.sourceId != b.sourceId) return a.sourceId < b.sourceId;
        return a.seq < b.seq;
    });

    std::vector<PCB> procs;
    procs.reserve(collected.size());
    int pid = 1;
    for (const auto& r : collected)
        procs.push_back(makePCB(pid++, r.sourceId, r.arrival, r.burst, r.anomaly, r.malicious));

    if (stats) {
        stats->producerThreads = static_cast<int>(specs.size());
        stats->legitSources = legitSources;
        stats->botSources = static_cast<int>(specs.size()) - legitSources;
        stats->requests = collected.size();
        stats->peakBuffer = buffer.peakOccupancy();
        stats->producerWaits = buffer.producerWaits();
        stats->wallMillis = std::chrono::duration<double, std::milli>(
                                std::chrono::steady_clock::now() - wallStart).count();
    }
    return procs;
}

}  // namespace cmlfq
