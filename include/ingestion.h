// =====================================================================
//  ingestion.h  —  multi-threaded request ingestion (producer/consumer)
//
//  This is the ONLY part of the project that uses real threads.
//
//    producer threads (one per traffic source)        consumer thread
//    ┌──────────────┐                                ┌──────────────┐
//    │ TRADER-01    │──┐                             │              │
//    │ TRADER-02    │──┤   push()   ┌─────────────┐  │  pop() and   │
//    │ ...          │──┼──────────▶ │ArrivalBuffer│─▶│  collect     │
//    │ DDOS-IP-1    │──┤  (blocks   │ bounded,    │  │              │
//    │ TOKEN-007    │──┘  if full)  │ mutex + 2 CV│  └──────────────┘
//    └──────────────┘               └─────────────┘
//
//  Each producer stamps its requests with SIMULATED arrival ticks drawn
//  from its own seeded RNG (seed + source index). Because the ticks are
//  simulated — never wall-clock — and the collected requests are sorted
//  by (arrival, source, sequence) afterwards, the final workload is
//  identical on every run with the same seed, no matter how the OS
//  happens to interleave the threads.
// =====================================================================
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "pcb.h"

namespace cmlfq {

enum class AttackType { NONE, DDOS, STUFFING, MIXED };

const char* toString(AttackType a);
bool parseAttackType(const std::string& s, AttackType& out);

// One request as produced by a traffic source, before it becomes a PCB.
struct Request {
    std::string sourceId;
    int    seq = 0;              // index within its source (for stable ordering)
    Tick   arrival = 0;
    Tick   burst = 1;
    double anomaly = 0.0;
    bool   malicious = false;    // ground truth
};

// ---------------------------------------------------------------------
// Bounded, thread-safe FIFO buffer (classic producer/consumer problem).
//   push() blocks while the buffer is full     (waits on notFull_)
//   pop()  blocks while the buffer is empty    (waits on notEmpty_)
//   pop() returns false once every producer has finished AND the
//   buffer is drained — that is the consumer's signal to stop.
// ---------------------------------------------------------------------
class ArrivalBuffer {
public:
    ArrivalBuffer(std::size_t capacity, int producers);

    void push(Request r);
    bool pop(Request& out);
    void producerFinished();

    std::size_t peakOccupancy() const;
    long long   producerWaits() const;   // times a producer had to block on a full buffer

private:
    mutable std::mutex m_;
    std::condition_variable notFull_, notEmpty_;
    std::deque<Request> q_;
    std::size_t capacity_;
    int activeProducers_;
    std::size_t peak_ = 0;
    long long fullWaits_ = 0;
};

struct GenerationParams {
    int legit = 50;               // number of legitimate requests
    int bots = 200;               // number of attack requests
    unsigned seed = 42;
    AttackType attack = AttackType::MIXED;
};

struct IngestionStats {
    int producerThreads = 0;
    int legitSources = 0;
    int botSources = 0;
    std::size_t requests = 0;
    std::size_t peakBuffer = 0;
    long long producerWaits = 0;
    double wallMillis = 0.0;
};

class Ingestion {
public:
    explicit Ingestion(const Config& cfg) : cfg_(cfg) {}

    // Spawn the producer threads + a consumer thread, collect every
    // request, and return them as PCBs (pids 1..N in arrival order).
    std::vector<PCB> generate(const GenerationParams& params, IngestionStats* stats = nullptr) const;

private:
    const Config& cfg_;
};

}  // namespace cmlfq
