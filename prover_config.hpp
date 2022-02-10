#ifndef ETHSNARKS_PROVER_CONFIG_HPP_
#define ETHSNARKS_PROVER_CONFIG_HPP_

#include <vector>

namespace libsnark {

struct Config
{
    Config()
    {
#ifdef MULTICORE
        num_threads = omp_get_max_threads();
#else
        num_threads = 1;
#endif
        fft = "recursive";
        smt = false;
        swapAB = true;
        multi_exp_c = 0;
        multi_exp_prefetch_locality = 0;
        prefetch_stride = 128;
        multi_exp_look_ahead = 1;
    }

    unsigned int num_threads;
    bool smt;
    std::string fft;
    std::vector<unsigned int> radixes;
    bool swapAB;
    unsigned int multi_exp_c;
    unsigned int multi_exp_prefetch_locality;   // 4 == no prefetching, [0, 3] prefetch locality
    unsigned int prefetch_stride;               // 4 * L1_CACHE_BYTES
    unsigned int multi_exp_look_ahead;
};

static std::ostream &operator<<(std::ostream &os, const Config& c)
{
    std::string radixes = "[";
    for (unsigned int i = 0; i < c.radixes.size(); i++)
    {
        radixes += (i == 0 ? "" : ",") + std::to_string(c.radixes[i]);
    }
    radixes += "]";

    return os <<
    "num_threads: " << c.num_threads << ", " <<
    "smt: " << c.smt << ", " <<
    "fft: " << c.fft << ", " <<
    "radixes: " << radixes << ", " <<
    "exp_c: " << c.multi_exp_c << ", " <<
    "pre_stride: " << c.prefetch_stride << ", " <<
    "exp_preloc: " << c.multi_exp_prefetch_locality << ", " <<
    "exp_lookahead: " << c.multi_exp_look_ahead;
}

static inline std::vector<std::pair<unsigned int, unsigned int>> get_cpu_ranges(unsigned int startIdx, unsigned int length, unsigned int num_threads = 0)
{
#ifdef MULTICORE
    size_t n = num_threads == 0 ? omp_get_max_threads() : num_threads;
#else
    size_t n = 1;
#endif

    std::vector<std::pair<unsigned int, unsigned int>> ranges;
    if (startIdx >= length)
    {
        return ranges;
    }
    ranges.reserve(n);

    auto dist = length - startIdx;
    n = std::min<unsigned int>(n, dist);
    unsigned int chunk = dist / n;
    unsigned int remainder = dist % n;

    for (unsigned int i = 0; i < n-1; i++)
    {
        auto next_end = startIdx + chunk + ((i < remainder) ? 1 : 0);
        ranges.emplace_back(startIdx, next_end);
        startIdx = next_end;
    }
    ranges.emplace_back(startIdx, length);
    return ranges;
}

}

#endif