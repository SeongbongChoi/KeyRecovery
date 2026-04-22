#include "protocol.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string_view>

namespace {

constexpr int kDefaultTrials = 10;
constexpr int kTMin          = 2;
constexpr int kTMax          = 15;
constexpr int kLambdaMin     = 160;
constexpr int kLambdaMax     = 256;
constexpr int kLambdaStep    = 32;

using RunFn = krp::Timings(*)(int, int, int);

void benchmark(RunFn run, int trials) {
    constexpr int kwInt = 8;   // lambda/t/n columns
    constexpr int kwDbl = 14;  // phase columns

    std::cout << std::setw(kwInt) << "lambda"
              << std::setw(kwInt) << "t"
              << std::setw(kwInt) << "n"
              << std::setw(kwDbl) << "phase1 (ms)"
              << std::setw(kwDbl) << "phase2 (ms)"
              << std::setw(kwDbl) << "phase3 (ms)" << '\n';
    std::cout << std::fixed << std::setprecision(4);

    for (int lambda = kLambdaMin; lambda <= kLambdaMax; lambda += kLambdaStep) {
        for (int t = kTMin; t <= kTMax; ++t) {
            const int n = t + 1;
            krp::Timings sum{};
            for (int trial = 0; trial < trials; ++trial) {
                const auto one = run(t, n, lambda);
                sum.p1 += one.p1;
                sum.p2 += one.p2;
                sum.p3 += one.p3;
            }
            const double scale = 1000.0 / trials;
            std::cout << std::setw(kwInt) << lambda
                      << std::setw(kwInt) << t
                      << std::setw(kwInt) << n
                      << std::setw(kwDbl) << sum.p1 * scale
                      << std::setw(kwDbl) << sum.p2 * scale
                      << std::setw(kwDbl) << sum.p3 * scale << '\n';
        }
    }
}

void usage(const char* prog) {
    std::cerr << "usage: " << prog << " {ours|hjky95} [trials]\n"
              << "       trials defaults to " << kDefaultTrials << "\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) { usage(argv[0]); return 2; }

    int trials = kDefaultTrials;
    if (argc == 3) {
        trials = std::atoi(argv[2]);
        if (trials <= 0) { usage(argv[0]); return 2; }
    }

    const std::string_view proto = argv[1];
    if (proto == "ours")   { benchmark(krp::run_ours,   trials); return 0; }
    if (proto == "hjky95") { benchmark(krp::run_hjky95, trials); return 0; }
    usage(argv[0]);
    return 2;
}
