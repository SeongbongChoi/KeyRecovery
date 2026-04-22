#pragma once

namespace krp {

struct Timings {
    double p1 = 0;
    double p2 = 0;
    double p3 = 0;
};

// One trial of the HJKY '95 proactive-secret-sharing recovery.
Timings run_hjky95(int t, int n, int lambda);

// One trial of our IEEE Access (2022) recovery protocol.
Timings run_ours(int t, int n, int lambda);

}  // namespace krp
