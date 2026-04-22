# Key Recovery Protocol

## Overview
This repository contains the implementation of our threshold key-recovery
protocol published in IEEE Access, 2022:
[doi:10.1109/ACCESS.2022.3231570](https://ieeexplore.ieee.org/document/9992201).

For performance comparison, this repository also includes the following
baseline recovery protocol:
- **HJKY '95** (Herzberg, Jarecki, Krawczyk, Yung, CRYPTO '95): 
    *"Proactive Secret Sharing or: How to Cope with Perpetual Leakage"*

### Build

Tested on Ubuntu 24.04 LTS with OpenSSL 3.0.13.

#### Prerequisites

```
sudo apt install build-essential cmake libssl-dev
```

#### Building

```
git clone https://github.com/CryptoLabCAU/KeyRecovery.git
cd KeyRecovery
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The resulting binary is placed at `bin/krp`.

### Test

Available protocols:
```
ours     - our key-recovery protocol (IEEE Access, 2022)
hjky95   - HJKY '95 baseline
```

Example usage (ours):
trials: the number of independent trials to average timings over (default: 10)
```
bin/krp ours 10
```

Example usage (HJKY '95):
trials: the number of independent trials to average timings over (default: 10)
```
bin/krp hjky95 10
```

Output is a right-aligned table on stdout, one row per `(lambda, t)` pair:
```
  lambda       t       n   phase1 (ms)   phase2 (ms)   phase3 (ms)
     160       2       3        1.0425        0.7098        0.1802
     160       3       4        1.1324        1.1179        0.1737
     ...
```
`phase1`/`phase2`/`phase3` are the mean wall-clock times of each protocol
phase in milliseconds. The scheme is `t`-out-of-`n` with `n = t + 1`, so for
`t=3, n=4` the key is recoverable by any 3 of the 4 parties. `lambda` sweeps
160/192/224/256 bits and `t` sweeps 2..15.

### Layout

```
include/
  primitive.hpp   curve, AES-GCM, Shamir, ZK, timer, OpenSSL RAII wrappers
  party.hpp       per-party state (shares, pairwise keys)
  protocol.hpp    run_ours / run_hjky95 entry points
src/
  primitive.cpp   party.cpp
  ours.cpp        hjky95.cpp
  main.cpp        CLI dispatch
```
