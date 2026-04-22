#pragma once

#include "primitive.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace krp {

// Per-party state for the key-recovery protocol.
// Parties are 1-indexed: valid indices are 1..n. Each party holds pairwise
// AES keys/IVs with every other party; key(j)/iv(j) are shared with party j.
class Party {
public:
    Party(const Curve& curve, int t, int n, int index,
          std::string_view si_hex, const std::vector<std::string>& X_hex);

    const Curve& curve() const noexcept { return *curve_; }
    int index() const noexcept { return index_; }
    int t()     const noexcept { return t_; }
    int n()     const noexcept { return n_; }

    const BIGNUM*   si()     const noexcept { return si_.get(); }
    const EC_POINT* X(int i) const noexcept { return X_[i].get(); }

    const AesGcm::Key& key(int j) const { return keys_[j]; }
    const AesGcm::Iv&  iv (int j) const { return ivs_[j]; }

private:
    const Curve* curve_;
    int t_;
    int n_;
    int index_;

    BnPtr si_;
    std::vector<EcPointPtr>  X_;      // size n+1, X_[i] = p(i) * G
    std::vector<AesGcm::Key> keys_;   // size n+1, keys_[j] shared with party j
    std::vector<AesGcm::Iv>  ivs_;    // size n+1
};

}  // namespace krp
