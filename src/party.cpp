#include "party.hpp"

namespace krp {

Party::Party(const Curve& curve, int t, int n, int index,
             std::string_view si_hex, const std::vector<std::string>& X_hex)
    : curve_(&curve)
    , t_(t)
    , n_(n)
    , index_(index)
    , si_(curve.bn_from_hex(si_hex))
    , keys_(static_cast<std::size_t>(n) + 1)
    , ivs_ (static_cast<std::size_t>(n) + 1)
{
    X_.reserve(static_cast<std::size_t>(n) + 1);
    for (int i = 0; i <= n; ++i)
        X_.push_back(curve.point_from_hex(X_hex[i]));

    for (int j = 0; j <= n; ++j) {
        keys_[j] = AesGcm::derive_key(index, j, "key_nonce");
        ivs_ [j] = AesGcm::derive_iv (index, j, "iv_nonce");
    }
}

}  // namespace krp
