// Our key-recovery protocol (IEEE Access, 2022).
//   https://ieeexplore.ieee.org/document/9992201
//
// Parties are 1-indexed.  P[1] is the leader whose share p(1) is being
// reconstructed; P[2..t+1] are the t helpers that contribute to the recovery.
//
// Phase 1: each helper pair (i, j) exchanges a random mask b[i][j], along with
//          the Pedersen-style commitment B[i][j] = b[i][j] * G.
// Phase 2: each helper decrypts the incoming masks, verifies them against the
//          commitments, and forms a partial sum
//              s_i = L_i(1) * p(i) + sum_{j != i} (b[i][j] - b[j][i])
//          encrypted to the leader.  The masks telescope when summed over i.
// Phase 3: the leader sums the partial sums; the result equals p(1), which is
//          verified against the public X[1].

#include "party.hpp"
#include "primitive.hpp"
#include "protocol.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace krp {

Timings run_ours(int t, int n, int lambda) {
    Curve curve(lambda);
    const ShamirShares shares = generate_shamir(curve, t, n);

    std::vector<std::unique_ptr<Party>> P(static_cast<std::size_t>(n) + 1);
    for (int i = 1; i <= n; ++i)
        P[i] = std::make_unique<Party>(curve, t, n, i, shares.x_hex[i], shares.X_hex);

    // Matrices indexed by party number (1..n); row/column 0 unused.
    const std::size_t dim = static_cast<std::size_t>(n) + 1;
    std::vector<std::vector<BnPtr>>                     b(dim);
    std::vector<std::vector<EcPointPtr>>                B(dim);
    std::vector<std::vector<std::vector<std::uint8_t>>> enc_b(dim);
    for (std::size_t i = 0; i < dim; ++i) {
        b[i].resize(dim);
        B[i].resize(dim);
        enc_b[i].resize(dim);
    }
    std::vector<std::vector<std::uint8_t>> enc_s(dim);

    Timer   clk;
    Timings out;

    // ---- Phase 1 ----------------------------------------------------------
    clk.reset();
    for (int i = 2; i <= t + 1; ++i) {
        for (int j = 2; j <= t + 1; ++j) {
            if (i == j) continue;
            b[i][j] = curve.rand_mod_order();
            B[i][j] = curve.new_point();
            if (!EC_POINT_mul(curve.group(), B[i][j].get(), b[i][j].get(),
                              nullptr, nullptr, curve.ctx()))
                throw_openssl("EC_POINT_mul(B)");
            enc_b[i][j] = AesGcm::encrypt(Curve::bn_to_hex(b[i][j].get()),
                                          P[i]->key(j), P[i]->iv(j));
        }
    }
    out.p1 = clk.elapsed();

    // ---- Phase 2 ----------------------------------------------------------
    clk.reset();
    for (int i = 2; i <= t + 1; ++i) {
        BnPtr li = lagrange_coefficient(curve, t + 1, i, 1);
        BnPtr s  = curve.new_bn();
        if (!BN_mod_mul(s.get(), P[i]->si(), li.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_mul(s = p(i) * L_i(1))");

        for (int j = 2; j <= t + 1; ++j) {
            if (i == j) continue;

            auto dec = AesGcm::decrypt(enc_b[j][i], P[i]->key(j), P[i]->iv(j));
            std::string bji_hex(dec.begin(), dec.end());
            BnPtr bji = curve.bn_from_hex(bji_hex);

            // Commitment check: decrypted bji must produce B[j][i].
            EcPointPtr check = curve.new_point();
            if (!EC_POINT_mul(curve.group(), check.get(), bji.get(),
                              nullptr, nullptr, curve.ctx()))
                throw_openssl("EC_POINT_mul(check)");
            if (EC_POINT_cmp(curve.group(), check.get(),
                             B[j][i].get(), curve.ctx()) != 0)
                throw std::runtime_error("mask commitment mismatch");

            if (!BN_mod_add(s.get(), s.get(), b[i][j].get(),
                            curve.order(), curve.ctx()))
                throw_openssl("BN_mod_add(+b[i][j])");
            if (!BN_mod_sub(s.get(), s.get(), bji.get(),
                            curve.order(), curve.ctx()))
                throw_openssl("BN_mod_sub(-b[j][i])");
        }

        enc_s[i] = AesGcm::encrypt(Curve::bn_to_hex(s.get()),
                                   P[i]->key(1), P[i]->iv(1));
    }
    out.p2 = clk.elapsed();

    // ---- Phase 3 ----------------------------------------------------------
    clk.reset();
    BnPtr total = curve.new_bn();
    for (int i = 2; i <= t + 1; ++i) {
        auto dec = AesGcm::decrypt(enc_s[i], P[1]->key(i), P[1]->iv(i));
        std::string hex(dec.begin(), dec.end());
        BnPtr s_i = curve.bn_from_hex(hex);
        if (!BN_mod_add(total.get(), total.get(), s_i.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_add(aggregate)");
    }

    EcPointPtr recovered = curve.new_point();
    if (!EC_POINT_mul(curve.group(), recovered.get(), total.get(),
                      nullptr, nullptr, curve.ctx()))
        throw_openssl("EC_POINT_mul(recovered)");
    if (EC_POINT_cmp(curve.group(), recovered.get(),
                     P[1]->X(1), curve.ctx()) != 0)
        throw std::runtime_error("recovered share does not match X[1]");
    out.p3 = clk.elapsed();

    return out;
}

}  // namespace krp
