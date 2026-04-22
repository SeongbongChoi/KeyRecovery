// Baseline proactive-secret-sharing key recovery.
//
// Herzberg, Jarecki, Krawczyk, Yung, "Proactive Secret Sharing or:
// How to Cope with Perpetual Leakage", CRYPTO '95, LNCS 963, pp. 339-352.
//
// Parties are 1-indexed.  P[1] is the leader whose share p(1) is being
// reconstructed.  Every other party P[2..n] is a helper.
//
// Phase 1: each helper i samples a random "zero polynomial" R_i of degree
//          t-1 with R_i(1) = 0, publishes commitments C_{i,k} = c_{i,k}*G,
//          and sends the encrypted share R_i(p) to every other party p.
// Phase 2: each recovering party p in [2..t+1] decrypts the incoming R_j(p),
//          verifies it via   R_j(p) * G == sum_k p^k * C_{j,k},
//          and forms  a_p = p(p) + sum_j R_j(p)  encrypted to the leader.
// Phase 3: the leader interpolates   p(1) = sum_p L_p(1) * a_p
//          and checks against the public X[1].  The zero polynomials cancel
//          under Lagrange interpolation at x=1 because each R_j(1) = 0.

#include "party.hpp"
#include "primitive.hpp"
#include "protocol.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace krp {
namespace {

// Evaluate a degree-(coeff.size()-1) polynomial at point x (mod order).
BnPtr poly_eval(const Curve& curve, const std::vector<BnPtr>& coeff, int x) {
    BnPtr res = curve.new_bn();
    BnPtr bnx = curve.new_bn();
    BN_zero(res.get());
    if (!BN_set_word(bnx.get(), static_cast<BN_ULONG>(x)))
        throw_openssl("BN_set_word");
    for (int k = static_cast<int>(coeff.size()) - 1; k >= 0; --k) {
        if (!BN_mod_mul(res.get(), res.get(), bnx.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_mul(poly)");
        if (!BN_mod_add(res.get(), res.get(), coeff[k].get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_add(poly)");
    }
    return res;
}

}  // namespace

Timings run_hjky95(int t, int n, int lambda) {
    Curve curve(lambda);
    const ShamirShares shares = generate_shamir(curve, t, n);

    std::vector<std::unique_ptr<Party>> P(static_cast<std::size_t>(n) + 1);
    for (int i = 1; i <= n; ++i)
        P[i] = std::make_unique<Party>(curve, t, n, i, shares.x_hex[i], shares.X_hex);

    const std::size_t dim = static_cast<std::size_t>(n) + 1;
    std::vector<std::vector<BnPtr>>                     coeff_r(dim);
    std::vector<std::vector<std::string>>               C_hex(dim);
    std::vector<std::vector<BnPtr>>                     r_to(dim);
    std::vector<std::vector<std::vector<std::uint8_t>>> enc_r(dim);
    for (std::size_t i = 0; i < dim; ++i) {
        r_to[i].resize(dim);
        enc_r[i].resize(dim);
    }
    std::vector<std::vector<std::uint8_t>> enc_a(dim);

    Timer   clk;
    Timings out;

    // ---- Phase 1 ----------------------------------------------------------
    clk.reset();
    for (int i = 2; i <= n; ++i) {
        coeff_r[i].resize(t);
        C_hex  [i].resize(t);

        // Sample c_{i,1}..c_{i,t-1} at random; force c_{i,0} = -sum so R_i(1) = 0.
        coeff_r[i][0] = curve.new_bn();
        BN_zero(coeff_r[i][0].get());
        for (int k = 1; k < t; ++k) {
            coeff_r[i][k] = curve.rand_mod_order();
            if (!BN_mod_sub(coeff_r[i][0].get(), coeff_r[i][0].get(),
                            coeff_r[i][k].get(), curve.order(), curve.ctx()))
                throw_openssl("BN_mod_sub(c_{i,0})");
        }
        for (int k = 0; k < t; ++k)
            C_hex[i][k] = commitment(curve, Curve::bn_to_hex(coeff_r[i][k].get()));

        // Evaluate R_i at every recovering point p = 2..t+1, encrypt outgoing shares.
        for (int p = 2; p <= t + 1; ++p) {
            r_to[i][p] = poly_eval(curve, coeff_r[i], p);
            if (i != p) {
                enc_r[i][p] = AesGcm::encrypt(Curve::bn_to_hex(r_to[i][p].get()),
                                              P[i]->key(p), P[i]->iv(p));
            }
        }
    }
    out.p1 = clk.elapsed();

    // ---- Phase 2 ----------------------------------------------------------
    clk.reset();
    std::vector<BnPtr> a(dim);
    for (int p = 2; p <= t + 1; ++p) {
        a[p] = curve.new_bn();
        BN_zero(a[p].get());

        // Precompute powers of p used in commitment verification.
        std::vector<BnPtr> p_powers(static_cast<std::size_t>(t));
        p_powers[0] = curve.new_bn(); BN_one(p_powers[0].get());
        if (t > 1) {
            p_powers[1] = curve.new_bn();
            BN_set_word(p_powers[1].get(), static_cast<BN_ULONG>(p));
        }
        for (int k = 2; k < t; ++k) {
            p_powers[k] = curve.new_bn();
            if (!BN_mod_mul(p_powers[k].get(), p_powers[k - 1].get(),
                            p_powers[1].get(), curve.order(), curve.ctx()))
                throw_openssl("BN_mod_mul(p^k)");
        }

        for (int j = 2; j <= n; ++j) {
            BnPtr rjp;
            if (j == p) {
                rjp = curve.new_bn();
                if (!BN_copy(rjp.get(), r_to[j][p].get()))
                    throw_openssl("BN_copy(self)");
            } else {
                auto dec = AesGcm::decrypt(enc_r[j][p], P[p]->key(j), P[p]->iv(j));
                std::string hex(dec.begin(), dec.end());
                rjp = curve.bn_from_hex(hex);

                EcPointPtr lhs = curve.new_point();
                EcPointPtr rhs = curve.new_point();
                if (!EC_POINT_mul(curve.group(), lhs.get(), rjp.get(),
                                  nullptr, nullptr, curve.ctx()))
                    throw_openssl("EC_POINT_mul(lhs)");
                for (int k = 0; k < t; ++k) {
                    EcPointPtr Ck = curve.point_from_hex(C_hex[j][k]);
                    EcPointPtr term = curve.new_point();
                    if (!EC_POINT_mul(curve.group(), term.get(), nullptr,
                                      Ck.get(), p_powers[k].get(), curve.ctx()))
                        throw_openssl("EC_POINT_mul(p^k * C)");
                    if (!EC_POINT_add(curve.group(), rhs.get(), rhs.get(),
                                      term.get(), curve.ctx()))
                        throw_openssl("EC_POINT_add(rhs)");
                }
                if (EC_POINT_cmp(curve.group(), lhs.get(), rhs.get(), curve.ctx()) != 0)
                    throw std::runtime_error("HJKY commitment verification failed");
            }

            if (!BN_mod_add(a[p].get(), a[p].get(), rjp.get(),
                            curve.order(), curve.ctx()))
                throw_openssl("BN_mod_add(a)");
        }

        if (!BN_mod_add(a[p].get(), a[p].get(), P[p]->si(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_add(+p(p))");
        enc_a[p] = AesGcm::encrypt(Curve::bn_to_hex(a[p].get()),
                                   P[p]->key(1), P[p]->iv(1));
    }
    out.p2 = clk.elapsed();

    // ---- Phase 3 ----------------------------------------------------------
    clk.reset();
    BnPtr total = curve.new_bn();
    BN_zero(total.get());
    for (int p = 2; p <= t + 1; ++p) {
        auto dec = AesGcm::decrypt(enc_a[p], P[1]->key(p), P[1]->iv(p));
        std::string hex(dec.begin(), dec.end());
        BnPtr a_p = curve.bn_from_hex(hex);

        BnPtr lp   = lagrange_coefficient(curve, t + 1, p, 1);
        BnPtr term = curve.new_bn();
        if (!BN_mod_mul(term.get(), lp.get(), a_p.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_mul(L_p * a_p)");
        if (!BN_mod_add(total.get(), total.get(), term.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_add(total)");
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
