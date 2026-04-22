#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

namespace krp {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL handles.
// ---------------------------------------------------------------------------

struct BnDeleter           { void operator()(BIGNUM* p)         const noexcept { BN_free(p); } };
struct BnCtxDeleter        { void operator()(BN_CTX* p)         const noexcept { BN_CTX_free(p); } };
struct EcGroupDeleter      { void operator()(EC_GROUP* p)       const noexcept { EC_GROUP_free(p); } };
struct EcPointDeleter      { void operator()(EC_POINT* p)       const noexcept { EC_POINT_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); } };

using BnPtr           = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr        = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using EcGroupPtr      = std::unique_ptr<EC_GROUP, EcGroupDeleter>;
using EcPointPtr      = std::unique_ptr<EC_POINT, EcPointDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

inline BnPtr make_bn() { return BnPtr{BN_new()}; }

[[noreturn]] void throw_openssl(const char* what);

// ---------------------------------------------------------------------------
// Curve
//
// Wraps an OpenSSL EC_GROUP with its order and a BN_CTX, plus convenience
// helpers for hex (de)serialization. Select the curve by security parameter
// lambda (bits): 160, 192, 224, 256.
// ---------------------------------------------------------------------------
class Curve {
public:
    explicit Curve(int lambda);

    const EC_GROUP* group()     const noexcept { return group_.get(); }
    const BIGNUM*   order()     const noexcept { return order_.get(); }
    const EC_POINT* generator() const noexcept;
    BN_CTX*         ctx()       const noexcept { return ctx_.get(); }

    EcPointPtr  new_point()                            const;
    EcPointPtr  point_from_hex(std::string_view hex)   const;
    std::string point_to_hex  (const EC_POINT* p)      const;

    BnPtr       new_bn()                               const { return make_bn(); }
    BnPtr       rand_mod_order()                       const;
    BnPtr       bn_from_hex   (std::string_view hex)   const;
    static std::string bn_to_hex(const BIGNUM* b);

private:
    EcGroupPtr       group_;
    BnPtr            order_;
    mutable BnCtxPtr ctx_;
};

// ---------------------------------------------------------------------------
// AES-256-GCM with 128-bit IV and 128-bit authentication tag.
// encrypt() returns [ciphertext || tag]; decrypt() verifies the tag.
// ---------------------------------------------------------------------------
class AesGcm {
public:
    static constexpr std::size_t KEY_LEN = 32;
    static constexpr std::size_t IV_LEN  = 16;
    static constexpr std::size_t TAG_LEN = 16;

    using Key = std::array<std::uint8_t, KEY_LEN>;
    using Iv  = std::array<std::uint8_t, IV_LEN>;

    // Symmetric key derivation: derive_key(i, j, nonce) == derive_key(j, i, nonce).
    static Key derive_key(int i, int j, std::string_view nonce);
    static Iv  derive_iv (int i, int j, std::string_view nonce);

    static std::vector<std::uint8_t> encrypt(std::string_view plaintext,
                                             const Key& key, const Iv& iv);
    static std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& ciphertext,
                                             const Key& key, const Iv& iv);
};

// ---------------------------------------------------------------------------
// Shamir secret sharing
//
// generate_shamir(t, n) produces shares for a (t+1)-of-n threshold scheme on
// `curve`. Returned arrays have size n+1:
//   x_hex[i] = p(i)       (scalar, hex)
//   X_hex[i] = p(i) * G   (curve point, hex)
// p(0) is the secret; p(i) for i >= 1 are the shares held by each party.
// ---------------------------------------------------------------------------
struct ShamirShares {
    std::vector<std::string> x_hex;
    std::vector<std::string> X_hex;
};

ShamirShares generate_shamir(const Curve& curve, int t, int n);

// Lagrange coefficient at x, using points 2..Q excluding i:
//   L_i(x) = prod_{j=2..Q, j != i} (x - j) * (i - j)^{-1}   (mod order).
BnPtr lagrange_coefficient(const Curve& curve, int Q, int i, int x);

// ---------------------------------------------------------------------------
// Zero-knowledge primitives
//
// Non-interactive Schnorr proof of knowledge of w such that W = w * G:
//   pick r <- Z_q, R = r * G, e = H(R || W), s = r + e * w (mod q).
// Verifier accepts iff s * G == R + e * W.
// ---------------------------------------------------------------------------
struct ZkProof {
    std::string R_hex;
    std::string s_hex;
};

ZkProof zk_prove (const Curve& curve, std::string_view w_hex);
bool    zk_verify(const Curve& curve, std::string_view W_hex, const ZkProof& proof);

// Scalar commitment: com = a * G.
std::string commitment(const Curve& curve, std::string_view a_hex);

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------
class Timer {
public:
    void   reset()   noexcept       { start_ = Clock::now(); }
    double elapsed() const noexcept  {
        using namespace std::chrono;
        return duration<double>(Clock::now() - start_).count();
    }
private:
    using Clock = std::chrono::steady_clock;
    Clock::time_point start_ = Clock::now();
};

}  // namespace krp
