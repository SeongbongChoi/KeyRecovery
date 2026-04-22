#include "primitive.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

namespace krp {

[[noreturn]] void throw_openssl(const char* what) {
    char buf[256] = {0};
    unsigned long err = ERR_get_error();
    if (err) ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(std::string("openssl: ") + what + (err ? ": " : "") + buf);
}

// ---------------------------------------------------------------------------
// Curve
// ---------------------------------------------------------------------------

namespace {
int nid_for_lambda(int lambda) {
    switch (lambda) {
        case 160: return NID_secp160k1;
        case 192: return NID_secp192k1;
        case 224: return NID_secp224k1;
        case 256: return NID_secp256k1;
        default:
            throw std::invalid_argument("Curve: unsupported lambda (expected 160/192/224/256)");
    }
}
}  // namespace

Curve::Curve(int lambda)
    : group_(EC_GROUP_new_by_curve_name(nid_for_lambda(lambda)))
    , order_(make_bn())
    , ctx_(BN_CTX_new())
{
    if (!group_) throw_openssl("EC_GROUP_new_by_curve_name");
    if (!order_) throw_openssl("BN_new(order)");
    if (!ctx_)   throw_openssl("BN_CTX_new");
    if (EC_GROUP_get_order(group_.get(), order_.get(), ctx_.get()) != 1)
        throw_openssl("EC_GROUP_get_order");
}

const EC_POINT* Curve::generator() const noexcept {
    return EC_GROUP_get0_generator(group_.get());
}

EcPointPtr Curve::new_point() const {
    EcPointPtr p{EC_POINT_new(group_.get())};
    if (!p) throw_openssl("EC_POINT_new");
    return p;
}

EcPointPtr Curve::point_from_hex(std::string_view hex) const {
    std::string z(hex);
    EcPointPtr p = new_point();
    if (!EC_POINT_hex2point(group_.get(), z.c_str(), p.get(), ctx_.get()))
        throw_openssl("EC_POINT_hex2point");
    return p;
}

std::string Curve::point_to_hex(const EC_POINT* p) const {
    char* h = EC_POINT_point2hex(group_.get(), p,
                                 EC_GROUP_get_point_conversion_form(group_.get()),
                                 ctx_.get());
    if (!h) throw_openssl("EC_POINT_point2hex");
    std::string s(h);
    OPENSSL_free(h);
    return s;
}

BnPtr Curve::rand_mod_order() const {
    BnPtr b = make_bn();
    if (!b || BN_rand_range(b.get(), order_.get()) != 1)
        throw_openssl("BN_rand_range");
    return b;
}

BnPtr Curve::bn_from_hex(std::string_view hex) const {
    std::string z(hex);
    BIGNUM* raw = nullptr;
    if (!BN_hex2bn(&raw, z.c_str())) throw_openssl("BN_hex2bn");
    return BnPtr{raw};
}

std::string Curve::bn_to_hex(const BIGNUM* b) {
    char* h = BN_bn2hex(b);
    if (!h) throw_openssl("BN_bn2hex");
    std::string s(h);
    OPENSSL_free(h);
    return s;
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

namespace {

std::string pair_material(int i, int j, std::string_view nonce) {
    auto [lo, hi] = std::minmax(i, j);
    std::string out;
    out.reserve(32 + nonce.size());
    out.append(std::to_string(hi));
    out.append(std::to_string(lo));
    out.append(nonce);
    return out;
}

void one_shot_digest(const char* alg, std::string_view data,
                     std::uint8_t* out, std::size_t out_len) {
    std::size_t len = out_len;
    if (EVP_Q_digest(nullptr, alg, nullptr,
                     data.data(), data.size(), out, &len) != 1)
        throw_openssl("EVP_Q_digest");
    if (len != out_len)
        throw std::runtime_error(std::string("digest ") + alg + ": unexpected length");
}

}  // namespace

AesGcm::Key AesGcm::derive_key(int i, int j, std::string_view nonce) {
    Key out{};
    const auto material = pair_material(i, j, nonce);
    one_shot_digest("SHA256", material, out.data(), out.size());
    return out;
}

AesGcm::Iv AesGcm::derive_iv(int i, int j, std::string_view nonce) {
    Iv out{};
    const auto material = pair_material(i, j, nonce);
    one_shot_digest("MD5", material, out.data(), out.size());
    return out;
}

std::vector<std::uint8_t> AesGcm::encrypt(std::string_view pt,
                                          const Key& key, const Iv& iv) {
    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_openssl("EVP_EncryptInit_ex(cipher)");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(IV_LEN), nullptr) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN");
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        throw_openssl("EVP_EncryptInit_ex(key/iv)");

    std::vector<std::uint8_t> out(pt.size() + TAG_LEN);
    int len = 0;
    int total = 0;
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &len,
                          reinterpret_cast<const std::uint8_t*>(pt.data()),
                          static_cast<int>(pt.size())) != 1)
        throw_openssl("EVP_EncryptUpdate");
    total += len;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) != 1)
        throw_openssl("EVP_EncryptFinal_ex");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(TAG_LEN), out.data() + total) != 1)
        throw_openssl("EVP_CTRL_GCM_GET_TAG");
    out.resize(static_cast<std::size_t>(total) + TAG_LEN);
    return out;
}

std::vector<std::uint8_t> AesGcm::decrypt(const std::vector<std::uint8_t>& in,
                                          const Key& key, const Iv& iv) {
    if (in.size() < TAG_LEN)
        throw std::runtime_error("AES-GCM: ciphertext shorter than tag");

    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_openssl("EVP_DecryptInit_ex(cipher)");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(IV_LEN), nullptr) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN");
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        throw_openssl("EVP_DecryptInit_ex(key/iv)");

    const std::size_t ct_len = in.size() - TAG_LEN;
    std::vector<std::uint8_t> out(ct_len);
    int len = 0;
    int total = 0;
    if (EVP_DecryptUpdate(ctx.get(), out.data(), &len,
                          in.data(), static_cast<int>(ct_len)) != 1)
        throw_openssl("EVP_DecryptUpdate");
    total += len;

    // Supply the expected tag.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(TAG_LEN),
                            const_cast<std::uint8_t*>(in.data() + ct_len)) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_TAG");
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) != 1)
        throw std::runtime_error("AES-GCM: tag verification failed");
    total += len;
    out.resize(static_cast<std::size_t>(total));
    return out;
}

// ---------------------------------------------------------------------------
// Shamir
// ---------------------------------------------------------------------------

ShamirShares generate_shamir(const Curve& curve, int t, int n) {
    std::vector<BnPtr> coeff(t);
    for (int i = 0; i < t; ++i)
        coeff[i] = curve.rand_mod_order();

    ShamirShares out;
    out.x_hex.resize(n + 1);
    out.X_hex.resize(n + 1);

    BnPtr       x   = curve.new_bn();
    BnPtr       idx = curve.new_bn();
    EcPointPtr  X   = curve.new_point();

    for (int i = 0; i <= n; ++i) {
        BN_zero(x.get());
        if (!BN_set_word(idx.get(), static_cast<BN_ULONG>(i)))
            throw_openssl("BN_set_word");

        // Horner evaluation of p(i) mod order.
        for (int j = t - 1; j >= 0; --j) {
            if (!BN_mod_mul(x.get(), x.get(), idx.get(), curve.order(), curve.ctx()))
                throw_openssl("BN_mod_mul");
            if (!BN_mod_add(x.get(), x.get(), coeff[j].get(), curve.order(), curve.ctx()))
                throw_openssl("BN_mod_add");
        }
        if (!EC_POINT_mul(curve.group(), X.get(), x.get(),
                          nullptr, nullptr, curve.ctx()))
            throw_openssl("EC_POINT_mul(Shamir)");

        out.x_hex[i] = Curve::bn_to_hex(x.get());
        out.X_hex[i] = curve.point_to_hex(X.get());
    }
    return out;
}

BnPtr lagrange_coefficient(const Curve& curve, int Q, int i, int x) {
    BnPtr res = curve.new_bn();
    BnPtr bnx = curve.new_bn();
    BnPtr bni = curve.new_bn();
    BN_one(res.get());
    BN_set_word(bnx.get(), static_cast<BN_ULONG>(x));
    BN_set_word(bni.get(), static_cast<BN_ULONG>(i));

    BnPtr bnj    = curve.new_bn();
    BnPtr num    = curve.new_bn();
    BnPtr den    = curve.new_bn();
    BnPtr factor = curve.new_bn();

    for (int j = 2; j <= Q; ++j) {
        if (j == i) continue;
        if (!BN_set_word(bnj.get(), static_cast<BN_ULONG>(j)))
            throw_openssl("BN_set_word(j)");

        if (!BN_mod_sub(num.get(), bnx.get(), bnj.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_sub(num)");
        if (!BN_mod_sub(den.get(), bni.get(), bnj.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_sub(den)");
        if (!BN_mod_inverse(den.get(), den.get(), curve.order(), curve.ctx()))
            throw_openssl("BN_mod_inverse");
        if (!BN_mod_mul(factor.get(), num.get(), den.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_mul(factor)");
        if (!BN_mod_mul(res.get(), res.get(), factor.get(),
                        curve.order(), curve.ctx()))
            throw_openssl("BN_mod_mul(res)");
    }
    return res;
}

// ---------------------------------------------------------------------------
// Zero-knowledge primitives
// ---------------------------------------------------------------------------

namespace {
BnPtr hash_to_scalar(const Curve& curve, const std::string& data) {
    std::uint8_t digest[32];
    one_shot_digest("SHA256", data, digest, sizeof(digest));
    BnPtr e = curve.new_bn();
    if (!BN_bin2bn(digest, sizeof(digest), e.get()))
        throw_openssl("BN_bin2bn");
    // Reduce mod order so subsequent multiplications are well-defined for any curve size.
    if (!BN_mod(e.get(), e.get(), curve.order(), curve.ctx()))
        throw_openssl("BN_mod");
    return e;
}
}  // namespace

ZkProof zk_prove(const Curve& curve, std::string_view w_hex) {
    BnPtr r = curve.rand_mod_order();
    BnPtr w = curve.bn_from_hex(w_hex);

    EcPointPtr R = curve.new_point();
    EcPointPtr W = curve.new_point();
    if (!EC_POINT_mul(curve.group(), R.get(), r.get(),
                      nullptr, nullptr, curve.ctx()))
        throw_openssl("EC_POINT_mul(R)");
    if (!EC_POINT_mul(curve.group(), W.get(), w.get(),
                      nullptr, nullptr, curve.ctx()))
        throw_openssl("EC_POINT_mul(W)");

    std::string R_hex = curve.point_to_hex(R.get());
    std::string W_hex = curve.point_to_hex(W.get());

    BnPtr e = hash_to_scalar(curve, R_hex + W_hex);

    BnPtr s = curve.new_bn();
    if (!BN_mod_mul(s.get(), e.get(), w.get(), curve.order(), curve.ctx()))
        throw_openssl("BN_mod_mul(s=e*w)");
    if (!BN_mod_add(s.get(), s.get(), r.get(), curve.order(), curve.ctx()))
        throw_openssl("BN_mod_add(s=r+e*w)");

    return {std::move(R_hex), Curve::bn_to_hex(s.get())};
}

bool zk_verify(const Curve& curve, std::string_view W_hex, const ZkProof& proof) {
    EcPointPtr W = curve.point_from_hex(W_hex);
    EcPointPtr R = curve.point_from_hex(proof.R_hex);
    BnPtr      s = curve.bn_from_hex(proof.s_hex);

    BnPtr e = hash_to_scalar(curve, proof.R_hex + std::string(W_hex));

    EcPointPtr lhs = curve.new_point();  // s * G
    EcPointPtr rhs = curve.new_point();  // R + e * W

    if (!EC_POINT_mul(curve.group(), lhs.get(), s.get(),
                      nullptr, nullptr, curve.ctx()))
        throw_openssl("EC_POINT_mul(lhs)");
    if (!EC_POINT_mul(curve.group(), rhs.get(), nullptr,
                      W.get(), e.get(), curve.ctx()))
        throw_openssl("EC_POINT_mul(e*W)");
    if (!EC_POINT_add(curve.group(), rhs.get(), rhs.get(),
                      R.get(), curve.ctx()))
        throw_openssl("EC_POINT_add");

    return EC_POINT_cmp(curve.group(), lhs.get(), rhs.get(), curve.ctx()) == 0;
}

std::string commitment(const Curve& curve, std::string_view a_hex) {
    BnPtr      a   = curve.bn_from_hex(a_hex);
    EcPointPtr com = curve.new_point();
    if (!EC_POINT_mul(curve.group(), com.get(), a.get(),
                      nullptr, nullptr, curve.ctx()))
        throw_openssl("EC_POINT_mul(commitment)");
    return curve.point_to_hex(com.get());
}

}  // namespace krp
