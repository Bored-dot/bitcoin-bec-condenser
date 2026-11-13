// musig.hpp — MuSig2 (BIP-327) omotač: key aggregation, dvije runde, agregacija potpisa
#pragma once

#include "crypto.hpp"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_musig.h>
#include <random>
#include <stdexcept>

namespace bec {

struct Rng {
    std::random_device rd;
    void fill(unsigned char* p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(rd() & 0xff); }
};

// Jedan potpisnik: ključ + (opcionalno) privatni ključ za potpisivanje.
struct Signer {
    secp256k1_keypair kp;
    secp256k1_pubkey  pk;
    secp256k1_xonly_pubkey xonly;
};

class MusigAggregator {
public:
    secp256k1_context* ctx;

    explicit MusigAggregator() {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        unsigned char seed[32];
        Rng rng; rng.fill(seed, 32);
        if (!secp256k1_context_randomize(ctx, seed)) throw std::runtime_error("context_randomize");
    }
    ~MusigAggregator() { if (ctx) secp256k1_context_destroy(ctx); }
    MusigAggregator(const MusigAggregator&) = delete;
    MusigAggregator& operator=(const MusigAggregator&) = delete;

    // --- učitavanje ključa iz 32-bajtnog secreta ---
    static bool make_signer(secp256k1_context* ctx, const unsigned char sk[32], Signer& out) {
        if (!secp256k1_keypair_create(ctx, &out.kp, sk)) return false;
        if (!secp256k1_keypair_pub(ctx, &out.pk, &out.kp)) return false;
        if (!secp256k1_keypair_xonly_pub(ctx, &out.xonly, nullptr, &out.kp)) return false;
        return true;
    }
};

// ================================================================ key aggregation
struct KeyAgg {
    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    unsigned char agg_ser[32];

    // agregira n ključeva; tweak_opt != nullptr primjenjuje BIP-341 taptweak kroz cache
    void aggregate(secp256k1_context* ctx, const std::vector<secp256k1_pubkey>& pks,
                   const unsigned char* tweak_opt) {
        std::vector<const secp256k1_pubkey*> ptrs;
        ptrs.reserve(pks.size());
        for (const secp256k1_pubkey& p : pks) ptrs.push_back(&p);
        if (!secp256k1_musig_pubkey_agg(ctx, &agg_pk, &cache, ptrs.data(), ptrs.size())) 
            throw std::runtime_error("musig_pubkey_agg");

        if (tweak_opt) {
            secp256k1_pubkey tweaked;
            if (!secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &cache, tweak_opt))
                throw std::runtime_error("taptweak (t >= n ili točka u beskonačnosti)");
            secp256k1_xonly_pubkey out;
            if (!secp256k1_xonly_pubkey_from_pubkey(ctx, &out, nullptr, &tweaked))
                throw std::runtime_error("tweakani ključ nije x-only");
            agg_pk = out;
        }
        secp256k1_xonly_pubkey_serialize(ctx, agg_ser, &agg_pk);
    }
};

// ================================================================ dvije runde
struct MusigSession {
    std::vector<secp256k1_musig_secnonce> secnonces;
    std::vector<secp256k1_musig_pubnonce> pubnonces;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
};

// Runda 1: svaki potpisnik generira nonce (mora biti kriptografski slučajan i NIKAD
// ponovljen — ponovna upotreba noncea otkriva privatni ključ).
inline void musig_round1(secp256k1_context* ctx, const std::vector<secp256k1_pubkey>& pks,
                         const unsigned char msg32[32], const secp256k1_musig_keyagg_cache& cache,
                         MusigSession& s) {
    size_t n = pks.size();
    s.secnonces.resize(n);
    s.pubnonces.resize(n);
    std::vector<const secp256k1_musig_pubnonce*> pp(n);
    Rng rng;
    for (size_t i = 0; i < n; i++) {
        unsigned char r[32];
        rng.fill(r, 32);
        if (!secp256k1_musig_nonce_gen(ctx, &s.secnonces[i], &s.pubnonces[i], r,
                                       nullptr, &pks[i], msg32, &cache, nullptr))
            throw std::runtime_error("musig_nonce_gen");
        pp[i] = &s.pubnonces[i];
    }
    if (!secp256k1_musig_nonce_agg(ctx, &s.aggnonce, pp.data(), n))
        throw std::runtime_error("musig_nonce_agg");
    if (!secp256k1_musig_nonce_process(ctx, &s.session, &s.aggnonce, msg32, &cache))
        throw std::runtime_error("musig_nonce_process");
}

// Runda 2: parcijalni potpisi + agregacija u 64-bajtni Schnorr potpis.
inline void musig_round2(secp256k1_context* ctx, const std::vector<Signer>& signers,
                         const secp256k1_musig_keyagg_cache& cache,
                         MusigSession& s, unsigned char sig64[64], bool verify_each = true) {
    size_t n = signers.size();
    std::vector<secp256k1_musig_partial_sig> psigs(n);
    std::vector<const secp256k1_musig_partial_sig*> pp(n);
    for (size_t i = 0; i < n; i++) {
        if (!secp256k1_musig_partial_sign(ctx, &psigs[i], &s.secnonces[i], &signers[i].kp, &cache, &s.session))
            throw std::runtime_error("musig_partial_sign");
        pp[i] = &psigs[i];
    }
    if (verify_each) {
        for (size_t i = 0; i < n; i++) {
            if (!secp256k1_musig_partial_sig_verify(ctx, &psigs[i], &s.pubnonces[i],
                                                    &signers[i].pk, &cache, &s.session))
                throw std::runtime_error("musig_partial_sig_verify (parcijalni potpis ne valja)");
        }
    }
    if (!secp256k1_musig_partial_sig_agg(ctx, sig64, &s.session, pp.data(), n))
        throw std::runtime_error("musig_partial_sig_agg");
}

// Jednostavni BIP-340 potpis (za script-path exit korisnika — nije MuSig2).
inline bool schnorr_sign(secp256k1_context* ctx, const Signer& s, const unsigned char msg32[32],
                         unsigned char sig64[64]) {
    unsigned char aux[32];
    Rng rng; rng.fill(aux, 32);
    return secp256k1_schnorrsig_sign32(ctx, sig64, msg32, &s.kp, aux) == 1;
}

inline bool schnorr_verify(secp256k1_context* ctx, const unsigned char sig64[64],
                           const unsigned char msg32[32], const secp256k1_xonly_pubkey& pk) {
    return secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &pk) == 1;
}

} // namespace bec
