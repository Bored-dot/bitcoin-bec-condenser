// vtxo.hpp — VTXO: jedan output po korisniku, iznos je činjenica a ne tvrdnja
//
// ZAŠTO OVO POSTOJI
// Stari model: jedan zajednički UTXO, N exit listova, korisnik troši CIJELI UTXO.
// Iznos koji mu pripada nije nigdje na lancu — skripta ga ne vidi, pa ga ni
// challenge/response ne može provjeriti. Posljedica: pošten izlaz i prijevara
// su ekonomski identični.
//
// Ovaj model: iznos je svojstvo outputa koji postoji na lancu.
//   1. funding tx stvara G grupnih outputa (svaki = zbroj balansa svoje grupe)
//   2. grupna tx troši grupni output i stvara po jedan VTXO za svakog korisnika,
//      s točno njegovim balansom
//   3. korisnik troši SVOJ VTXO — ne može dotaći tuđi, jer tuđi ima tuđi ključ
//
// Nema covenanta i nema pretpostavke o promatraču. Iznos se ne provjerava
// skriptom — on je već upisan u output. To je ista garancija kao kod obične
// uplate, i to je poanta: ne treba nam covenant za nešto što lanac već zna.
//
// KLJUČEVI IZRAČUN
//   VTXO output:  internal = MuSig2(operator, korisnik)
//                 leaf     = <delay> CSV DROP <korisnik> CHECKSIG
//                 → key-path traži OBA potpisa (operator ne može sam)
//                 → script-path je samo korisnikov, nakon CSV-a (unilateralni exit)
//
//   grupni output: internal = MuSig2(operator + svi korisnici grupe), bez skripta
//                 → nitko sam ne može potrošiti grupni output
//                 → grupnu tx moraju potpisati SVI u grupi ili se ne može broadcastati
//
// ŠTO OVO RJEŠAVA, A ŠTO NE
//   ✅ iznos: output na lancu ima točan iznos; nema "podigni sve"
//   ✅ tuđa sredstva: korisnik A ne može dotaći VTXO korisnika B (drugi ključ)
//   ✅ operator ne može ukrasti VTXO (MuSig2 traži i korisnikov potpis)
//   ✅ nema watchtowera za VTXO sigurnost — korisnik izlazi sam
//   ⚠️  krug: svi u grupi moraju potpisati grupnu tx. To je jednokratno, prije
//       nego što grupni output uopće postoji, ali je stvarno usko grlo.
//   ⚠️  ovo nije L2 protokol: nema state machine, gossip-a ni perzistencije.
//       Ovo je settlement sloj koji L2 može koristiti.
#pragma once

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"

namespace bec {

// ================================================================ VTXO ključevi
struct VtxoKeys {
    std::vector<unsigned char> leaf;      // exit skript
    unsigned char internal[32];           // MuSig2(operator, korisnik)
    unsigned char script_root[32];        // = leaf hash (jedan list)
    unsigned char tweak[32];              // tagged_hash("TapTweak", internal ‖ root)
    unsigned char output[32];             // tweakana output točka (x-only)
    int parity = 0;
};

inline void compute_vtxo_keys(secp256k1_context* ctx,
                              const std::vector<secp256k1_pubkey>& pks,   // [operator, korisnik]
                              const unsigned char user_xonly[32],
                              uint32_t delay_blocks,
                              VtxoKeys& out) {
    // 1. agregat bez tweaka = internal key
    KeyAgg ka;
    ka.aggregate(ctx, pks, nullptr);
    std::memcpy(out.internal, ka.agg_ser, 32);

    // 2. exit skript + njegov hash (stablo s jednim listom → root = leaf hash)
    out.leaf = csv_checksig_script(user_xonly, delay_blocks);
    tapleaf_hash(out.leaf, out.script_root);

    // 3. BIP-341 taptweak
    TaprootCommitment c;
    tap_tweak(out.internal, out.script_root, c);
    std::memcpy(out.tweak, c.tweak, 32);

    // 4. output točka = internal + tweak*G  (+ parnost za kontrolni blok)
    secp256k1_pubkey tw;
    secp256k1_xonly_pubkey nx;
    if (!secp256k1_xonly_pubkey_parse(ctx, &nx, out.internal))
        throw std::runtime_error("vtxo: internal key nije valjan");
    if (!secp256k1_xonly_pubkey_tweak_add(ctx, &tw, &nx, out.tweak))
        throw std::runtime_error("vtxo: taptweak pao");
    unsigned char s33[33]; size_t l33 = 33;
    secp256k1_ec_pubkey_serialize(ctx, s33, &l33, &tw, SECP256K1_EC_COMPRESSED);
    out.parity = (s33[0] == 0x03) ? 1 : 0;
    std::memcpy(out.output, s33 + 1, 32);
}

// ================================================================ grupni ključ
// Grupni output nema skriptno stablo, pa je output key = agregat direktno.
struct GroupKeys {
    unsigned char output[32];   // MuSig2(operator + svi u grupi), x-only
};

inline void compute_group_key(secp256k1_context* ctx,
                              const std::vector<secp256k1_pubkey>& pks,
                              GroupKeys& out) {
    KeyAgg ka;
    ka.aggregate(ctx, pks, nullptr);
    std::memcpy(out.output, ka.agg_ser, 32);
}

// ================================================================ plan kruga
struct GroupPlan {
    std::vector<size_t> users;
    uint64_t total = 0;
};

// dijeli korisnike u grupe od najviše `fanout`; svaka grupa = jedan grupni output
inline std::vector<GroupPlan> plan_groups(const std::vector<uint64_t>& amounts, size_t fanout) {
    if (fanout == 0) throw std::runtime_error("plan_groups: fanout 0");
    std::vector<GroupPlan> gs;
    GroupPlan cur;
    for (size_t i = 0; i < amounts.size(); i++) {
        cur.users.push_back(i);
        cur.total += amounts[i];
        if (cur.users.size() == fanout) { gs.push_back(cur); cur = GroupPlan(); }
    }
    if (!cur.users.empty()) gs.push_back(cur);
    return gs;
}

// ================================================================ potpisivanje
// MuSig2 preko BIP-341 sighasha za key-path: agregat mora biti tweakan istim
// tweakom kao output, inače potpis ne vrijedi za ovaj output.
inline void sign_musig_keypath(const std::vector<Signer>& signers,
                               const std::vector<secp256k1_pubkey>& pks,
                               const unsigned char* tweak_opt,
                               const Tx& tx, const std::vector<TxOut>& spent,
                               size_t in_idx, unsigned char sig64[64]) {
    if (signers.size() != pks.size()) throw std::runtime_error("sign_musig_keypath: veličine se ne slažu");
    MusigAggregator agg;
    KeyAgg ka;
    ka.aggregate(agg.ctx, pks, tweak_opt);

    unsigned char sh[32];
    sighash_taproot(tx, spent, in_idx, 0x00, 0, nullptr, sh);

    MusigSession s;
    musig_round1(agg.ctx, pks, sh, ka.cache, s);
    musig_round2(agg.ctx, signers, ka.cache, s, sig64, true);
}

} // namespace bec
