// vtxo_round.hpp — model kruga: ključevi, funding tx, grupne tx, potpisivanje
//
// Odvojeno od CLI-a da se može testirati i čitati bez argumenata. Sve što
// CLI radi je: napuni polja, pozove build_* i sign_*, pa zapiše rezultat.
#pragma once

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"
#include "vtxo.hpp"

#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <stdexcept>

namespace bec {

// ================================================================ manifest
inline std::map<std::string, std::string> vtxo_read_kv(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) throw std::runtime_error("ne mogu otvoriti " + path);
    std::map<std::string, std::string> m;
    std::string l;
    while (std::getline(f, l)) {
        while (!l.empty() && (l.back() == '\r' || l.back() == ' ')) l.pop_back();
        size_t eq = l.find('=');
        if (eq == std::string::npos) continue;
        m[l.substr(0, eq)] = l.substr(eq + 1);
    }
    return m;
}
inline const std::string& vtxo_kv(const std::map<std::string, std::string>& m, const std::string& k) {
    auto it = m.find(k);
    if (it == m.end()) throw std::runtime_error("manifest: nedostaje '" + k + "'");
    return it->second;
}
inline uint64_t vtxo_kv_u64(const std::map<std::string, std::string>& m, const std::string& k) {
    return std::stoull(vtxo_kv(m, k));
}
inline size_t vtxo_kv_sz(const std::map<std::string, std::string>& m, const std::string& k) {
    return (size_t)std::stoul(vtxo_kv(m, k));
}

inline bool vtxo_txid_rev(const std::string& hex, unsigned char out[32]) {
    unsigned char t[32];
    if (!from_hex32(hex, t)) return false;
    for (int i = 0; i < 32; i++) out[i] = t[31 - i];
    return true;
}

inline void vtxo_write_hex(const std::string& path, const std::vector<unsigned char>& raw) {
    std::ofstream o(path);
    if (!o.good()) throw std::runtime_error("ne mogu pisati " + path);
    o << to_hex(raw) << "\n";
}

// ================================================================ krug
struct Round {
    size_t n_users = 0, fanout = 4;
    uint32_t delay = 144;
    uint64_t group_fee = 400, funding_fee = 500;
    std::string hrp = "bcrt";

    std::vector<unsigned char> op_sk, op_change_script;
    std::vector<std::vector<unsigned char>> user_sk;
    std::vector<uint64_t> amounts;

    unsigned char fund_txid[32];
    uint32_t fund_vout = 0;
    uint64_t fund_amount = 0;

    // izvedeno
    Signer op;
    std::vector<Signer> users;
    std::vector<unsigned char> op_x;
    std::vector<unsigned char> user_x_all;      // n * 32
    std::vector<GroupPlan> groups;
    std::vector<GroupKeys> gkeys;
    std::vector<VtxoKeys> vtxos;

    Tx funding;
    std::vector<Tx> gtxs;

    const unsigned char* ux(size_t i) const { return &user_x_all[i * 32]; }

    void build_keys() {
        MusigAggregator agg;
        users.resize(n_users);
        user_x_all.assign(n_users * 32, 0);
        for (size_t i = 0; i < n_users; i++) {
            if (!MusigAggregator::make_signer(agg.ctx, user_sk[i].data(), users[i]))
                throw std::runtime_error("neispravan korisnički ključ");
            secp256k1_xonly_pubkey_serialize(agg.ctx, &user_x_all[i * 32], &users[i].xonly);
        }
        if (!MusigAggregator::make_signer(agg.ctx, op_sk.data(), op))
            throw std::runtime_error("neispravan operatorov ključ");
        op_x.assign(32, 0);
        secp256k1_xonly_pubkey_serialize(agg.ctx, op_x.data(), &op.xonly);
    }

    // grupni ključ = MuSig2(operator + svi korisnici grupe)
    std::vector<secp256k1_pubkey> group_pks(size_t g) const {
        std::vector<secp256k1_pubkey> pks;
        pks.push_back(op.pk);
        for (size_t u : groups[g].users) pks.push_back(users[u].pk);
        return pks;
    }

    std::vector<Signer> group_signers(size_t g) const {
        std::vector<Signer> s;
        s.push_back(op);
        for (size_t u : groups[g].users) s.push_back(users[u]);
        return s;
    }

    void build_plan() {
        MusigAggregator agg;
        groups = plan_groups(amounts, fanout);
        gkeys.resize(groups.size());
        for (size_t g = 0; g < groups.size(); g++)
            compute_group_key(agg.ctx, group_pks(g), gkeys[g]);

        vtxos.resize(n_users);
        for (size_t i = 0; i < n_users; i++) {
            std::vector<secp256k1_pubkey> pks = { op.pk, users[i].pk };
            compute_vtxo_keys(agg.ctx, pks, ux(i), delay, vtxos[i]);
        }
    }

    size_t group_of(size_t user) const {
        for (size_t g = 0; g < groups.size(); g++)
            for (size_t u : groups[g].users) if (u == user) return g;
        throw std::runtime_error("korisnik nije ni u jednoj grupi");
    }
    size_t vout_of(size_t user) const {
        size_t g = group_of(user);
        for (size_t i = 0; i < groups[g].users.size(); i++)
            if (groups[g].users[i] == user) return i;
        throw std::runtime_error("vout");
    }

    // funding: operatorov UTXO → grupni outputi + ostatak
    void build_funding() {
        funding = Tx();
        funding.version = 2;
        TxIn in;
        std::memcpy(in.txid, fund_txid, 32);
        in.vout = fund_vout;
        in.sequence = 0xfffffffd;
        funding.vin.push_back(in);

        uint64_t need = 0;
        for (size_t g = 0; g < groups.size(); g++) {
            TxOut o;
            o.value = groups[g].total + group_fee;   // grupa nosi i fee za svoju tx
            o.script = p2tr_script(gkeys[g].output);
            funding.vout.push_back(o);
            need += o.value;
        }
        if (fund_amount <= need + funding_fee)
            throw std::runtime_error("funding iznos premalen: treba > " + std::to_string(need + funding_fee));

        TxOut ch;
        ch.value = fund_amount - need - funding_fee;
        ch.script = op_change_script;
        funding.vout.push_back(ch);
    }

    // grupna tx g: troši funding:g → po jedan VTXO za svakog u grupi
    void build_group_txs() {
        gtxs.clear();
        const std::string ftxid = funding.txid();
        for (size_t g = 0; g < groups.size(); g++) {
            Tx tx;
            tx.version = 2;
            TxIn in;
            if (!vtxo_txid_rev(ftxid, in.txid)) throw std::runtime_error("funding txid");
            in.vout = (uint32_t)g;
            in.sequence = 0xfffffffd;
            tx.vin.push_back(in);

            for (size_t u : groups[g].users) {
                TxOut o;
                o.value = amounts[u];              // TOČNO njegov balans
                o.script = p2tr_script(vtxos[u].output);
                tx.vout.push_back(o);
            }
            gtxs.push_back(tx);
        }
    }

    std::vector<TxOut> group_spent(size_t g) const {
        std::vector<TxOut> s(1);
        s[0].value = groups[g].total + group_fee;
        s[0].script = p2tr_script(gkeys[g].output);
        return s;
    }

    // potpis grupne tx: MuSig2(operator + svi u grupi), key-path bez tweaka
    void sign_group_tx(size_t g) {
        unsigned char sig[64];
        sign_musig_keypath(group_signers(g), group_pks(g), nullptr, gtxs[g], group_spent(g), 0, sig);
        gtxs[g].vin[0].witness.clear();
        gtxs[g].vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    }

    void sign_all_groups() { for (size_t g = 0; g < gtxs.size(); g++) sign_group_tx(g); }

    // funding potpisuje samo operator (njegov je novac)
    void sign_funding() {
        MusigAggregator agg;
        std::vector<TxOut> spent(1);
        spent[0].value = fund_amount;
        spent[0].script = p2tr_script(op_x.data());
        unsigned char sh[32];
        sighash_taproot(funding, spent, 0, 0x00, 0, nullptr, sh);
        unsigned char sig[64];
        if (!schnorr_sign(agg.ctx, op, sh, sig)) throw std::runtime_error("funding potpis");
        funding.vin[0].witness.clear();
        funding.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    }
};

} // namespace bec
