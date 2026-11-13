// taproot.hpp — BIP-341 taproot (skriptno stablo, taptweak, kontrolni blok, sighash)
//                  + BIP-340 tagged hash + serijalizacija transakcija
#pragma once

#include "crypto.hpp"
#include <stdexcept>

namespace bec {

// ================================================================ Merkle (state)
// Općenito Merkle stablo s dokazom — koristi se za "state root" nad listovima
// korisnika (xonly ključ + balans). Pravi SHA-256, Bitcoin pravilo dupliciranja.
struct MerkleTree {
    std::vector<std::vector<unsigned char>> levels; // levels[0] = svi listovi (32 B svaki)

    void build(const std::vector<unsigned char>& leaves) {
        levels.clear();
        if (leaves.empty()) return;
        if (leaves.size() % 32) throw std::runtime_error("MerkleTree: leaves nisu 32-bajtni");
        levels.push_back(leaves);
        while (levels.back().size() > 32) {
            const std::vector<unsigned char>& cur = levels.back();
            size_t n = cur.size() / 32;
            std::vector<unsigned char> next;
            next.reserve(((n + 1) / 2) * 32);
            for (size_t i = 0; i < n; i += 2) {
                const unsigned char* l = &cur[i * 32];
                const unsigned char* r = (i + 1 < n) ? &cur[(i + 1) * 32] : l;
                std::vector<unsigned char> buf(64);
                std::memcpy(buf.data(), l, 32);
                std::memcpy(buf.data() + 32, r, 32);
                unsigned char h[32];
                sha256(buf.data(), 64, h);
                next.insert(next.end(), h, h + 32);
            }
            levels.push_back(std::move(next));
        }
    }

    void root(unsigned char out[32]) const {
        if (levels.empty()) { std::memset(out, 0, 32); return; }
        std::memcpy(out, levels.back().data(), 32);
    }

    size_t depth() const { return levels.empty() ? 0 : levels.size() - 1; }

    std::vector<unsigned char> proof(size_t index) const {
        std::vector<unsigned char> p;
        for (size_t lvl = 0; lvl + 1 < levels.size(); lvl++) {
            const std::vector<unsigned char>& cur = levels[lvl];
            size_t n = cur.size() / 32;
            size_t sib = index ^ 1;
            if (sib >= n) sib = index;
            p.insert(p.end(), &cur[sib * 32], &cur[sib * 32] + 32);
            index /= 2;
        }
        return p;
    }
};

inline bool merkle_verify(const unsigned char leaf[32], const unsigned char* proof, size_t proof_len,
                          size_t index, const unsigned char expected_root[32]) {
    if (proof_len % 32) return false;
    unsigned char cur[32];
    std::memcpy(cur, leaf, 32);
    for (size_t off = 0; off < proof_len; off += 32) {
        std::vector<unsigned char> buf(64);
        if (index & 1) { std::memcpy(buf.data(), proof + off, 32); std::memcpy(buf.data() + 32, cur, 32); }
        else           { std::memcpy(buf.data(), cur, 32);          std::memcpy(buf.data() + 32, proof + off, 32); }
        unsigned char h[32];
        sha256(buf.data(), 64, h);
        std::memcpy(cur, h, 32);
        index /= 2;
    }
    return std::memcmp(cur, expected_root, 32) == 0;
}

// ================================================================ tapscript
enum : unsigned char {
    OP_DUP = 0x76, OP_DROP = 0x75, OP_EQUAL = 0x87, OP_EQUALVERIFY = 0x88,
    OP_SHA256 = 0xa8, OP_CHECKSIG = 0xac, OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_CHECKLOCKTIMEVERIFY = 0xb1, OP_1 = 0x51, OP_16 = 0x60
};

inline void push_data(std::vector<unsigned char>& s, const unsigned char* p, size_t n) {
    if (n == 0) { s.push_back(0x00); return; }
    if (n == 1) { s.push_back(0x01); s.push_back(p[0]); return; }
    if (n <= 75) { s.push_back((unsigned char)n); s.insert(s.end(), p, p + n); return; }
    if (n <= 255) { s.push_back(0x4c); s.push_back((unsigned char)n); s.insert(s.end(), p, p + n); return; }
    s.push_back(0x4d); s.push_back((unsigned char)n); s.push_back((unsigned char)(n >> 8));
    s.insert(s.end(), p, p + n);
}

// minimalni push cijelog broja za CSV (BIP-62 / ScriptNum)
inline void push_scriptnum(std::vector<unsigned char>& s, uint64_t v) {
    if (v == 0) { s.push_back(0x00); return; }
    if (v >= 1 && v <= 16) { s.push_back((unsigned char)(OP_1 + v - 1)); return; }
    std::vector<unsigned char> be;
    while (v) { be.push_back((unsigned char)(v & 0xff)); v >>= 8; }
    while (be.size() > 1 && be.back() == 0 && !(be[be.size() - 2] & 0x80)) be.pop_back();
    if (be.back() & 0x80) be.push_back(0x00); // sign bit
    push_data(s, be.data(), be.size());
}

// Korisnički "unilateral exit" list:
//   <state_root> OP_DROP <delay> OP_CSV OP_DROP <user_xonly> OP_CHECKSIG
// State root je ubačen u svaki list, pa taptweak (i time output key) obavezno
// komitira cijelo stanje L2-a.
inline std::vector<unsigned char> exit_leaf_script(const unsigned char state_root[32],
                                                  const unsigned char user_xonly[32],
                                                  uint32_t delay_blocks) {
    std::vector<unsigned char> s;
    push_data(s, state_root, 32);          // commit na stanje
    s.push_back(OP_DROP);
    push_scriptnum(s, delay_blocks);       // CSV delay
    s.push_back(OP_CHECKSEQUENCEVERIFY);
    s.push_back(OP_DROP);
    push_data(s, user_xonly, 32);          // ključ korisnika
    s.push_back(OP_CHECKSIG);
    return s;
}

// ================================================================ BIP-341 skriptno stablo
inline constexpr unsigned char TAPROOT_LEAF_TAPSCRIPT = 0xc0;

inline void tapleaf_hash(const std::vector<unsigned char>& script, unsigned char out[32]) {
    std::vector<unsigned char> buf;
    buf.push_back(TAPROOT_LEAF_TAPSCRIPT);
    put_compactsize(buf, script.size());
    buf.insert(buf.end(), script.begin(), script.end());
    tagged_hash("TapLeaf", buf.data(), buf.size(), out);
}

inline void tapbranch_hash(const unsigned char a[32], const unsigned char b[32], unsigned char out[32]) {
    std::vector<unsigned char> buf(64);
    if (std::memcmp(a, b, 32) < 0) { std::memcpy(buf.data(), a, 32); std::memcpy(buf.data() + 32, b, 32); }
    else                           { std::memcpy(buf.data(), b, 32); std::memcpy(buf.data() + 32, a, 32); }
    tagged_hash("TapBranch", buf.data(), 64, out);
}

// Balansirano stablo: parovi se spajaju odozdo prema gore (kao Bitcoin Core).
struct TapScriptTree {
    std::vector<std::vector<unsigned char>> levels; // razine hash-eva listova
    std::vector<std::vector<unsigned char>> leaf_scripts;

    void build(const std::vector<std::vector<unsigned char>>& scripts) {
        leaf_scripts = scripts;
        levels.clear();
        std::vector<unsigned char> base;
        base.reserve(scripts.size() * 32);
        for (const std::vector<unsigned char>& sc : scripts) {
            unsigned char h[32];
            tapleaf_hash(sc, h);
            base.insert(base.end(), h, h + 32);
        }
        levels.push_back(base);
        while (levels.back().size() > 32) {
            const std::vector<unsigned char>& cur = levels.back();
            size_t n = cur.size() / 32;
            std::vector<unsigned char> next;
            for (size_t i = 0; i < n; i += 2) {
                unsigned char h[32];
                if (i + 1 < n) tapbranch_hash(&cur[i * 32], &cur[(i + 1) * 32], h);
                else           std::memcpy(h, &cur[i * 32], 32);
                next.insert(next.end(), h, h + 32);
            }
            levels.push_back(std::move(next));
        }
    }

    void merkle_root(unsigned char out[32]) const {
        if (levels.empty()) { std::memset(out, 0, 32); return; }
        std::memcpy(out, levels.back().data(), 32);
    }

    size_t depth() const { return levels.empty() ? 0 : levels.size() - 1; }

    // put od lista do korijena (bottom-up hash-evi braće)
    std::vector<unsigned char> merkle_path(size_t index) const {
        std::vector<unsigned char> p;
        for (size_t lvl = 0; lvl + 1 < levels.size(); lvl++) {
            const std::vector<unsigned char>& cur = levels[lvl];
            size_t n = cur.size() / 32;
            size_t sib = index ^ 1;
            // BIP-341: ako je zadnji čvor neparan, on se PROMOVIRA na razinu
            // iznad — nema brata, pa nema ni elementa u putu. Dodavanje
            // vlastitog hasha ovdje proizvede kontrolni blok pogrešne duljine
            // i node ga odbija s "Witness program hash mismatch".
            if (sib < n)
                p.insert(p.end(), &cur[sib * 32], &cur[sib * 32] + 32);
            index /= 2;
        }
        return p;
    }
};

// ================================================================ taptweak + kontrolni blok
struct TaprootCommitment {
    unsigned char internal[32];  // xonly internal key
    unsigned char tweak[32];     // tagged_hash("TapTweak", internal||root)
    unsigned char output[32];    // xonly output key
    int output_parity = 0;
    bool has_scripts = false;
};

inline bool tap_tweak(const unsigned char internal[32], const unsigned char* script_root_or_null,
                      TaprootCommitment& c) {
    std::memcpy(c.internal, internal, 32);
    std::vector<unsigned char> buf;
    buf.insert(buf.end(), internal, internal + 32);
    c.has_scripts = (script_root_or_null != nullptr);
    if (c.has_scripts) buf.insert(buf.end(), script_root_or_null, script_root_or_null + 32);
    tagged_hash("TapTweak", buf.data(), buf.size(), c.tweak);
    return true;
}

// kontrolni blok: [0xc0 | parity] || internal_key || put do korijena
inline std::vector<unsigned char> control_block(const TaprootCommitment& c, int parity,
                                               const std::vector<unsigned char>& merkle_path) {
    std::vector<unsigned char> cb;
    cb.push_back((unsigned char)(TAPROOT_LEAF_TAPSCRIPT | (parity & 1)));
    cb.insert(cb.end(), c.internal, c.internal + 32);
    cb.insert(cb.end(), merkle_path.begin(), merkle_path.end());
    return cb;
}

// ================================================================ transakcije
struct TxIn {
    unsigned char txid[32]; // interno (little-endian) — reverse od prikazanog hexa
    uint32_t vout = 0;
    uint32_t sequence = 0xfffffffd;
    std::vector<std::vector<unsigned char>> witness;
};

struct TxOut {
    uint64_t value = 0;
    std::vector<unsigned char> script;
};

struct Tx {
    uint32_t version = 2;
    uint32_t locktime = 0;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;

    std::vector<unsigned char> serialize(bool with_witness) const {
        std::vector<unsigned char> s;
        put_u32le(s, version);
        bool use_wit = with_witness;
        if (use_wit) {
            bool any = false;
            for (const TxIn& in : vin) if (!in.witness.empty()) any = true;
            if (!any) use_wit = false;
        }
        if (use_wit) { s.push_back(0x00); s.push_back(0x01); }
        put_compactsize(s, vin.size());
        for (const TxIn& in : vin) {
            s.insert(s.end(), in.txid, in.txid + 32);
            put_u32le(s, in.vout);
            put_compactsize(s, 0); // prazan scriptSig
            put_u32le(s, in.sequence);
        }
        put_compactsize(s, vout.size());
        for (const TxOut& o : vout) {
            put_u64le(s, o.value);
            put_compactsize(s, o.script.size());
            s.insert(s.end(), o.script.begin(), o.script.end());
        }
        if (use_wit) {
            for (const TxIn& in : vin) {
                put_compactsize(s, in.witness.size());
                for (const std::vector<unsigned char>& item : in.witness) {
                    put_compactsize(s, item.size());
                    s.insert(s.end(), item.begin(), item.end());
                }
            }
        }
        put_u32le(s, locktime);
        return s;
    }

    // txid = double SHA-256 nad serijalizacijom bez witnessa, prikazano obrnuto
    std::string txid() const {
        std::vector<unsigned char> raw = serialize(false);
        unsigned char h1[32], h2[32];
        sha256(raw.data(), raw.size(), h1);
        sha256(h1, 32, h2);
        unsigned char rev[32];
        for (int i = 0; i < 32; i++) rev[i] = h2[31 - i];
        return to_hex(rev, 32);
    }
};

inline std::vector<unsigned char> p2tr_script(const unsigned char output_key[32]) {
    std::vector<unsigned char> s;
    s.push_back(OP_1);
    s.push_back(0x20);
    s.insert(s.end(), output_key, output_key + 32);
    return s;
}

// ================================================================ BIP-341 sighash
inline void sha256_vec(const std::vector<unsigned char>& v, unsigned char out[32]) {
    sha256(v.data(), v.size(), out);
}

inline void sighash_taproot(const Tx& tx,
                            const std::vector<TxOut>& spent_outputs,
                            size_t input_index,
                            unsigned char hash_type,               // 0x00 = SIGHASH_DEFAULT
                            int ext_flag,                          // 0 = key path, 1 = script path
                            const unsigned char* tapleaf_hash_,    // nullptr za key path
                            unsigned char out[32]) {
    const uint8_t ANYONECANPAY = 0x80, NONE = 0x02, SINGLE = 0x03;

    std::vector<unsigned char> ss;
    ss.push_back(0x00);              // epoch
    ss.push_back(hash_type);
    put_u32le(ss, tx.version);
    put_u32le(ss, tx.locktime);

    if (!(hash_type & ANYONECANPAY)) {
        std::vector<unsigned char> outpoints, amounts, spks, seqs;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            outpoints.insert(outpoints.end(), tx.vin[i].txid, tx.vin[i].txid + 32);
            put_u32le(outpoints, tx.vin[i].vout);
            put_u64le(amounts, spent_outputs[i].value);
            put_compactsize(spks, spent_outputs[i].script.size());
            spks.insert(spks.end(), spent_outputs[i].script.begin(), spent_outputs[i].script.end());
            put_u32le(seqs, tx.vin[i].sequence);
        }
        unsigned char h[32];
        sha256_vec(outpoints, h); put_bytes(ss, h, 32);
        sha256_vec(amounts, h);   put_bytes(ss, h, 32);
        sha256_vec(spks, h);      put_bytes(ss, h, 32);
        sha256_vec(seqs, h);      put_bytes(ss, h, 32);
    }

    if (!(hash_type & (SINGLE | NONE))) {
        std::vector<unsigned char> outs;
        for (const TxOut& o : tx.vout) {
            put_u64le(outs, o.value);
            put_compactsize(outs, o.script.size());
            outs.insert(outs.end(), o.script.begin(), o.script.end());
        }
        unsigned char h[32];
        sha256_vec(outs, h);
        put_bytes(ss, h, 32);
    }

    unsigned char spend_type = (unsigned char)((ext_flag * 2) + 0); // annex = 0
    ss.push_back(spend_type);

    if (hash_type & ANYONECANPAY) {
        ss.insert(ss.end(), tx.vin[input_index].txid, tx.vin[input_index].txid + 32);
        put_u32le(ss, tx.vin[input_index].vout);
        put_u64le(ss, spent_outputs[input_index].value);
        put_compactsize(ss, spent_outputs[input_index].script.size());
        ss.insert(ss.end(), spent_outputs[input_index].script.begin(),
                  spent_outputs[input_index].script.end());
        put_u32le(ss, tx.vin[input_index].sequence);
    } else {
        put_u32le(ss, (uint32_t)input_index);
    }

    if (hash_type & SINGLE) throw std::runtime_error("SIGHASH_SINGLE nije podržan");

    if (ext_flag == 1) {
        if (!tapleaf_hash_) throw std::runtime_error("script path traži tapleaf hash");
        put_bytes(ss, tapleaf_hash_, 32);
        ss.push_back(0x00);          // key_version
        put_u32le(ss, 0xffffffffu);  // codesep_pos
    }

    tagged_hash("TapSighash", ss.data(), ss.size(), out);
}

} // namespace bec
