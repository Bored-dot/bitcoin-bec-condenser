// gate_matrix.hpp — matrica skriptova: jedan logički gate = 8 listova
//
// OVO JE PRAVI BitVM2 KOMAD. Prethodni sloj (src/bitvm.hpp) dokazivao je samo
// ekvivokaciju: "prover je isti bit otvorio dvaput". Ovdje se provjerava da
// prover nije lagao o IZRAČUNU: svaki gate nosi po jedan list za svaku od
// 2^3 = 8 kombinacija svojih triju žica, pa je svaka kombinacija — i ispravna
// i neispravna — posebno potrošiva.
//
// ZAŠTO 8 LISTOVA PO GATEU
//   gate ima dvije ulazne žice i jednu izlaznu: (va, vb, vc) ∈ {0,1}^3.
//   Za XOR/AND/OR je točno 4 kombinacije konzistentne s funkcijom, a 4 nisu.
//     · konzistentna kombinacija  → list potpisuje PROVER     (dokaz da je gate dobar)
//     · nekonzistentna kombinacija → list potpisuje OSPORAVATELJ (dokaz prijevare)
//   Isti witness format radi za oba puta; razlika je samo koji list i koji ključ.
//
// ZAŠTO NE TREBA OP_CAT
//   Ne provjeravamo "hash(va‖vb‖vc) == commitment", nego svaku žicu zasebno:
//   h(w, v) = SHA256(preimage(w, v)) i preimage se predaje u witnessu. Tri para
//   OP_SHA256 / OP_EQUALVERIFY, pa CHECKSIG. Ništa ne treba spajati na lancu.
//
// ŠTO OVO JOŠ NIJE
//   · nije bisection protokol — ovdje se osporava jedan gate po transakciji;
//     BitVM2 dodaje logaritamsko sužavanje da osporavanje cijelog izračuna
//     stane u O(log n) rundi umjesto O(n).
//   · nema garbled circuits — vrijednosti žica su proverove tvrdnje, a ne
//     izlaz garbled tablice. Zato prover i dalje mora biti uhvaćen u
//     nekonzistentnosti gatea, a ne u krivom izlazu garbled tablice.
#pragma once

#include "taproot.hpp"

namespace bec {

// ================================================================ gate model
enum GateOp : unsigned char { GATE_XOR = 0, GATE_AND = 1, GATE_OR = 2 };

inline bool gate_eval(GateOp op, bool a, bool b) {
    switch (op) {
        case GATE_XOR: return a != b;
        case GATE_AND: return a && b;
        default:       return a || b;
    }
}

inline const char* gate_name(GateOp op) {
    switch (op) {
        case GATE_XOR: return "XOR";
        case GATE_AND: return "AND";
        default:       return "OR";
    }
}

struct GateDef {
    uint32_t wa = 0;   // ulazna žica a
    uint32_t wb = 0;   // ulazna žica b
    uint32_t wc = 0;   // izlazna žica
    GateOp   op = GATE_XOR;
};

// ================================================================ žice
// preimage(w, v) = SHA256( 0x02 || w_le32 || v || salt )        — 38 bajtova
inline void wire_preimage(uint32_t wire, unsigned char val, const unsigned char salt[32],
                          unsigned char out[32]) {
    unsigned char buf[38];
    buf[0] = 0x02;
    for (int i = 0; i < 4; i++) buf[1 + i] = (unsigned char)(wire >> (8 * i));
    buf[5] = (unsigned char)(val & 1);
    std::memcpy(buf + 6, salt, 32);
    sha256(buf, sizeof(buf), out);
}

// commitment(w, v) = SHA256(preimage(w, v)) — ovo ide u skript
inline void wire_commitment(uint32_t wire, unsigned char val, const unsigned char salt[32],
                            unsigned char out[32]) {
    unsigned char pre[32];
    wire_preimage(wire, val, salt, pre);
    sha256(pre, 32, out);
}

// ================================================================ list gatea
//   OP_SHA256 <h(wc,vc)> OP_EQUALVERIFY
//   OP_SHA256 <h(wb,vb)> OP_EQUALVERIFY
//   OP_SHA256 <h(wa,va)> OP_EQUALVERIFY
//   <key> OP_CHECKSIG
//
// Redoslijed je obrnut od redoslijeda u witnessu jer Script troši s vrha
// stacka: witness [sig, pre_a, pre_b, pre_c, script, cb] ostavlja pre_c na vrhu.
inline std::vector<unsigned char> gate_leaf_script(const unsigned char h_a[32],
                                                   const unsigned char h_b[32],
                                                   const unsigned char h_c[32],
                                                   const unsigned char key_xonly[32]) {
    std::vector<unsigned char> s;
    s.push_back(OP_SHA256); push_data(s, h_c, 32); s.push_back(OP_EQUALVERIFY);
    s.push_back(OP_SHA256); push_data(s, h_b, 32); s.push_back(OP_EQUALVERIFY);
    s.push_back(OP_SHA256); push_data(s, h_a, 32); s.push_back(OP_EQUALVERIFY);
    push_data(s, key_xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

// kombinacija k ∈ [0,8): va = (k>>2)&1, vb = (k>>1)&1, vc = k&1
inline void combo_bits(unsigned k, unsigned char& va, unsigned char& vb, unsigned char& vc) {
    va = (unsigned char)((k >> 2) & 1);
    vb = (unsigned char)((k >> 1) & 1);
    vc = (unsigned char)(k & 1);
}

// ================================================================ 8-bitni zbrajač
// Ripple-carry, 8 bitova + 8 bitova → 8 bitova sume + carry out (9. bit).
// Bit 0:  s0 = a0 XOR b0 ,  c1 = a0 AND b0                       (2 gatea)
// Bit i:  t  = ai XOR bi ,  si = t XOR ci ,
//         u  = ai AND bi ,  v  = t AND ci ,  c(i+1) = u OR v      (5 gatea)
// Ukupno 2 + 7*5 = 37 gatea.
struct Adder {
    std::vector<GateDef> gates;
    std::vector<uint32_t> in_a, in_b, out_s, carry;
    size_t n_wires = 0;

    uint32_t new_wire() { return (uint32_t)n_wires++; }

    void build(size_t bits_in = 8) {
        gates.clear();
        n_wires = 0;
        in_a.clear(); in_b.clear(); out_s.clear(); carry.clear();

        for (size_t i = 0; i < bits_in; i++) in_a.push_back(new_wire());
        for (size_t i = 0; i < bits_in; i++) in_b.push_back(new_wire());
        for (size_t i = 0; i < bits_in; i++) out_s.push_back(new_wire());
        for (size_t i = 0; i <= bits_in; i++) carry.push_back(new_wire());

        // bit 0
        gates.push_back({in_a[0], in_b[0], out_s[0], GATE_XOR});
        gates.push_back({in_a[0], in_b[0], carry[1], GATE_AND});

        for (size_t i = 1; i < bits_in; i++) {
            uint32_t t = new_wire(), u = new_wire(), v = new_wire();
            gates.push_back({in_a[i], in_b[i], t, GATE_XOR});
            gates.push_back({t, carry[i], out_s[i], GATE_XOR});
            gates.push_back({in_a[i], in_b[i], u, GATE_AND});
            gates.push_back({t, carry[i], v, GATE_AND});
            gates.push_back({u, v, carry[i + 1], GATE_OR});
        }
    }

    // vrijednosti svih žica za konkretne ulaze a i b
    std::vector<unsigned char> eval(uint64_t a, uint64_t b) const {
        size_t bits_in = in_a.size();
        std::vector<unsigned char> w(n_wires, 0);
        for (size_t i = 0; i < bits_in; i++) {
            w[in_a[i]] = (unsigned char)((a >> i) & 1);
            w[in_b[i]] = (unsigned char)((b >> i) & 1);
        }
        for (const GateDef& g : gates)
            w[g.wc] = (unsigned char)gate_eval(g.op, w[g.wa] != 0, w[g.wb] != 0);
        return w;
    }

    uint64_t sum_of(uint64_t a, uint64_t b) const {
        size_t bits_in = in_a.size();
        uint64_t s = 0;
        for (size_t i = 0; i < bits_in; i++) s |= (uint64_t)((a + b) >> i & 1) << i;
        return s;
    }
};

// ================================================================ matrica
// Indeks lista: gate g, kombinacija k  →  g * 8 + k.
// Timeout (prover vraća bond) je zadnji list.
struct GateMatrix {
    const Adder* adder = nullptr;
    unsigned char salt[32];
    unsigned char prover_x[32];
    unsigned char challenger_x[32];

    size_t n_leaves() const { return adder->gates.size() * 8 + 1; }
    size_t timeout_index() const { return adder->gates.size() * 8; }
    static size_t leaf_index(size_t gate, unsigned k) { return gate * 8 + k; }

    // je li kombinacija k konzistentna s funkcijom gatea g
    bool combo_consistent(size_t g, unsigned k) const {
        unsigned char va, vb, vc;
        combo_bits(k, va, vb, vc);
        const GateDef& d = adder->gates[g];
        return (unsigned char)(gate_eval(d.op, va != 0, vb != 0) ? 1 : 0) == vc;
    }

    std::vector<unsigned char> leaf_script(size_t g, unsigned k) const {
        unsigned char va, vb, vc;
        combo_bits(k, va, vb, vc);
        const GateDef& d = adder->gates[g];
        unsigned char ha[32], hb[32], hc[32];
        wire_commitment(d.wa, va, salt, ha);
        wire_commitment(d.wb, vb, salt, hb);
        wire_commitment(d.wc, vc, salt, hc);
        const unsigned char* key = combo_consistent(g, k) ? prover_x : challenger_x;
        return gate_leaf_script(ha, hb, hc, key);
    }

    void build_scripts(std::vector<std::vector<unsigned char>>& scripts) const {
        scripts.clear();
        scripts.reserve(n_leaves());
        for (size_t g = 0; g < adder->gates.size(); g++)
            for (unsigned k = 0; k < 8; k++)
                scripts.push_back(leaf_script(g, k));
    }
};

} // namespace bec
