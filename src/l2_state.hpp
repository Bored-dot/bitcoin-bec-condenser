// l2_state.hpp — L2 stanje: vlasništvo, prijelazi i dokaziv lanac
//
// ŠTO OVAJ SLOJ DODAJE
// VTXO settlement (vtxo.hpp) rješava "koliko kome pripada na lancu". Ne rješava
// "kako vrijednost prelazi od A do B bez on-chain transakcije". Ovo je taj sloj.
//
//   transfer: A → B je PRE-POTPISANA transakcija koja se NE broadcasta.
//             B postaje vlasnik off-chain. A više ne može trošiti taj VTXO.
//   exit:     A uvijek može izaći sam nakon CSV-a — ali samo dok nije prenio.
//   conflict: ako A pokuša prenijeti i B-u i C-u, obje transakcije troše isti
//             outpoint. Lanac ne može potvrditi obje. Konflikt rješava
//             konsenzus, ne operatorova riječ.
//
// DOKAZIV LANAC
// Svaki prijelaz ima digest koji uključuje prethodni digest. Stranke mogu
// dokazati povijest, a operator je ne može tiho prepisati.
//
// KLJUČNA VREMENSKA ASIMETRIJA
//   transfer tx: key-path, BEZ CSV-a → valjan odmah, potvrđuje se u 1 bloku
//   exit tx:     script-path, CSV D   → valjan tek D blokova nakon nastanka VTXO-a
// Zato operator (ili primatelj) ima D blokova prednosti da objavi transfer
// prije nego A uopće dobije pravo na exit. To je cijeli mehanizam zaštite.
//
// ŠTO OVO NE RJEŠAVA
//   · mrežni sloj (dvije runde potpisa preko žice)
//   · perzistenciju (stanje je datoteka, ne baza s WAL-om)
//   · HSM / nonce management
//   · watchtower kao servis — netko mora biti živ unutar CSV prozora
#pragma once

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"
#include "vtxo.hpp"

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <stdexcept>
#include <algorithm>

namespace bec {

// ================================================================ zapis VTXO-a
struct L2Vtxo {
    std::string id;                    // "txid:vout"
    unsigned char txid[32]{};          // interno (little-endian)
    uint32_t vout = 0;
    uint64_t amount = 0;
    unsigned char output[32]{};        // tweakana output točka
    unsigned char internal[32]{};      // MuSig2(operator, vlasnik)
    int parity = 0;
    std::vector<unsigned char> leaf;   // exit skript vlasnika
    std::vector<unsigned char> owner_sk;
    unsigned char owner_x[32]{};
    bool spent = false;
};

// ================================================================ prijelaz
struct L2Transition {
    std::string kind;      // "genesis" | "transfer"
    std::string from;      // id VTXO-a koji se troši ("-" za genesis)
    std::string to;        // id novog VTXO-a ("-" ako nema)
    uint64_t amount = 0;
    std::string txid;
    unsigned char digest[32]{};
};

// ================================================================ stanje
struct L2State {
    uint32_t delay = 144;
    std::string hrp = "bcrt";
    std::vector<unsigned char> op_sk;
    unsigned char op_x[32]{};
    std::vector<L2Vtxo> vtxos;
    std::vector<L2Transition> chain;

    const L2Vtxo* find(const std::string& id) const {
        for (const L2Vtxo& v : vtxos) if (v.id == id) return &v;
        return nullptr;
    }
    L2Vtxo* find_mut(const std::string& id) {
        for (L2Vtxo& v : vtxos) if (v.id == id) return &v;
        return nullptr;
    }

    void save(const std::string& path) const {
        std::ofstream o(path);
        if (!o.good()) throw std::runtime_error("ne mogu pisati " + path);
        o << "version=1\n"
          << "delay=" << delay << "\n"
          << "hrp=" << hrp << "\n"
          << "op_sk=" << to_hex(op_sk) << "\n"
          << "op_x=" << to_hex(op_x, 32) << "\n"
          << "n_vtxos=" << vtxos.size() << "\n";
        for (size_t i = 0; i < vtxos.size(); i++) {
            const L2Vtxo& v = vtxos[i];
            const std::string p = "v" + std::to_string(i) + "_";
            o << p << "id=" << v.id << "\n"
              << p << "txid=" << to_hex(v.txid, 32) << "\n"
              << p << "vout=" << v.vout << "\n"
              << p << "amount=" << v.amount << "\n"
              << p << "output=" << to_hex(v.output, 32) << "\n"
              << p << "internal=" << to_hex(v.internal, 32) << "\n"
              << p << "parity=" << v.parity << "\n"
              << p << "leaf=" << to_hex(v.leaf) << "\n"
              << p << "owner_sk=" << to_hex(v.owner_sk) << "\n"
              << p << "owner_x=" << to_hex(v.owner_x, 32) << "\n"
              << p << "spent=" << (v.spent ? 1 : 0) << "\n";
        }
        o << "n_chain=" << chain.size() << "\n";
        for (size_t i = 0; i < chain.size(); i++) {
            const L2Transition& t = chain[i];
            const std::string p = "c" + std::to_string(i) + "_";
            o << p << "kind=" << t.kind << "\n"
              << p << "from=" << t.from << "\n"
              << p << "to=" << t.to << "\n"
              << p << "amount=" << t.amount << "\n"
              << p << "txid=" << t.txid << "\n"
              << p << "digest=" << to_hex(t.digest, 32) << "\n";
        }
    }

    static L2State load(const std::string& path) {
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
        auto get = [&](const std::string& k) -> std::string {
            auto it = m.find(k);
            if (it == m.end()) throw std::runtime_error("state: nedostaje '" + k + "'");
            return it->second;
        };

        L2State s;
        s.delay = (uint32_t)std::stoul(get("delay"));
        s.hrp   = get("hrp");
        if (!from_hex(get("op_sk"), s.op_sk) || s.op_sk.size() != 32)
            throw std::runtime_error("state: op_sk");
        if (!from_hex32(get("op_x"), s.op_x)) throw std::runtime_error("state: op_x");

        const size_t nv = (size_t)std::stoul(get("n_vtxos"));
        s.vtxos.resize(nv);
        for (size_t i = 0; i < nv; i++) {
            const std::string p = "v" + std::to_string(i) + "_";
            L2Vtxo& v = s.vtxos[i];
            v.id = get(p + "id");
            if (!from_hex32(get(p + "txid"), v.txid)) throw std::runtime_error("state: txid");
            v.vout   = (uint32_t)std::stoul(get(p + "vout"));
            v.amount = std::stoull(get(p + "amount"));
            if (!from_hex32(get(p + "output"), v.output)) throw std::runtime_error("state: output");
            if (!from_hex32(get(p + "internal"), v.internal)) throw std::runtime_error("state: internal");
            v.parity = std::stoi(get(p + "parity"));
            if (!from_hex(get(p + "leaf"), v.leaf)) throw std::runtime_error("state: leaf");
            if (!from_hex(get(p + "owner_sk"), v.owner_sk)) throw std::runtime_error("state: owner_sk");
            if (!from_hex32(get(p + "owner_x"), v.owner_x)) throw std::runtime_error("state: owner_x");
            v.spent  = std::stoi(get(p + "spent")) != 0;
        }

        const size_t nc = (size_t)std::stoul(get("n_chain"));
        s.chain.resize(nc);
        for (size_t i = 0; i < nc; i++) {
            const std::string p = "c" + std::to_string(i) + "_";
            L2Transition& t = s.chain[i];
            t.kind   = get(p + "kind");
            t.from   = get(p + "from");
            t.to     = get(p + "to");
            t.amount = std::stoull(get(p + "amount"));
            t.txid   = get(p + "txid");
            if (!from_hex32(get(p + "digest"), t.digest)) throw std::runtime_error("state: digest");
        }
        return s;
    }
};

// ================================================================ dokaziv lanac
inline void chain_digest(const unsigned char prev[32], const std::string& kind,
                         const std::string& from, const std::string& to,
                         uint64_t amount, const std::string& txid,
                         unsigned char out[32]) {
    static const char tag[] = "BEC/L2/v1";
    std::vector<unsigned char> b;
    b.insert(b.end(), tag, tag + sizeof(tag) - 1);
    b.insert(b.end(), prev, prev + 32);
    auto put_str = [&](const std::string& s) {
        put_compactsize(b, s.size());
        b.insert(b.end(), s.begin(), s.end());
    };
    put_str(kind);
    put_str(from);
    put_str(to);
    put_u64le(b, amount);
    put_str(txid);
    sha256(b.data(), b.size(), out);
}

inline void append_transition(L2State& s, const std::string& kind, const std::string& from,
                              const std::string& to, uint64_t amount, const std::string& txid) {
    unsigned char prev[32] = {0};
    if (!s.chain.empty()) std::memcpy(prev, s.chain.back().digest, 32);
    L2Transition t;
    t.kind = kind; t.from = from; t.to = to; t.amount = amount; t.txid = txid;
    chain_digest(prev, kind, from, to, amount, txid, t.digest);
    s.chain.push_back(t);
}

// ================================================================ revizija
struct AuditResult {
    bool chain_ok = true;
    bool ownership_ok = true;
    size_t n_vtxos = 0, n_spent = 0, n_unspent = 0;
    std::string err;
    unsigned char tip[32]{};
    uint64_t total_unspent = 0;
};

inline AuditResult audit(const L2State& s) {
    AuditResult r;
    r.n_vtxos = s.vtxos.size();

    // 1. lanac: svaki digest mora odgovarati prethodnom
    unsigned char prev[32] = {0};
    for (size_t i = 0; i < s.chain.size(); i++) {
        const L2Transition& t = s.chain[i];
        unsigned char want[32];
        chain_digest(prev, t.kind, t.from, t.to, t.amount, t.txid, want);
        if (std::memcmp(want, t.digest, 32) != 0) {
            r.chain_ok = false;
            r.err = "digest prijelaza " + std::to_string(i) + " ne odgovara";
            break;
        }
        std::memcpy(prev, t.digest, 32);
    }
    std::memcpy(r.tip, prev, 32);

    // 2. vlasništvo: svaki "from" mora postojati i biti potrošen točno jednom
    std::map<std::string, int> spent_count;
    for (const L2Transition& t : s.chain)
        if (t.kind == "transfer") spent_count[t.from]++;

    for (const auto& kvp : spent_count) {
        const L2Vtxo* v = s.find(kvp.first);
        if (!v) { r.ownership_ok = false; r.err = "prijelaz troši nepostojeći VTXO " + kvp.first; break; }
        if (kvp.second > 1) { r.ownership_ok = false; r.err = "VTXO potrošen dvaput: " + kvp.first; break; }
        if (!v->spent) { r.ownership_ok = false; r.err = "VTXO nije označen kao potrošen: " + kvp.first; break; }
    }

    for (const L2Vtxo& v : s.vtxos) {
        if (v.spent) r.n_spent++;
        else { r.n_unspent++; r.total_unspent += v.amount; }
    }
    return r;
}

} // namespace bec
