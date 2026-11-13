// matrix_main.cpp — CLI za matricu skriptova (8-bitni zbrajač kao BitVM2 gate matrica)
//
//   build      izgradi matricu: 37 gatea × 8 listova + timeout = 297 listova
//   proof-ok   prover dokazuje da je gate konzistentan (konzistentna kombinacija)
//   proof-bad  osporavatelj dokazuje prijevaru (nekonzistentna kombinacija)
//   timeout    prover vraća bond nakon CSV-a
//
// Build: test/build.sh ga gradi kao `bec-matrix`.

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"
#include "bitvm.hpp"
#include "gate_matrix.hpp"

#include <iostream>
#include <fstream>
#include <map>

using namespace bec;

static void die(const std::string& m) { std::cerr << "[ERROR] " << m << "\n"; std::exit(1); }

static std::string arg_value(int argc, char** argv, const std::string& n, const std::string& d = "") {
    for (int i = 1; i + 1 < argc; i++) if (n == argv[i]) return argv[i + 1];
    return d;
}
static bool arg_present(int argc, char** argv, const std::string& n) {
    for (int i = 1; i < argc; i++) if (n == argv[i]) return true;
    return false;
}

static std::map<std::string, std::string> read_kv(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) die("ne mogu otvoriti " + path);
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
static std::string kv(const std::map<std::string, std::string>& m, const std::string& k) {
    auto it = m.find(k);
    if (it == m.end()) die("nedostaje polje '" + k + "'");
    return it->second;
}
static bool txid_rev(const std::string& hex, unsigned char out[32]) {
    unsigned char t[32];
    if (!from_hex32(hex, t)) return false;
    for (int i = 0; i < 32; i++) out[i] = t[31 - i];
    return true;
}

// ================================================================ build
static int cmd_build(int argc, char** argv) {
    const size_t bits = (size_t)std::stoul(arg_value(argc, argv, "--bits", "8"));
    const uint32_t csvb = (uint32_t)std::stoul(arg_value(argc, argv, "--csv", "96"));
    const std::string hrp = arg_value(argc, argv, "--hrp", "bcrt");
    const std::string out_path = arg_value(argc, argv, "--out", "matrix.txt");
    if (bits < 1 || bits > 16) die("--bits mora biti 1..16");

    MusigAggregator agg;
    unsigned char psk[32], csk[32], salt[32];
    if (!from_hex32(arg_value(argc, argv, "--prover-key"), psk)) die("--prover-key <64 hex>");
    if (!from_hex32(arg_value(argc, argv, "--challenger-key"), csk)) die("--challenger-key <64 hex>");
    const std::string salt_hex = arg_value(argc, argv, "--salt");
    if (salt_hex.empty()) { Rng r; r.fill(salt, 32); }
    else if (!from_hex32(salt_hex, salt)) die("--salt <64 hex>");

    Signer prover, challenger;
    if (!MusigAggregator::make_signer(agg.ctx, psk, prover)) die("neispravan --prover-key");
    if (!MusigAggregator::make_signer(agg.ctx, csk, challenger)) die("neispravan --challenger-key");
    secure_zero(psk, 32);
    secure_zero(csk, 32);

    Adder adder;
    adder.build(bits);

    GateMatrix m;
    m.adder = &adder;
    std::memcpy(m.salt, salt, 32);
    secp256k1_xonly_pubkey_serialize(agg.ctx, m.prover_x, &prover.xonly);
    secp256k1_xonly_pubkey_serialize(agg.ctx, m.challenger_x, &challenger.xonly);

    std::vector<std::vector<unsigned char>> scripts;
    m.build_scripts(scripts);
    scripts.push_back(bond_timeout_script(m.prover_x, csvb));

    TapScriptTree tree;
    tree.build(scripts);
    unsigned char root[32];
    tree.merkle_root(root);

    unsigned char internal[32];
    std::memcpy(internal, nums_internal_key(), 32);
    TaprootCommitment c;
    tap_tweak(internal, root, c);
    secp256k1_pubkey tw;
    secp256k1_xonly_pubkey nx;
    if (!secp256k1_xonly_pubkey_parse(agg.ctx, &nx, internal)) die("NUMS parse");
    if (!secp256k1_xonly_pubkey_tweak_add(agg.ctx, &tw, &nx, c.tweak)) die("taptweak");
    unsigned char s33[33]; size_t l33 = 33;
    secp256k1_ec_pubkey_serialize(agg.ctx, s33, &l33, &tw, SECP256K1_EC_COMPRESSED);
    int parity = (s33[0] == 0x03) ? 1 : 0;
    std::memcpy(c.output, s33 + 1, 32);

    std::string addr;
    if (!taproot_address(hrp, c.output, addr)) die("bech32m");

    // koliko listova pripada proveru, a koliko osporavatelju
    size_t n_prover = 0, n_chal = 0;
    for (size_t g = 0; g < adder.gates.size(); g++)
        for (unsigned k = 0; k < 8; k++) (m.combo_consistent(g, k) ? n_prover : n_chal)++;

    std::cout << "\n========== BITVM2 GATE MATRIX — " << bits << "-bitni zbrajač ==========\n";
    std::cout << "Žica (commitmenta)                   : " << adder.n_wires << "\n";
    std::cout << "Gatea                                : " << adder.gates.size() << "\n";
    std::cout << "Listova ukupno (8 po gateu + timeout): " << scripts.size() << "\n";
    std::cout << "  · proverovi (konzistentni)         : " << n_prover << "\n";
    std::cout << "  · osporavateljevi (nekonzistentni) : " << n_chal << "\n";
    std::cout << "Dubina skriptnog stabla              : " << tree.depth()
              << "  (kontrolni blok " << 33 + tree.depth() * 32 << " B)\n";
    std::cout << "Timeout CSV (blokovi)                : " << csvb << "\n";
    std::cout << "Internal key                         : NUMS (key-path nemoguć)\n";
    std::cout << "Taproot output key                   : " << to_hex(c.output, 32) << "\n";
    std::cout << "bech32m adresa (" << hrp << ")              : " << addr << "\n";
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << "Svaki list provjerava tri žice zasebno (bez OP_CAT):\n";
    std::cout << "  OP_SHA256 <h(wc,vc)> EQUALVERIFY  ·  <h(wb,vb)>  ·  <h(wa,va)>  → CHECKSIG\n";
    std::cout << "Provjera ispravnosti zbrajanja (npr. 200+100=300 > 255):\n";
    std::cout << "  zbrajač daje 8 bitova sume + carry out, pa 300 → 0x2C uz carry=1\n";
    std::cout << "=================================================================\n";

    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << "bits=" << bits << "\n"
        << "csv=" << csvb << "\n"
        << "hrp=" << hrp << "\n"
        << "n_gates=" << adder.gates.size() << "\n"
        << "n_leaves=" << scripts.size() << "\n"
        << "n_wires=" << adder.n_wires << "\n"
        << "internal=" << to_hex(internal, 32) << "\n"
        << "tweak=" << to_hex(c.tweak, 32) << "\n"
        << "output=" << to_hex(c.output, 32) << "\n"
        << "parity=" << parity << "\n"
        << "script_root=" << to_hex(root, 32) << "\n"
        << "address=" << addr << "\n"
        << "prover=" << to_hex(m.prover_x, 32) << "\n"
        << "challenger=" << to_hex(m.challenger_x, 32) << "\n"
        << "salt=" << to_hex(salt, 32) << "\n";
    out.close();
    std::cout << "\n[matrix] spremljeno u " << out_path << "\n";
    return 0;
}

// ================================================================ zajedničko za proof
struct Ctx {
    std::map<std::string, std::string> m;
    Adder adder;
    GateMatrix mx;
    TapScriptTree tree;
    std::vector<std::vector<unsigned char>> scripts;
    Tx tx;
    std::vector<TxOut> spent;
    unsigned char outkey[32];
    unsigned char internal[32];
    int parity = 0;
};

static Ctx load(int argc, char** argv) {
    Ctx x;
    x.m = read_kv(arg_value(argc, argv, "--matrix", "matrix.txt"));
    if (!from_hex32(kv(x.m, "output"), x.outkey)) die("output key nije 32 B");
    if (!from_hex32(kv(x.m, "internal"), x.internal)) die("internal key");
    x.parity = std::stoi(kv(x.m, "parity"));

    x.adder.build((size_t)std::stoul(kv(x.m, "bits")));
    x.mx.adder = &x.adder;
    if (!from_hex32(kv(x.m, "salt"), x.mx.salt)) die("salt");
    if (!from_hex32(kv(x.m, "prover"), x.mx.prover_x)) die("prover");
    if (!from_hex32(kv(x.m, "challenger"), x.mx.challenger_x)) die("challenger");

    x.mx.build_scripts(x.scripts);
    x.scripts.push_back(bond_timeout_script(x.mx.prover_x, (uint32_t)std::stoul(kv(x.m, "csv"))));
    x.tree.build(x.scripts);

    unsigned char rc[32], claimed[32];
    x.tree.merkle_root(rc);
    if (!from_hex32(kv(x.m, "script_root"), claimed)) die("script_root");
    if (std::memcmp(rc, claimed, 32) != 0) die("rekonstruirana matrica ne odgovara commitmentu");

    const std::string txid = arg_value(argc, argv, "--txid");
    if (txid.empty()) die("--txid je obavezan");
    const uint32_t vout = (uint32_t)std::stoul(arg_value(argc, argv, "--vout", "0"));
    const uint64_t amount = std::stoull(arg_value(argc, argv, "--amount", "0"));
    const uint64_t fee = std::stoull(arg_value(argc, argv, "--fee", "2000"));
    const std::string dest = arg_value(argc, argv, "--dest-script");
    if (dest.empty()) die("--dest-script je obavezan");
    if (amount == 0) die("--amount (sats) je obavezan");

    TxIn in;
    if (!txid_rev(txid, in.txid)) die("neispravan --txid");
    in.vout = vout;
    in.sequence = (uint32_t)std::stoul(arg_value(argc, argv, "--sequence", "1"));
    x.tx.version = 2;
    x.tx.vin.push_back(in);

    TxOut s; s.value = amount; s.script = p2tr_script(x.outkey);
    x.spent.push_back(s);

    TxOut o; o.value = amount - fee;
    if (!from_hex(dest, o.script)) die("neispravan --dest-script");
    x.tx.vout.push_back(o);
    return x;
}

// zajednička izgradnja dokaza; bad=false → proverov put, bad=true → osporavateljev
static int make_gate_proof(int argc, char** argv, bool bad) {
    Ctx x = load(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", bad ? "bad.hex" : "ok.hex");
    const size_t gate = (size_t)std::stoul(arg_value(argc, argv, "--gate", "0"));
    const uint64_t a = std::stoull(arg_value(argc, argv, "--a", "0"));
    const uint64_t b = std::stoull(arg_value(argc, argv, "--b", "0"));
    if (gate >= x.adder.gates.size()) die("--gate izvan granica");

    MusigAggregator agg;
    const GateDef& d = x.adder.gates[gate];

    // prave vrijednosti svih žica za te ulaze
    std::vector<unsigned char> w = x.adder.eval(a, b);
    unsigned char va = w[d.wa], vb = w[d.wb];
    unsigned char vc_true = (unsigned char)(gate_eval(d.op, va != 0, vb != 0) ? 1 : 0);
    unsigned char vc = bad ? (unsigned char)(vc_true ^ 1) : vc_true;

    // kombinacija k koja odgovara otkrivenim vrijednostima
    unsigned k = (unsigned)((va << 2) | (vb << 1) | vc);
    const size_t idx = GateMatrix::leaf_index(gate, k);

    bool consistent = x.mx.combo_consistent(gate, k);
    if (bad && consistent) die("unutarnja greška: 'bad' dokaz je ispao konzistentan");
    if (!bad && !consistent) die("unutarnja greška: 'ok' dokaz je ispao nekonzistentan");

    // preimagei otkrivenih vrijednosti
    unsigned char pa[32], pb[32], pc[32];
    wire_preimage(d.wa, va, x.mx.salt, pa);
    wire_preimage(d.wb, vb, x.mx.salt, pb);
    wire_preimage(d.wc, vc, x.mx.salt, pc);

    unsigned char flipped[32];
    if (arg_present(argc, argv, "--wrong-preimage")) {
        // namjerno pokvaren dokaz: preimage koji ne hashira na commitment u skriptu
        wire_preimage(d.wc, (unsigned char)(vc ^ 1), x.mx.salt, flipped);
        std::memcpy(pc, flipped, 32);
    }

    unsigned char leaf_hash[32];
    tapleaf_hash(x.scripts[idx], leaf_hash);
    unsigned char sighash[32];
    sighash_taproot(x.tx, x.spent, 0, 0x00, 1, leaf_hash, sighash);

    // ključ: prover za konzistentan list, osporavatelj za nekonzistentan.
    // --as-prover / --as-challenger namjerno zamjenjuju ključ za negativne testove.
    bool sign_as_prover = consistent;
    if (arg_present(argc, argv, "--as-prover"))     sign_as_prover = true;
    if (arg_present(argc, argv, "--as-challenger")) sign_as_prover = false;

    const char* key_arg = sign_as_prover ? "--prover-key" : "--challenger-key";
    unsigned char sk[32];
    if (!from_hex32(arg_value(argc, argv, key_arg), sk)) die(std::string("nedostaje ") + key_arg);
    Signer sg;
    if (!MusigAggregator::make_signer(agg.ctx, sk, sg)) die("neispravan ključ");
    secure_zero(sk, 32);

    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, sg, sighash, sig)) die("potpisivanje nije uspjelo");

    std::vector<unsigned char> path = x.tree.merkle_path(idx);
    TaprootCommitment c;
    std::memcpy(c.internal, x.internal, 32);
    std::vector<unsigned char> cb = control_block(c, x.parity, path);

    x.tx.vin[0].witness.clear();
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(pa, pa + 32));
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(pb, pb + 32));
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(pc, pc + 32));
    x.tx.vin[0].witness.push_back(x.scripts[idx]);
    x.tx.vin[0].witness.push_back(cb);

    std::cout << (bad ? "======= MATRIX PRIJEVARA (osporavatelj) ========"
                      : "======= MATRIX DOKAZ (prover, konzistentno) =====") << "\n";
    std::cout << "Gate                         : " << gate << " (" << gate_name(d.op) << ", žice "
              << d.wa << "," << d.wb << " -> " << d.wc << ")\n";
    std::cout << "Ulazi a,b                    : " << a << ", " << b << "  (suma 9 bita: "
              << (a + b) << ")\n";
    std::cout << "Otkriveno (va,vb,vc)         : " << (int)va << "," << (int)vb << "," << (int)vc
              << (bad ? "   ← vc je KRIVO (stvarno " : "   ← stvarno ")
              << (int)vc_true << (bad ? ")" : "") << "\n";
    std::cout << "Kombinacija u matrici        : k=" << k << "  (" << (consistent ? "KONZISTENTNA" : "NEKONZISTENTNA") << ")\n";
    std::cout << "Indeks lista                 : " << idx << " od " << x.scripts.size() << "\n";
    std::cout << "Potpisnik                    : " << (sign_as_prover ? "PROVER" : "OSPORAVATELJ") << "\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " (" << cb.size() << " B)\n";

    std::vector<unsigned char> raw = x.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << x.tx.txid() << "\n";
    std::cout << "=================================================\n";
    return 0;
}

static int cmd_proof_ok(int argc, char** argv)  { return make_gate_proof(argc, argv, false); }
static int cmd_proof_bad(int argc, char** argv) { return make_gate_proof(argc, argv, true); }

// ================================================================ timeout
static int cmd_timeout(int argc, char** argv) {
    Ctx x = load(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "timeout.hex");
    MusigAggregator agg;

    const size_t idx = x.mx.timeout_index();
    unsigned char leaf_hash[32];
    tapleaf_hash(x.scripts[idx], leaf_hash);
    unsigned char sighash[32];
    sighash_taproot(x.tx, x.spent, 0, 0x00, 1, leaf_hash, sighash);

    unsigned char sk[32];
    if (!from_hex32(arg_value(argc, argv, "--prover-key"), sk)) die("--prover-key");
    Signer sg;
    if (!MusigAggregator::make_signer(agg.ctx, sk, sg)) die("prover key");
    secure_zero(sk, 32);

    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, sg, sighash, sig)) die("potpisivanje");

    std::vector<unsigned char> path = x.tree.merkle_path(idx);
    TaprootCommitment c;
    std::memcpy(c.internal, x.internal, 32);
    std::vector<unsigned char> cb = control_block(c, x.parity, path);

    x.tx.vin[0].witness.clear();
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    x.tx.vin[0].witness.push_back(x.scripts[idx]);
    x.tx.vin[0].witness.push_back(cb);

    std::cout << "======= MATRIX TIMEOUT (prover vraća bond) =======\n";
    std::cout << "Indeks lista                 : " << idx << " (timeout, zadnji)\n";
    std::cout << "nSequence                    : " << x.tx.vin[0].sequence
              << "  (CSV traži >= " << kv(x.m, "csv") << ")\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " (" << cb.size() << " B)\n";

    std::vector<unsigned char> raw = x.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << x.tx.txid() << "\n";
    std::cout << "=================================================\n";
    return 0;
}

// ================================================================ main
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "bec-matrix — BitVM2 matrica skriptova (8-bitni zbrajač)\n\n"
                  << "  build      --bits 8 --csv 96 --prover-key <hex> --challenger-key <hex>\n"
                  << "             [--salt <hex>] [--hrp bcrt] --out matrix.txt\n"
                  << "  proof-ok   --matrix matrix.txt --gate G --a N --b N --txid <hex> --vout N\n"
                  << "             --amount <sats> --dest-script <hex> --fee <sats> --sequence 1\n"
                  << "             --prover-key <hex> [--wrong-preimage] [--as-challenger] --out ok.hex\n"
                  << "  proof-bad  (isto, ali --challenger-key; dokazuje nekonzistentan gate)\n"
                  << "  timeout    --matrix matrix.txt --txid <hex> --vout N --amount <sats>\n"
                  << "             --dest-script <hex> --fee <sats> --sequence 96\n"
                  << "             --prover-key <hex> --out timeout.hex\n";
        return 0;
    }
    std::string cmd = argv[1];
    try {
        if (cmd == "build")     return cmd_build(argc, argv);
        if (cmd == "proof-ok")  return cmd_proof_ok(argc, argv);
        if (cmd == "proof-bad") return cmd_proof_bad(argc, argv);
        if (cmd == "timeout")   return cmd_timeout(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Nepoznata naredba: " << cmd << "\n";
    return 1;
}
