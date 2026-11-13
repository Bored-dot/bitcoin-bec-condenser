// bitvm_main.cpp — CLI za BitVM jezgru (bit-commitment bond)
//
// Naredbe:
//   bond      izgradi bond output: N penalty listova (po jedan indeks bita) + 1 timeout
//   penalty   osporavatelj preuzima bond otkrivanjem OBA preimagea za isti indeks
//   timeout   prover vraća bond nakon CSV-a
//
// Build: vidi test/build.sh (gradi se kao drugi binarij, `bec-bitvm`)

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"
#include "bitvm.hpp"

#include <iostream>
#include <fstream>
#include <map>
#include <functional>

using namespace bec;

static void die(const std::string& m) { std::cerr << "[ERROR] " << m << "\n"; std::exit(1); }

static std::string arg_value(int argc, char** argv, const std::string& name, const std::string& def = "") {
    for (int i = 1; i + 1 < argc; i++) if (name == argv[i]) return argv[i + 1];
    return def;
}
static bool arg_present(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; i++) if (name == argv[i]) return true;
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

// ================================================================ bond
static int cmd_bond(int argc, char** argv) {
    const int bits        = std::stoi(arg_value(argc, argv, "--bits", "8"));
    const uint32_t csvb   = (uint32_t)std::stoul(arg_value(argc, argv, "--csv", "144"));
    const std::string hrp = arg_value(argc, argv, "--hrp", "bcrt");
    const std::string out_path = arg_value(argc, argv, "--out", "bond.txt");
    if (bits < 1 || bits > 16) die("--bits mora biti 1..16 (svaki bit je jedan penalty list)");

    MusigAggregator agg;
    unsigned char psk[32], csk[32], salt[32];
    if (!from_hex32(arg_value(argc, argv, "--prover-key"), psk)) die("--prover-key <64 hex>");
    if (!from_hex32(arg_value(argc, argv, "--challenger-key"), csk)) die("--challenger-key <64 hex>");
    const std::string salt_hex = arg_value(argc, argv, "--salt");
    if (salt_hex.empty()) {
        Rng r; r.fill(salt, 32);
    } else if (!from_hex32(salt_hex, salt)) die("--salt <64 hex>");

    Signer prover, challenger;
    if (!MusigAggregator::make_signer(agg.ctx, psk, prover)) die("neispravan --prover-key");
    if (!MusigAggregator::make_signer(agg.ctx, csk, challenger)) die("neispravan --challenger-key");
    secure_zero(psk, 32);
    secure_zero(csk, 32);

    unsigned char px[32], cx[32];
    secp256k1_xonly_pubkey_serialize(agg.ctx, px, &prover.xonly);
    secp256k1_xonly_pubkey_serialize(agg.ctx, cx, &challenger.xonly);

    // Bitovi proverove tvrdnje. U pravom BitVM-u ovo je izlaz izračuna;
    // ovdje je fiksni uzorak da test može pokazati ekvivokaciju.
    std::vector<std::vector<unsigned char>> scripts;
    std::vector<unsigned char> hs0, hs1;
    for (int i = 0; i < bits; i++) {
        unsigned char h0[32], h1[32];
        bit_commitment(0, (uint32_t)i, salt, h0);
        bit_commitment(1, (uint32_t)i, salt, h1);
        hs0.insert(hs0.end(), h0, h0 + 32);
        hs1.insert(hs1.end(), h1, h1 + 32);
        scripts.push_back(equivocation_penalty_script(h0, h1, cx));
    }
    scripts.push_back(bond_timeout_script(px, csvb));

    TapScriptTree tree;
    tree.build(scripts);
    unsigned char root[32];
    tree.merkle_root(root);

    // NUMS internal key: key-path nemoguć, sve ide preko skriptnog stabla
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

    std::cout << "\n=============== BITVM BOND (bit-commitment) ===============\n";
    std::cout << "Bitova (penalty listova)             : " << bits << "\n";
    std::cout << "Timeout CSV (blokovi)                : " << csvb << "\n";
    std::cout << "Dubina skriptnog stabla              : " << tree.depth() << "\n";
    std::cout << "Internal key                         : NUMS (key-path nemoguć)\n";
    std::cout << "Taproot output key                   : " << to_hex(c.output, 32) << "\n";
    std::cout << "bech32m adresa (" << hrp << ")              : " << addr << "\n";
    std::cout << "-----------------------------------------------------------\n";
    std::cout << "Penalty list za indeks i prihvaća SAMO oba preimagea:\n";
    std::cout << "  witness = [sig, preimage(0,i), preimage(1,i)]\n";
    std::cout << "  skript  = OP_SHA256 <h1> EQUALVERIFY OP_SHA256 <h0> EQUALVERIFY <challenger> CHECKSIG\n";
    std::cout << "===========================================================\n";

    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << "bits=" << bits << "\n"
        << "csv=" << csvb << "\n"
        << "hrp=" << hrp << "\n"
        << "internal=" << to_hex(internal, 32) << "\n"
        << "tweak=" << to_hex(c.tweak, 32) << "\n"
        << "output=" << to_hex(c.output, 32) << "\n"
        << "parity=" << parity << "\n"
        << "script_root=" << to_hex(root, 32) << "\n"
        << "address=" << addr << "\n"
        << "prover=" << to_hex(px, 32) << "\n"
        << "challenger=" << to_hex(cx, 32) << "\n"
        << "salt=" << to_hex(salt, 32) << "\n"
        << "h0=" << to_hex(hs0) << "\n"
        << "h1=" << to_hex(hs1) << "\n";
    out.close();
    std::cout << "\n[bond] spremljeno u " << out_path << "\n";
    return 0;
}

// ================================================================ zajedničko
struct Ctx { std::map<std::string, std::string> m; Tx tx; std::vector<TxOut> spent; unsigned char outkey[32]; };

static Ctx prepare(int argc, char** argv) {
    Ctx x;
    x.m = read_kv(arg_value(argc, argv, "--bond", "bond.txt"));
    if (!from_hex32(kv(x.m, "output"), x.outkey)) die("output key nije 32 B");
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
    in.sequence = (uint32_t)std::stoul(arg_value(argc, argv, "--sequence", "4294967293"));
    x.tx.version = 2;
    x.tx.vin.push_back(in);

    TxOut s; s.value = amount; s.script = p2tr_script(x.outkey);
    x.spent.push_back(s);

    TxOut o; o.value = amount - fee;
    if (!from_hex(dest, o.script)) die("neispravan --dest-script");
    x.tx.vout.push_back(o);
    return x;
}

// rekonstrukcija skriptnog stabla iz bond datoteke
static std::vector<std::vector<unsigned char>> rebuild(const std::map<std::string, std::string>& m,
                                                       TapScriptTree& tree, unsigned char prover_x[32],
                                                       unsigned char challenger_x[32]) {
    const int bits = std::stoi(kv(m, "bits"));
    const uint32_t csvb = (uint32_t)std::stoul(kv(m, "csv"));
    if (!from_hex32(kv(m, "prover"), prover_x)) die("prover nije 32 B");
    if (!from_hex32(kv(m, "challenger"), challenger_x)) die("challenger nije 32 B");

    std::vector<unsigned char> hs0, hs1;
    if (!from_hex(kv(m, "h0"), hs0) || !from_hex(kv(m, "h1"), hs1)) die("h0/h1 hex");
    if (hs0.size() != (size_t)bits * 32 || hs1.size() != (size_t)bits * 32) die("h0/h1 veličina");

    std::vector<std::vector<unsigned char>> scripts;
    for (int i = 0; i < bits; i++)
        scripts.push_back(equivocation_penalty_script(&hs0[i * 32], &hs1[i * 32], challenger_x));
    scripts.push_back(bond_timeout_script(prover_x, csvb));

    tree.build(scripts);
    unsigned char rc[32], claimed[32];
    tree.merkle_root(rc);
    if (!from_hex32(kv(m, "script_root"), claimed)) die("script_root");
    if (std::memcmp(rc, claimed, 32) != 0) die("rekonstruirano stablo ne odgovara bondu");
    return scripts;
}

// ================================================================ penalty
static int cmd_penalty(int argc, char** argv) {
    Ctx x = prepare(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "penalty.hex");
    const int index = std::stoi(arg_value(argc, argv, "--index", "0"));
    MusigAggregator agg;

    TapScriptTree tree;
    unsigned char px[32], cx[32];
    std::vector<std::vector<unsigned char>> scripts = rebuild(x.m, tree, px, cx);
    const int bits = std::stoi(kv(x.m, "bits"));
    if (index < 0 || index >= bits) die("--index izvan granica");

    // preimagei
    unsigned char salt[32];
    if (!from_hex32(kv(x.m, "salt"), salt)) die("salt nije 32 B");
    unsigned char pre0[32], pre1[32];
    bit_preimage(0, (uint32_t)index, salt, pre0);
    bit_preimage(1, (uint32_t)index, salt, pre1);
    secure_zero(salt, 32);

    if (arg_present(argc, argv, "--bad-preimage")) {
        pre0[0] ^= 0xFF;   // namjerno pokvaren dokaz
    }
    if (arg_present(argc, argv, "--single-preimage")) {
        // samo jedan preimage — skript mora pasti na drugom EQUALVERIFY
        std::memset(pre0, 0, 32);
    }

    unsigned char leaf_hash[32];
    tapleaf_hash(scripts[index], leaf_hash);
    unsigned char sighash[32];
    sighash_taproot(x.tx, x.spent, 0, 0x00, 1, leaf_hash, sighash);

    unsigned char csk[32];
    if (!from_hex32(arg_value(argc, argv, "--challenger-key"), csk)) die("--challenger-key");
    Signer ch;
    if (!MusigAggregator::make_signer(agg.ctx, csk, ch)) die("challenger key");
    secure_zero(csk, 32);
    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, ch, sighash, sig)) die("potpisivanje");

    std::vector<unsigned char> path = tree.merkle_path((size_t)index);
    TaprootCommitment c;
    unsigned char internal[32];
    if (!from_hex32(kv(x.m, "internal"), internal)) die("internal");
    std::memcpy(c.internal, internal, 32);
    const int parity = std::stoi(kv(x.m, "parity"));
    std::vector<unsigned char> cb = control_block(c, parity, path);

    x.tx.vin[0].witness.clear();
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(pre0, pre0 + 32));
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(pre1, pre1 + 32));
    x.tx.vin[0].witness.push_back(scripts[index]);
    x.tx.vin[0].witness.push_back(cb);

    std::cout << "=============== BITVM PENALTY (ekvivokacija dokazana) ===========\n";
    std::cout << "Indeks bita                  : " << index << "\n";
    std::cout << "preimage(0,i)                : " << to_hex(pre0, 32) << "\n";
    std::cout << "preimage(1,i)                : " << to_hex(pre1, 32) << "\n";
    std::cout << "Skript                       : " << to_hex(scripts[index]) << "\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " (" << cb.size() << " B)\n";
    std::cout << "Napomena                     : skript prihvaća SAMO oba preimagea;\n";
    std::cout << "                               jedan ili pogrešan → OP_EQUALVERIFY pada\n";

    std::vector<unsigned char> raw = x.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << x.tx.txid() << "\n";
    std::cout << "=================================================================\n";
    return 0;
}

// ================================================================ timeout
static int cmd_timeout(int argc, char** argv) {
    Ctx x = prepare(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "timeout.hex");
    MusigAggregator agg;

    TapScriptTree tree;
    unsigned char px[32], cx[32];
    std::vector<std::vector<unsigned char>> scripts = rebuild(x.m, tree, px, cx);
    const int bits = std::stoi(kv(x.m, "bits"));

    const size_t idx = (size_t)bits;     // timeout list je zadnji
    unsigned char leaf_hash[32];
    tapleaf_hash(scripts[idx], leaf_hash);
    unsigned char sighash[32];
    sighash_taproot(x.tx, x.spent, 0, 0x00, 1, leaf_hash, sighash);

    unsigned char psk[32];
    if (!from_hex32(arg_value(argc, argv, "--prover-key"), psk)) die("--prover-key");
    Signer pr;
    if (!MusigAggregator::make_signer(agg.ctx, psk, pr)) die("prover key");
    secure_zero(psk, 32);
    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, pr, sighash, sig)) die("potpisivanje");

    std::vector<unsigned char> path = tree.merkle_path(idx);
    TaprootCommitment c;
    unsigned char internal[32];
    if (!from_hex32(kv(x.m, "internal"), internal)) die("internal");
    std::memcpy(c.internal, internal, 32);
    std::vector<unsigned char> cb = control_block(c, std::stoi(kv(x.m, "parity")), path);

    x.tx.vin[0].witness.clear();
    x.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    x.tx.vin[0].witness.push_back(scripts[idx]);
    x.tx.vin[0].witness.push_back(cb);

    std::cout << "=============== BITVM TIMEOUT (prover vraća bond) ================\n";
    std::cout << "nSequence                    : " << x.tx.vin[0].sequence
              << "  (CSV traži >= " << kv(x.m, "csv") << ")\n";
    std::cout << "Skript                       : " << to_hex(scripts[idx]) << "\n";

    std::vector<unsigned char> raw = x.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << x.tx.txid() << "\n";
    std::cout << "=================================================================\n";
    return 0;
}

// ================================================================ main
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "bec-bitvm — BitVM jezgra (bit-commitment bond)\n\n"
                  << "  bond     --bits N --csv D --prover-key <hex> --challenger-key <hex>\n"
                  << "           [--salt <hex>] [--hrp bcrt] --out bond.txt\n"
                  << "  penalty  --bond bond.txt --index I --txid <hex> --vout N --amount <sats>\n"
                  << "           --dest-script <hex> --fee <sats> --challenger-key <hex>\n"
                  << "           [--bad-preimage] [--single-preimage] --out penalty.hex\n"
                  << "  timeout  --bond bond.txt --txid <hex> --vout N --amount <sats>\n"
                  << "           --dest-script <hex> --fee <sats> --sequence D --prover-key <hex>\n"
                  << "           --out timeout.hex\n";
        return 0;
    }
    std::string cmd = argv[1];
    try {
        if (cmd == "bond")    return cmd_bond(argc, argv);
        if (cmd == "penalty") return cmd_penalty(argc, argv);
        if (cmd == "timeout") return cmd_timeout(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Nepoznata naredba: " << cmd << "\n";
    return 1;
}
