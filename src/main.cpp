// main.cpp — bitcoin-bec-condenser: stvarna implementacija BIP-327 + BIP-341
//
// Što program radi:
//   1. Učita N korisničkih ključeva i izgradi Merkle stablo stanja (state root).
//   2. Izgradi tapscript stablo s listom "unilateral exit" za svakog korisnika;
//      svaki list sadrži state root, pa output key komitira cijelo stanje.
//   3. Agregira ključeve operatora MuSig2 protokolom u jedan internal key.
//   4. Izračuna BIP-341 taptweak i Taproot output key + bech32m adresu.
//   5. (spend-keypath)    MuSig2 potpis preko BIP-341 sighasha -> key-path spend
//   6. (spend-scriptpath) korisnikov unilateralni exit preko skripte + CSV delay
//   7. (spend-op-exit)    operatorska putanja preko skriptnog lista (CSV stroži)
//   8. (spend-challenge)  osporavatelj oduzima izlaz uz javni dokaz prijevare
//   9. (proof)            inclusion proof korisnika u state root
//
// Build: vidi test/build.sh

#include "crypto.hpp"
#include "taproot.hpp"
#include "musig.hpp"
#include "protect.hpp"
#include "challenge.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include <functional>

using namespace bec;

static const char* VERSION_STR = "bec-condenser 2.0 (BIP-327 + BIP-341, regtest-verified)";

// ---------------------------------------------------------------- helpers
static void die(const std::string& msg) { std::cerr << "[ERROR] " << msg << "\n"; std::exit(1); }

static std::string arg_value(int argc, char** argv, const std::string& name, const std::string& def = "") {
    for (int i = 1; i + 1 < argc; i++) if (name == argv[i]) return argv[i + 1];
    return def;
}
static bool arg_present(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; i++) if (name == argv[i]) return true;
    return false;
}

static std::vector<std::string> read_lines(const std::string& path) {
    std::ifstream f(path);
    if (!f.good()) die("ne mogu otvoriti " + path);
    std::vector<std::string> out;
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        size_t p = line.find_first_not_of(" \t");
        if (p != std::string::npos) line = line.substr(p);
        if (line.empty() || line[0] == '#') continue;
        out.push_back(line);
    }
    return out;
}

static std::map<std::string, std::string> read_kv(const std::string& path) {
    std::map<std::string, std::string> m;
    for (const std::string& l : read_lines(path)) {
        size_t eq = l.find('=');
        if (eq == std::string::npos) continue;
        m[l.substr(0, eq)] = l.substr(eq + 1);
    }
    return m;
}

static std::string kv_get(const std::map<std::string, std::string>& m, const std::string& k) {
    auto it = m.find(k);
    if (it == m.end()) die("nedostaje polje '" + k + "' u datoteci stanja");
    return it->second;
}

// Okreni 32-bajtni hash: prikazani txid (big-endian hex) -> interni (little-endian)
static bool txid_from_display_hex(const std::string& hex, unsigned char out[32]) {
    unsigned char tmp[32];
    if (!from_hex32(hex, tmp)) return false;
    for (int i = 0; i < 32; i++) out[i] = tmp[31 - i];
    return true;
}

// ================================================================ commit
static int cmd_commit(int argc, char** argv) {
    const std::string keys_path = arg_value(argc, argv, "--keys", "keys.txt");
    const std::string ops_path  = arg_value(argc, argv, "--operators", "operators.txt");
    const std::string out_path  = arg_value(argc, argv, "--out", "commitment.txt");
    const std::string hrp       = arg_value(argc, argv, "--hrp", "bcrt");
    const uint32_t delay        = (uint32_t)std::stoul(arg_value(argc, argv, "--delay", "10"));
    // --protect: internal key = NUMS (key-path nemoguć) + operatorski list s dužim CSV-om.
    // Bez toga operatori mogu potrošiti output odmah i pretrčati korisnički exit.
    const bool protect          = arg_present(argc, argv, "--protect");
    const uint32_t op_delay     = (uint32_t)std::stoul(arg_value(argc, argv, "--op-delay",
                                       std::to_string(delay * 2)));
    // --challenge: svaki korisnik dobiva DVA lista — claim (nakon prozora) i
    // challenge (osporavatelj s dokazom). Vidi src/challenge.hpp.
    const bool challenge_mode  = arg_present(argc, argv, "--challenge");
    const uint32_t chal_window = (uint32_t)std::stoul(arg_value(argc, argv, "--challenge-window", "144"));
    unsigned char challenger_xonly[32] = {0};
    bool have_challenger = false;
    const std::string leaf_mode = arg_value(argc, argv, "--leaf-mode", "exit"); // exit | pk
    size_t leaves               = (size_t)std::stoul(arg_value(argc, argv, "--leaves", "64"));

    MusigAggregator agg_ctx;

    if (challenge_mode) {
        unsigned char csk[32];
        if (!from_hex32(arg_value(argc, argv, "--challenger-key"), csk))
            die("--challenge traži --challenger-key <64 hex> (tajni ključ osporavatelja)");
        Signer cs;
        if (!MusigAggregator::make_signer(agg_ctx.ctx, csk, cs)) die("neispravan --challenger-key");
        secure_zero(csk, 32);
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, challenger_xonly, &cs.xonly);
        have_challenger = true;
    }

    // ---- korisnici ----
    std::vector<std::string> key_lines = read_lines(keys_path);
    std::vector<Signer> users;
    users.reserve(key_lines.size());
    size_t rejected = 0;
    for (const std::string& line : key_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) { rejected++; continue; }
        Signer s;
        if (!MusigAggregator::make_signer(agg_ctx.ctx, sk, s)) { rejected++; secure_zero(sk, 32); continue; }
        secure_zero(sk, 32);
        users.push_back(s);
    }
    if (users.size() < 2) die("potrebno je barem 2 valjana korisnička ključa");
    std::cout << "[commit] korisnika: " << users.size() << "  (odbačeno: " << rejected << ")\n";

    // ---- stanje: list = tagged_hash("BEC/state", xonly || balance_le8) ----
    std::vector<unsigned char> leaves_bytes;
    leaves_bytes.reserve(users.size() * 32);
    for (size_t i = 0; i < users.size(); i++) {
        unsigned char payload[40];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, payload, &users[i].xonly);
        uint64_t balance = 100000000ULL + 1500ULL * (i % 977); // demo balans
        for (int b = 0; b < 8; b++) payload[32 + b] = (unsigned char)(balance >> (8 * b));
        unsigned char h[32];
        tagged_hash("BEC/state", payload, sizeof(payload), h);
        leaves_bytes.insert(leaves_bytes.end(), h, h + 32);
    }
    MerkleTree state_tree;
    state_tree.build(leaves_bytes);
    unsigned char state_root[32];
    state_tree.root(state_root);

    // ---- tapscript stablo: exit list za prvih `leaves` korisnika ----
    if (leaves == 0) leaves = 1;
    if (leaves > users.size()) leaves = users.size();
    // power-of-two samo zato da descriptor u testu ima jednoznačan oblik
    size_t p2 = 1;
    while (p2 * 2 <= leaves) p2 *= 2;
    if (p2 != leaves) {
        std::cout << "[commit] napomena: --leaves " << leaves << " nije potencija dvojke; "
                  << "koristim " << p2 << " za skriptno stablo (descriptor se ne može jednoznačno opisati)\n";
        leaves = p2;
    }

    if (protect && op_delay <= delay)
        die("--op-delay mora biti STROGO veći od --delay, inače operatori mogu pretrčati korisnike");

    if (challenge_mode && !have_challenger) die("--challenge bez osporavatelja");
    // U --challenge načinu svaki korisnik zauzima DVA lista (claim + challenge).
    const size_t per_user = challenge_mode ? 2 : 1;

    std::vector<std::vector<unsigned char>> scripts;
    scripts.reserve(leaves);
    // Ako je --protect, list 0 je operatorski; korisnici počinju nakon njega.
    const size_t user_leaf_offset = protect ? 1 : 0;
    size_t n_user_leaves = leaves > user_leaf_offset ? leaves - user_leaf_offset : 0;
    if (challenge_mode) n_user_leaves /= 2;   // svaki korisnik traži 2 lista
    leaves = user_leaf_offset + per_user * n_user_leaves;   // stvarna veličina stabla

    for (size_t i = 0; i < n_user_leaves; i++) {
        unsigned char ux[32];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ux, &users[i].xonly);
        if (challenge_mode) {
            // tvrdnja: koliko korisnik i misli da mu pripada
            uint64_t bal = 100000000ULL + 1500ULL * (i % 977);
            unsigned char digest[32];
            claim_digest_of(state_root, i, bal, digest);
            scripts.push_back(claim_leaf_script(digest, ux, chal_window));
            scripts.push_back(challenge_leaf_script(digest, challenger_xonly, 1));
        } else if (leaf_mode == "pk") {
            // list identičan descriptor fragmentu pk(KEY): <32B kljuc> OP_CHECKSIG
            std::vector<unsigned char> sc;
            push_data(sc, ux, 32);
            sc.push_back(OP_CHECKSIG);
            scripts.push_back(sc);
        } else {
            scripts.push_back(exit_leaf_script(state_root, ux, delay));
        }
    }
    // operatorski list ide na index 0 (samo u --protect načinu)
    unsigned char op_agg_ser[32] = {0};
    if (protect) {
        std::vector<std::string> ops_pre = read_lines(ops_path);
        std::vector<secp256k1_pubkey> op_pks_pre;
        for (const std::string& line : ops_pre) {
            unsigned char sk[32];
            if (!from_hex32(line, sk)) die("neispravan operatorski ključ");
            Signer sg;
            if (!MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) die("neispravan operatorski ključ");
            secure_zero(sk, 32);
            op_pks_pre.push_back(sg.pk);
        }
        if (op_pks_pre.empty()) die("nema operatorskih ključeva");
        KeyAgg ka_pre;
        ka_pre.aggregate(agg_ctx.ctx, op_pks_pre, nullptr);
        std::memcpy(op_agg_ser, ka_pre.agg_ser, 32);
        scripts.insert(scripts.begin(), csv_checksig_script(op_agg_ser, op_delay));
    }

    TapScriptTree sc_tree;
    sc_tree.build(scripts);
    unsigned char script_root[32];
    sc_tree.merkle_root(script_root);

    // ---- operatori -> MuSig2 agregat ----
    std::vector<std::string> op_lines = read_lines(ops_path);
    std::vector<Signer> operators;
    for (const std::string& line : op_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) die("neispravan operatorski ključ: " + line.substr(0, 16) + "...");
        Signer s;
        if (!MusigAggregator::make_signer(agg_ctx.ctx, sk, s)) die("neispravan operatorski ključ (>= n?)");
        secure_zero(sk, 32);
        operators.push_back(s);
    }
    if (operators.empty()) die("nema operatorskih ključeva u " + ops_path);

    std::vector<secp256k1_pubkey> op_pks;
    for (const Signer& s : operators) op_pks.push_back(s.pk);

    KeyAgg ka;
    ka.aggregate(agg_ctx.ctx, op_pks, nullptr);
    unsigned char internal[32];
    if (protect) {
        // NUMS: nitko ne zna diskretni log, pa key-path ne postoji.
        std::memcpy(internal, nums_internal_key(), 32);
    } else {
        std::memcpy(internal, ka.agg_ser, 32);
    }

    // ---- BIP-341 taptweak (ručno, da uhvatimo parity output ključa) ----
    TaprootCommitment c;
    tap_tweak(internal, script_root, c);
    secp256k1_pubkey tweaked;
    // U --protect načinu tweak se NE smije primijeniti na MuSig2 cache
    // (internal je NUMS, ne agregat operatora), pa računamo preko točke.
    bool tweak_ok = false;
    if (protect) {
        secp256k1_xonly_pubkey nums_x;
        if (secp256k1_xonly_pubkey_parse(agg_ctx.ctx, &nums_x, internal))
            tweak_ok = secp256k1_xonly_pubkey_tweak_add(agg_ctx.ctx, &tweaked, &nums_x, c.tweak) == 1;
    } else {
        tweak_ok = secp256k1_musig_pubkey_xonly_tweak_add(agg_ctx.ctx, &tweaked, &ka.cache, c.tweak) == 1;
    }
    if (!tweak_ok) die("taptweak nije valjan");
    unsigned char ser33[33];
    size_t ser33len = 33;
    secp256k1_ec_pubkey_serialize(agg_ctx.ctx, ser33, &ser33len, &tweaked, SECP256K1_EC_COMPRESSED);
    int parity = (ser33[0] == 0x03) ? 1 : 0;
    std::memcpy(c.output, ser33 + 1, 32);
    c.output_parity = parity;

    std::string addr;
    if (!taproot_address(hrp, c.output, addr)) die("bech32m enkodiranje nije uspjelo");

    // ---- descriptor (ugniježđeni, točno odgovara našem stablu) ----
    std::function<std::string(size_t, size_t)> build_desc = [&](size_t lo, size_t hi) -> std::string {
        if (hi - lo == 1) {
            if (leaf_mode == "pk") {
                unsigned char ux[32];
                secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ux, &users[lo].xonly);
                return "pk(" + to_hex(ux, 32) + ")";
            }
            return "raw(" + to_hex(scripts[lo]) + ")";
        }
        size_t mid = lo + (hi - lo) / 2;
        return "{" + build_desc(lo, mid) + "," + build_desc(mid, hi) + "}";
    };
    std::string descriptor = "tr(" + to_hex(internal, 32) + "," + build_desc(0, leaves) + ")";

    // ---- ispis ----
    std::cout << "\n=============== BEC CONDENSER — TAPROOT COMMITMENT ===============\n";
    std::cout << "Korisnika u stanju (listovi)        : " << users.size() << "\n";
    std::cout << "Dubina state Merkle stabla          : " << state_tree.depth() << "\n";
    std::cout << "Exit listova u tapscript stablu     : " << leaves << "\n";
    std::cout << "Dubina tapscript stabla             : " << sc_tree.depth() << "\n";
    std::cout << "CSV delay korisnika (blokovi)       : " << delay << "\n";
    std::cout << "CSV delay operatora (blokovi)       : " << (protect ? std::to_string(op_delay) : "— (nema operatorskog lista)") << "\n";
    std::cout << "Key-path potrošnja                  : " << (protect ? "NEMOGUĆA (NUMS internal key)" : "moguća (MuSig2 operatora)") << "\n";
    if (challenge_mode)
        std::cout << "Challenge/response                  : AKTIVAN (prozor " << chal_window
                  << " blokova, challenge CSV 1)\n";
    std::cout << "Operatorskih ključeva (MuSig2)      : " << operators.size() << "\n";
    std::cout << "-------------------------------------------------------------------\n";
    std::cout << "State root                          : " << to_hex(state_root, 32) << "\n";
    std::cout << "Tapscript merkle root               : " << to_hex(script_root, 32) << "\n";
    std::cout << "Internal key                        : " << to_hex(internal, 32) << "\n";
    std::cout << "Taptweak t                          : " << to_hex(c.tweak, 32) << "\n";
    std::cout << "Taproot output key                  : " << to_hex(c.output, 32) << "\n";
    std::cout << "Output key parity                   : " << (parity ? "odd (0x03)" : "even (0x02)") << "\n";
    std::cout << "bech32m adresa (" << hrp << ")              : " << addr << "\n";
    std::cout << "-------------------------------------------------------------------\n";
    if (protect)
        std::cout << "descriptor                          : (nije prikazan — raw() unutar tr() nije valjan descriptor)\n";
    else
        std::cout << "descriptor                          : " << descriptor << "\n";
    std::cout << "===================================================================\n";

    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << "version=" << VERSION_STR << "\n"
        << "internal=" << to_hex(internal, 32) << "\n"
        << "tweak=" << to_hex(c.tweak, 32) << "\n"
        << "output=" << to_hex(c.output, 32) << "\n"
        << "parity=" << parity << "\n"
        << "state_root=" << to_hex(state_root, 32) << "\n"
        << "script_root=" << to_hex(script_root, 32) << "\n"
        << "leaves=" << leaves << "\n"
        << "delay=" << delay << "\n"
        << "address=" << addr << "\n"
        << "descriptor=" << (protect ? std::string("") : descriptor) << "\n"
        << "hrp=" << hrp << "\n"
        << "keys_file=" << keys_path << "\n"
        << "operators_file=" << ops_path << "\n"
        << "n_users=" << users.size() << "\n"
        << "leaf_mode=" << leaf_mode << "\n"
        << "protect=" << (protect ? 1 : 0) << "\n"
        << "op_delay=" << op_delay << "\n"
        << "op_agg=" << (protect ? to_hex(op_agg_ser, 32) : std::string("")) << "\n"
        << "challenge=" << (challenge_mode ? 1 : 0) << "\n"
        << "challenge_window=" << chal_window << "\n"
        << "challenger=" << (challenge_mode ? to_hex(challenger_xonly, 32) : std::string("")) << "\n";
    out.close();
    std::cout << "\n[commit] spremljeno u " << out_path << "\n";
    return 0;
}

// ================================================================ zajedničko za spend
struct SpendCtx {
    std::map<std::string, std::string> cm;
    TaprootCommitment commitment;
    Tx tx;
    std::vector<TxOut> spent;
    unsigned char output_key[32];
};

static SpendCtx prepare_spend(int argc, char** argv) {
    SpendCtx s;
    s.cm = read_kv(arg_value(argc, argv, "--commitment", "commitment.txt"));
    if (!from_hex32(kv_get(s.cm, "internal"), s.commitment.internal)) die("internal key nije 32 B");
    if (!from_hex32(kv_get(s.cm, "tweak"), s.commitment.tweak)) die("tweak nije 32 B");
    if (!from_hex32(kv_get(s.cm, "output"), s.output_key)) die("output key nije 32 B");
    s.commitment.output_parity = std::stoi(kv_get(s.cm, "parity"));
    std::memcpy(s.commitment.output, s.output_key, 32);

    const std::string txid_hex = arg_value(argc, argv, "--txid");
    if (txid_hex.empty()) die("--txid je obavezan");
    const uint32_t vout = (uint32_t)std::stoul(arg_value(argc, argv, "--vout", "0"));
    const uint64_t amount = std::stoull(arg_value(argc, argv, "--amount", "0"));
    const uint64_t fee    = std::stoull(arg_value(argc, argv, "--fee", "1000"));
    const std::string dest_hex = arg_value(argc, argv, "--dest-script");
    if (dest_hex.empty()) die("--dest-script je obavezan");
    if (amount == 0) die("--amount (sats) je obavezan");

    TxIn in;
    if (!txid_from_display_hex(txid_hex, in.txid)) die("neispravan --txid");
    in.vout = vout;
    in.sequence = (uint32_t)std::stoul(arg_value(argc, argv, "--sequence", "4294967293"));
    s.tx.version = 2;
    s.tx.locktime = (uint32_t)std::stoul(arg_value(argc, argv, "--locktime", "0"));
    s.tx.vin.push_back(in);

    TxOut spent_out;
    spent_out.value = amount;
    spent_out.script = p2tr_script(s.output_key);
    s.spent.push_back(spent_out);

    TxOut o;
    o.value = amount - fee;
    if (!from_hex(dest_hex, o.script)) die("neispravan --dest-script (hex)");
    s.tx.vout.push_back(o);
    return s;
}

// ================================================================ spend-keypath
static int cmd_spend_keypath(int argc, char** argv) {
    SpendCtx s = prepare_spend(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "keypath.hex");
    // --fake-keypath: namjerno proizvedi key-path transakciju i u --protect načinu,
    // da negativni test dokaže da je NUMS internal key stvarno nepotrošiv.
    const bool fake_keypath = arg_present(argc, argv, "--fake-keypath");
    MusigAggregator agg_ctx;

    // operatori
    std::vector<std::string> op_lines = read_lines(kv_get(s.cm, "operators_file"));
    std::vector<Signer> operators;
    for (const std::string& line : op_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) die("neispravan operatorski ključ");
        Signer sg; if (!MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) die("neispravan operatorski ključ");
        secure_zero(sk, 32);
        operators.push_back(sg);
    }

    // keyagg s taptweakom kroz cache (ista cache kao kod commit-a)
    std::vector<secp256k1_pubkey> pks;
    for (const Signer& sg : operators) pks.push_back(sg.pk);
    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    {
        std::vector<const secp256k1_pubkey*> ptrs;
        for (const secp256k1_pubkey& p : pks) ptrs.push_back(&p);
        if (!secp256k1_musig_pubkey_agg(agg_ctx.ctx, &agg_pk, &cache, ptrs.data(), ptrs.size()))
            die("musig_pubkey_agg");
        secp256k1_pubkey tweaked;
        if (!secp256k1_musig_pubkey_xonly_tweak_add(agg_ctx.ctx, &tweaked, &cache, s.commitment.tweak))
            die("taptweak");
        unsigned char ser[33]; size_t l = 33;
        secp256k1_ec_pubkey_serialize(agg_ctx.ctx, ser, &l, &tweaked, SECP256K1_EC_COMPRESSED);
        if (std::memcmp(ser + 1, s.output_key, 32) != 0) {
            if (!fake_keypath)
                die("agregirani ključ ne odgovara commitmentu (krivi operatorski ključevi?)");
            std::cout << "[fake-keypath] tweakani agregat operatora NE odgovara output keyu "
                         "— ovo je namjerno (NUMS internal key)\n";
        }
        if (!secp256k1_xonly_pubkey_from_pubkey(agg_ctx.ctx, &agg_pk, nullptr, &tweaked))
            die("xonly");
    }

    // BIP-341 sighash (key path, SIGHASH_DEFAULT)
    unsigned char sighash[32];
    sighash_taproot(s.tx, s.spent, 0, 0x00, 0, nullptr, sighash);

    // --- negativni test: potpis SAMO jednim operatorskim ključem (bug iz originala) ---
    if (arg_present(argc, argv, "--rogue")) {
        unsigned char bad[64];
        unsigned char aux[32];
        { Rng rng; rng.fill(aux, 32); }
        secp256k1_schnorrsig_sign32(agg_ctx.ctx, bad, sighash, &operators[0].kp, aux);
        secp256k1_xonly_pubkey out_xonly_bad;
        secp256k1_xonly_pubkey_parse(agg_ctx.ctx, &out_xonly_bad, s.output_key);
        bool bad_ok = schnorr_verify(agg_ctx.ctx, bad, sighash, out_xonly_bad);
        std::cout << "=============== KEY-PATH SPEND (KRIVI POTPIS) ===============\n";
        std::cout << "Potpis je napravljen SAMO ključem operatora #0.\n";
        std::cout << "Verifikacija vs output key   : " << (bad_ok ? "OK (!!)" : "FAIL — očekivano") << "\n";
        s.tx.vin[0].witness.clear();
        s.tx.vin[0].witness.push_back(std::vector<unsigned char>(bad, bad + 64));
        std::vector<unsigned char> raw_bad = s.tx.serialize(true);
        std::ofstream ob{out_path};
        if (!ob.good()) die("ne mogu pisati " + out_path);
        ob << to_hex(raw_bad) << "\n";
        ob.close();
        std::cout << "txid                         : " << s.tx.txid() << "\n";
        std::cout << "=============================================================\n";
        return bad_ok ? 1 : 0;
    }

    // MuSig2 dvije runde
    std::vector<secp256k1_pubkey> pks2;
    for (const Signer& sg : operators) pks2.push_back(sg.pk);
    MusigSession sess;
    musig_round1(agg_ctx.ctx, pks2, sighash, cache, sess);
    unsigned char sig[64];
    musig_round2(agg_ctx.ctx, operators, cache, sess, sig);

    secp256k1_xonly_pubkey out_xonly;
    if (!secp256k1_xonly_pubkey_parse(agg_ctx.ctx, &out_xonly, s.output_key)) die("xonly parse");
    bool ok = schnorr_verify(agg_ctx.ctx, sig, sighash, out_xonly);
    if (!ok) {
        if (!fake_keypath) die("finalni MuSig2 potpis NE valja protiv output keya — prekidam");
        std::cout << "[fake-keypath] potpis NE valja protiv output keya — očekivano, "
                     "key-path je u --protect načinu onemogućen\n";
    }

    s.tx.vin[0].witness.clear();
    s.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));

    std::cout << "=============== KEY-PATH SPEND (MuSig2) ===============\n";
    std::cout << "Potpisnika (MuSig2)          : " << operators.size() << "\n";
    std::cout << "Sighash (BIP-341)            : " << to_hex(sighash, 32) << "\n";
    std::cout << "Finalni Schnorr potpis       : " << to_hex(sig, 64) << "\n";
    std::cout << "Witness veličina             : " << 64 << " B (1 element)\n";
    std::cout << "Verifikacija vs output key   : " << (ok ? "OK" : "FAIL") << "\n";

    std::vector<unsigned char> raw = s.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << s.tx.txid() << "\n";
    std::cout << "=======================================================\n";
    return 0;
}

// ================================================================ spend-scriptpath
static int cmd_spend_scriptpath(int argc, char** argv) {
    SpendCtx s = prepare_spend(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "scriptpath.hex");
    const size_t leaf = (size_t)std::stoul(arg_value(argc, argv, "--leaf", "0"));
    MusigAggregator agg_ctx;

    // rekonstrukcija skriptnog stabla iz commitmenta → potreban state_root i delay
    unsigned char state_root[32];
    if (!from_hex32(kv_get(s.cm, "state_root"), state_root)) die("state_root nije 32 B");
    const uint32_t delay = (uint32_t)std::stoul(kv_get(s.cm, "delay"));
    const size_t leaves = (size_t)std::stoul(kv_get(s.cm, "leaves"));

    std::map<std::string, std::string>::const_iterator it_protect = s.cm.find("protect");
    const bool protect = (it_protect != s.cm.end() && it_protect->second == "1");
    const size_t user_offset = protect ? 1 : 0;

    std::vector<std::string> user_lines = read_lines(kv_get(s.cm, "keys_file"));
    std::vector<Signer> users;
    for (const std::string& line : user_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) continue;
        Signer sg;
        if (MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) users.push_back(sg);
        secure_zero(sk, 32);
    }
    std::map<std::string, std::string>::const_iterator it_ch = s.cm.find("challenge");
    const bool chal = (it_ch != s.cm.end() && it_ch->second == "1");
    const uint32_t chal_window = chal ? (uint32_t)std::stoul(kv_get(s.cm, "challenge_window")) : 0;
    unsigned char challenger_x[32] = {0};
    if (chal && !from_hex32(kv_get(s.cm, "challenger"), challenger_x)) die("challenger nije 32 B");
    const size_t per_user = chal ? 2 : 1;

    size_t n_user_leaves = leaves > user_offset ? leaves - user_offset : 0;
    if (chal) n_user_leaves /= 2;
    if (leaf >= n_user_leaves || leaf >= users.size()) die("--leaf izvan granica");

    std::vector<std::vector<unsigned char>> scripts;
    if (protect) {
        unsigned char op_agg[32];
        if (!from_hex32(kv_get(s.cm, "op_agg"), op_agg)) die("op_agg nije 32 B");
        scripts.push_back(csv_checksig_script(op_agg, (uint32_t)std::stoul(kv_get(s.cm, "op_delay"))));
    }
    for (size_t i = 0; i < n_user_leaves; i++) {
        unsigned char ux[32];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ux, &users[i].xonly);
        if (chal) {
            uint64_t bal = 100000000ULL + 1500ULL * (i % 977);
            unsigned char digest[32];
            claim_digest_of(state_root, i, bal, digest);
            scripts.push_back(claim_leaf_script(digest, ux, chal_window));
            scripts.push_back(challenge_leaf_script(digest, challenger_x, 1));
        } else {
            scripts.push_back(exit_leaf_script(state_root, ux, delay));
        }
    }
    TapScriptTree tree;
    tree.build(scripts);
    unsigned char root_check[32];
    tree.merkle_root(root_check);
    unsigned char claimed[32];
    if (!from_hex32(kv_get(s.cm, "script_root"), claimed)) die("script_root nije 32 B");
    if (std::memcmp(root_check, claimed, 32) != 0)
        die("rekonstruirano skriptno stablo ne odgovara commitmentu");

    const size_t script_index = user_offset + per_user * leaf;
    unsigned char leaf_hash[32];
    tapleaf_hash(scripts[script_index], leaf_hash);

    // sighash za script path
    unsigned char sighash[32];
    sighash_taproot(s.tx, s.spent, 0, 0x00, 1, leaf_hash, sighash);

    unsigned char sig[64];
    if (!schnorr_sign(agg_ctx.ctx, users[leaf], sighash, sig)) die("potpisivanje nije uspjelo");

    secp256k1_xonly_pubkey uxonly;
    secp256k1_xonly_pubkey_from_pubkey(agg_ctx.ctx, &uxonly, nullptr, &users[leaf].pk);
    bool ok = schnorr_verify(agg_ctx.ctx, sig, sighash, uxonly);
    if (!ok) die("korisnikov potpis ne valja");

    std::vector<unsigned char> path = tree.merkle_path(script_index);
    TaprootCommitment c;
    std::memcpy(c.internal, s.commitment.internal, 32);
    std::vector<unsigned char> cb = control_block(c, s.commitment.output_parity, path);
    if (arg_present(argc, argv, "--bad-control") && cb.size() > 33) {
        cb[33] ^= 0x01; // namjerno pokvari prvi hash u putu
        std::cout << "[negativni test] kontrolni blok je namjerno pokvaren\n";
    }

    s.tx.vin[0].witness.clear();
    s.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    s.tx.vin[0].witness.push_back(scripts[script_index]);
    s.tx.vin[0].witness.push_back(cb);

    std::cout << "============ SCRIPT-PATH SPEND (unilateralni exit) ============\n";
    std::cout << "Korisnik (leaf index)        : " << leaf << "\n";
    std::cout << "nSequence                    : " << s.tx.vin[0].sequence
              << "  (CSV traži >= " << delay << ")\n";
    std::cout << "Script (hex)                 : " << to_hex(scripts[script_index]) << "\n";
    std::cout << "Kontrolni blok               : " << to_hex(cb) << "\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " ("
              << cb.size() << " B ukupno)\n";
    std::cout << "Sighash (BIP-341, ext_flag 1): " << to_hex(sighash, 32) << "\n";
    std::cout << "Potpis korisnika             : " << to_hex(sig, 64) << "\n";
    std::cout << "Witness veličina             : " << (64 + 2 + scripts[script_index].size() + 2 + cb.size()) << " B\n";
    std::cout << "CSV delay istekao?           : "
              << ((s.tx.vin[0].sequence & 0xffff) >= delay ? "DA" : "NE — node će odbiti")
              << "\n";

    std::vector<unsigned char> raw = s.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << s.tx.txid() << "\n";
    std::cout << "===============================================================\n";
    return 0;
}

// ================================================================ spend-op-exit
// Operatorska putanja: operatorski list u skriptnom stablu, potpisan MuSig2 protokolom.
// Vremenski je iza korisničkog CSV-a, pa operatori mogu djelovati tek nakon što su
// korisnici imali priliku izaći.
static int cmd_spend_op_exit(int argc, char** argv) {
    SpendCtx s = prepare_spend(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "opexit.hex");
    MusigAggregator agg_ctx;

    std::map<std::string, std::string>::const_iterator it_protect = s.cm.find("protect");
    if (it_protect == s.cm.end() || it_protect->second != "1")
        die("commitment nije u --protect načinu; operatorski list ne postoji");

    unsigned char op_agg[32];
    if (!from_hex32(kv_get(s.cm, "op_agg"), op_agg)) die("op_agg nije 32 B");
    const uint32_t op_delay = (uint32_t)std::stoul(kv_get(s.cm, "op_delay"));
    const uint32_t delay    = (uint32_t)std::stoul(kv_get(s.cm, "delay"));
    const size_t leaves     = (size_t)std::stoul(kv_get(s.cm, "leaves"));

    // operatori
    std::vector<std::string> op_lines = read_lines(kv_get(s.cm, "operators_file"));
    std::vector<Signer> operators;
    for (const std::string& line : op_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) die("neispravan operatorski ključ");
        Signer sg;
        if (!MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) die("neispravan operatorski ključ");
        secure_zero(sk, 32);
        operators.push_back(sg);
    }

    // keyagg operatora — BEZ taptweaka, jer je ovo ključ u skriptnom listu
    secp256k1_musig_keyagg_cache cache;
    secp256k1_xonly_pubkey agg_pk;
    {
        std::vector<const secp256k1_pubkey*> ptrs;
        for (const Signer& sg : operators) ptrs.push_back(&sg.pk);
        if (!secp256k1_musig_pubkey_agg(agg_ctx.ctx, &agg_pk, &cache, ptrs.data(), ptrs.size()))
            die("musig_pubkey_agg");
        unsigned char ser[32];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ser, &agg_pk);
        if (std::memcmp(ser, op_agg, 32) != 0)
            die("agregat operatora ne odgovara commitmentu");
    }

    // rekonstrukcija stabla
    unsigned char state_root[32];
    if (!from_hex32(kv_get(s.cm, "state_root"), state_root)) die("state_root nije 32 B");
    std::vector<std::string> user_lines = read_lines(kv_get(s.cm, "keys_file"));
    std::vector<Signer> users;
    for (const std::string& line : user_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) continue;
        Signer sg;
        if (MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) users.push_back(sg);
        secure_zero(sk, 32);
    }
    const size_t n_user_leaves = leaves > 1 ? leaves - 1 : 0;
    std::vector<std::vector<unsigned char>> scripts;
    scripts.push_back(csv_checksig_script(op_agg, op_delay));
    for (size_t i = 0; i < n_user_leaves && i < users.size(); i++) {
        unsigned char ux[32];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ux, &users[i].xonly);
        scripts.push_back(exit_leaf_script(state_root, ux, delay));
    }
    TapScriptTree tree;
    tree.build(scripts);
    unsigned char root_check[32];
    tree.merkle_root(root_check);
    unsigned char claimed[32];
    if (!from_hex32(kv_get(s.cm, "script_root"), claimed)) die("script_root nije 32 B");
    if (std::memcmp(root_check, claimed, 32) != 0)
        die("rekonstruirano skriptno stablo ne odgovara commitmentu");

    unsigned char leaf_hash[32];
    tapleaf_hash(scripts[0], leaf_hash);

    unsigned char sighash[32];
    sighash_taproot(s.tx, s.spent, 0, 0x00, 1, leaf_hash, sighash);

    std::vector<secp256k1_pubkey> pks;
    for (const Signer& sg : operators) pks.push_back(sg.pk);
    MusigSession sess;
    musig_round1(agg_ctx.ctx, pks, sighash, cache, sess);
    unsigned char sig[64];
    musig_round2(agg_ctx.ctx, operators, cache, sess, sig);

    unsigned char ser[32];
    secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ser, &agg_pk);
    secp256k1_xonly_pubkey agg_x;
    if (!secp256k1_xonly_pubkey_parse(agg_ctx.ctx, &agg_x, ser)) die("agg xonly parse");
    bool ok = schnorr_verify(agg_ctx.ctx, sig, sighash, agg_x);
    if (!ok) die("MuSig2 potpis operatora ne valja");

    std::vector<unsigned char> path = tree.merkle_path(0);
    TaprootCommitment c;
    std::memcpy(c.internal, s.commitment.internal, 32);
    std::vector<unsigned char> cb = control_block(c, s.commitment.output_parity, path);

    s.tx.vin[0].witness.clear();
    s.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    s.tx.vin[0].witness.push_back(scripts[0]);
    s.tx.vin[0].witness.push_back(cb);

    std::cout << "============ SCRIPT-PATH SPEND (operatorska putanja) ============\n";
    std::cout << "Potpisnika (MuSig2)          : " << operators.size() << "\n";
    std::cout << "nSequence                    : " << s.tx.vin[0].sequence
              << "  (CSV traži >= " << op_delay << ")\n";
    std::cout << "Korisnički CSV               : " << delay
              << "  (operatori su " << (op_delay > delay ? "SPORIJI — dobro" : "BRŽI — KRIVO") << ")\n";
    std::cout << "Script (hex)                 : " << to_hex(scripts[0]) << "\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " (" << cb.size() << " B)\n";
    std::cout << "Sighash (BIP-341, ext_flag 1): " << to_hex(sighash, 32) << "\n";
    std::cout << "MuSig2 potpis                : " << to_hex(sig, 64) << "\n";
    std::cout << "Operator može potrošiti?     : "
              << ((s.tx.vin[0].sequence & 0xffff) >= op_delay ? "DA" : "NE — još traje korisnički prozor")
              << "\n";

    std::vector<unsigned char> raw = s.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << s.tx.txid() << "\n";
    std::cout << "=================================================================\n";
    return 0;
}

// ================================================================ spend-challenge
// Osporavatelj preuzima izlaz otkrivanjem dokaza (preimage) koji hashira na
// claim_digest iz skripta. Bez točnog dokaza skript pada na OP_EQUALVERIFY.
static int cmd_spend_challenge(int argc, char** argv) {
    SpendCtx s = prepare_spend(argc, argv);
    const std::string out_path = arg_value(argc, argv, "--out", "challenge.hex");
    const size_t leaf = (size_t)std::stoul(arg_value(argc, argv, "--leaf", "0"));
    MusigAggregator agg_ctx;

    std::map<std::string, std::string>::const_iterator it_ch = s.cm.find("challenge");
    if (it_ch == s.cm.end() || it_ch->second != "1")
        die("commitment nije u --challenge načinu");

    unsigned char state_root[32];
    if (!from_hex32(kv_get(s.cm, "state_root"), state_root)) die("state_root nije 32 B");
    const uint32_t delay = (uint32_t)std::stoul(kv_get(s.cm, "delay"));
    const size_t leaves = (size_t)std::stoul(kv_get(s.cm, "leaves"));
    const uint32_t chal_window = (uint32_t)std::stoul(kv_get(s.cm, "challenge_window"));
    unsigned char challenger_x[32];
    if (!from_hex32(kv_get(s.cm, "challenger"), challenger_x)) die("challenger nije 32 B");

    std::map<std::string, std::string>::const_iterator it_p = s.cm.find("protect");
    const bool protect = (it_p != s.cm.end() && it_p->second == "1");
    const size_t user_offset = protect ? 1 : 0;

    std::vector<std::string> user_lines = read_lines(kv_get(s.cm, "keys_file"));
    std::vector<Signer> users;
    for (const std::string& line : user_lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) continue;
        Signer sg;
        if (MusigAggregator::make_signer(agg_ctx.ctx, sk, sg)) users.push_back(sg);
        secure_zero(sk, 32);
    }
    size_t n_user_leaves = leaves > user_offset ? leaves - user_offset : 0;
    n_user_leaves /= 2;
    if (leaf >= n_user_leaves || leaf >= users.size()) die("--leaf izvan granica");

    std::vector<std::vector<unsigned char>> scripts;
    if (protect) {
        unsigned char op_agg[32];
        if (!from_hex32(kv_get(s.cm, "op_agg"), op_agg)) die("op_agg nije 32 B");
        scripts.push_back(csv_checksig_script(op_agg, (uint32_t)std::stoul(kv_get(s.cm, "op_delay"))));
    }
    std::vector<unsigned char> claim_digest;
    for (size_t i = 0; i < n_user_leaves; i++) {
        unsigned char ux[32];
        secp256k1_xonly_pubkey_serialize(agg_ctx.ctx, ux, &users[i].xonly);
        uint64_t bal = 100000000ULL + 1500ULL * (i % 977);
        unsigned char digest[32];
        claim_digest_of(state_root, i, bal, digest);
        if (i == leaf) claim_digest.assign(digest, digest + 32);
        scripts.push_back(claim_leaf_script(digest, ux, chal_window));
        scripts.push_back(challenge_leaf_script(digest, challenger_x, 1));
    }

    TapScriptTree tree;
    tree.build(scripts);
    unsigned char root_check[32];
    tree.merkle_root(root_check);
    unsigned char claimed_root[32];
    if (!from_hex32(kv_get(s.cm, "script_root"), claimed_root)) die("script_root nije 32 B");
    if (std::memcmp(root_check, claimed_root, 32) != 0)
        die("rekonstruirano skriptno stablo ne odgovara commitmentu");

    // Dokaz je 48-bajtni preimage tvrdnje; SHA256(dokaz) mora dati claim_digest.
    std::vector<unsigned char> evidence(48, 0);
    {
        std::memcpy(evidence.data(), state_root, 32);
        for (int b = 0; b < 8; b++) evidence[32 + b] = (unsigned char)((uint64_t)leaf >> (8 * b));
        uint64_t bal = 100000000ULL + 1500ULL * (leaf % 977);
        for (int b = 0; b < 8; b++) evidence[40 + b] = (unsigned char)(bal >> (8 * b));
        if (arg_present(argc, argv, "--bad-evidence")) {
            evidence[0] ^= 0xFF;   // namjerno pokvaren dokaz
        }
    }
    unsigned char ev_digest[32];
    sha256(evidence.data(), evidence.size(), ev_digest);

    // challenge list je neparan (1) unutar para
    const size_t script_index = user_offset + 2 * leaf + 1;
    unsigned char leaf_hash[32];
    tapleaf_hash(scripts[script_index], leaf_hash);

    unsigned char sighash[32];
    sighash_taproot(s.tx, s.spent, 0, 0x00, 1, leaf_hash, sighash);

    unsigned char csk[32];
    if (!from_hex32(arg_value(argc, argv, "--challenger-key"), csk))
        die("--challenger-key je obavezan");
    Signer challenger;
    if (!MusigAggregator::make_signer(agg_ctx.ctx, csk, challenger)) die("neispravan --challenger-key");
    secure_zero(csk, 32);

    unsigned char sig[64];
    if (!schnorr_sign(agg_ctx.ctx, challenger, sighash, sig)) die("potpisivanje nije uspjelo");

    std::vector<unsigned char> path = tree.merkle_path(script_index);
    TaprootCommitment c;
    std::memcpy(c.internal, s.commitment.internal, 32);
    std::vector<unsigned char> cb = control_block(c, s.commitment.output_parity, path);

    s.tx.vin[0].witness.clear();
    s.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    s.tx.vin[0].witness.push_back(evidence);
    s.tx.vin[0].witness.push_back(scripts[script_index]);
    s.tx.vin[0].witness.push_back(cb);

    std::cout << "============ CHALLENGE SPEND (osporavanje izlaza) ============\n";
    std::cout << "Korisnik (leaf index)        : " << leaf << "\n";
    std::cout << "nSequence                    : " << s.tx.vin[0].sequence
              << "  (challenge CSV traži >= 1)\n";
    std::cout << "Claim digest (iz skripta)    : " << to_hex(claim_digest.data(), 32) << "\n";
    std::cout << "Dokaz (preimage, 48 B)       : " << to_hex(evidence) << "\n";
    std::cout << "SHA256(dokaz)                : " << to_hex(ev_digest, 32) << "\n";
    std::cout << "Dokaz odgovara digestu?      : "
              << (std::memcmp(ev_digest, claim_digest.data(), 32) == 0 ? "DA" : "NE — namjerno pokvaren")
              << "\n";
    std::cout << "Script                       : " << to_hex(scripts[script_index]) << "\n";
    std::cout << "Dubina dokaza                : " << path.size() / 32 << " (" << cb.size() << " B)\n";

    std::vector<unsigned char> raw = s.tx.serialize(true);
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    out << to_hex(raw) << "\n";
    out.close();
    std::cout << "Raw transakcija              : " << out_path << " (" << raw.size() << " B)\n";
    std::cout << "txid                         : " << s.tx.txid() << "\n";
    std::cout << "==============================================================\n";
    return 0;
}

// ================================================================ proof
static int cmd_proof(int argc, char** argv) {
    const std::string keys_path = arg_value(argc, argv, "--keys", "keys.txt");
    const std::string cm_path   = arg_value(argc, argv, "--commitment", "commitment.txt");
    const size_t index          = (size_t)std::stoul(arg_value(argc, argv, "--index", "0"));
    MusigAggregator ctx;
    auto cm = read_kv(cm_path);

    unsigned char state_root[32];
    if (!from_hex32(kv_get(cm, "state_root"), state_root)) die("state_root");

    std::vector<std::string> lines = read_lines(keys_path);
    std::vector<Signer> users;
    for (const std::string& line : lines) {
        unsigned char sk[32];
        if (!from_hex32(line, sk)) continue;
        Signer s; if (MusigAggregator::make_signer(ctx.ctx, sk, s)) users.push_back(s);
        secure_zero(sk, 32);
    }
    if (index >= users.size()) die("--index izvan granica");

    std::vector<unsigned char> leaves_bytes;
    for (size_t i = 0; i < users.size(); i++) {
        unsigned char payload[40];
        secp256k1_xonly_pubkey_serialize(ctx.ctx, payload, &users[i].xonly);
        uint64_t balance = 100000000ULL + 1500ULL * (i % 977);
        for (int b = 0; b < 8; b++) payload[32 + b] = (unsigned char)(balance >> (8 * b));
        unsigned char h[32];
        tagged_hash("BEC/state", payload, sizeof(payload), h);
        leaves_bytes.insert(leaves_bytes.end(), h, h + 32);
    }
    MerkleTree t;
    t.build(leaves_bytes);
    std::vector<unsigned char> proof = t.proof(index);
    bool ok = merkle_verify(&leaves_bytes[index * 32], proof.data(), proof.size(), index, state_root);

    std::cout << "=============== INCLUSION PROOF (state root) ===============\n";
    std::cout << "Korisnik (index)             : " << index << "\n";
    std::cout << "List (leaf hash)             : " << to_hex(&leaves_bytes[index * 32], 32) << "\n";
    std::cout << "Dubina dokaza                : " << proof.size() / 32 << " ("
              << proof.size() << " B)\n";
    std::cout << "State root                   : " << to_hex(state_root, 32) << "\n";
    std::cout << "Verifikacija                 : " << (ok ? "OK" : "FAIL") << "\n";
    std::cout << "Proof (hex)                  : " << to_hex(proof) << "\n";
    std::cout << "============================================================\n";
    return ok ? 0 : 2;
}

// ================================================================ genkeys
static int cmd_genkeys(int argc, char** argv) {
    const size_t n = (size_t)std::stoul(arg_value(argc, argv, "--count", "16"));
    const std::string out_path = arg_value(argc, argv, "--out", "keys.txt");
    MusigAggregator ctx;
    Rng rng;
    std::ofstream out(out_path);
    if (!out.good()) die("ne mogu pisati " + out_path);
    size_t made = 0;
    while (made < n) {
        unsigned char sk[32];
        rng.fill(sk, 32);
        if (!secp256k1_ec_seckey_verify(ctx.ctx, sk)) continue;
        out << to_hex(sk, 32) << "\n";
        secure_zero(sk, 32);
        made++;
    }
    out.close();
    std::cout << "[genkeys] " << made << " ključeva -> " << out_path << "\n";
    return 0;
}

// ================================================================ main
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << VERSION_STR << "\n\n"
                  << "Naredbe:\n"
                  << "  genkeys      --count N --out keys.txt\n"
                  << "  commit       --keys keys.txt --operators operators.txt --delay 10 --leaves 64\n"
                  << "               --hrp bcrt --out commitment.txt\n"
                  << "               [--protect] [--op-delay 288]   (NUMS internal key + operatorski CSV)\n"
                  << "               [--challenge --challenge-window 96 --challenger-key <hex>]\n"
                  << "  spend-keypath --commitment commitment.txt --txid <hex> --vout 0 --amount <sats>\n"
                  << "               --dest-script <hex> --fee <sats> --out keypath.hex\n"
                  << "  spend-scriptpath --commitment commitment.txt --txid <hex> --vout 0 --amount <sats>\n"
                  << "               --dest-script <hex> --fee <sats> --leaf K --sequence D --out scriptpath.hex\n"
                  << "  spend-op-exit --commitment commitment.txt --txid <hex> --vout 0 --amount <sats>\n"
                  << "               --dest-script <hex> --fee <sats> --sequence D --out opexit.hex\n"
                  << "  spend-challenge --commitment commitment.txt --txid <hex> --vout 0 --amount <sats>\n"
                  << "               --dest-script <hex> --fee <sats> --leaf K --challenger-key <hex>\n"
                  << "               [--bad-evidence] --out challenge.hex\n"
                  << "  proof        --keys keys.txt --commitment commitment.txt --index 7\n";
        return 0;
    }
    std::string cmd = argv[1];
    try {
        if (cmd == "genkeys")          return cmd_genkeys(argc, argv);
        if (cmd == "commit")           return cmd_commit(argc, argv);
        if (cmd == "spend-keypath")    return cmd_spend_keypath(argc, argv);
        if (cmd == "spend-scriptpath") return cmd_spend_scriptpath(argc, argv);
        if (cmd == "spend-op-exit")    return cmd_spend_op_exit(argc, argv);
        if (cmd == "spend-challenge")  return cmd_spend_challenge(argc, argv);
        if (cmd == "proof")            return cmd_proof(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Nepoznata naredba: " << cmd << "\n";
    return 1;
}
