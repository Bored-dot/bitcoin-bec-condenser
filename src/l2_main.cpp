// l2_main.cpp — CLI za L2 sloj: off-chain prijelazi, unilateralni exit, konflikti
//
//   init      postavi početno stanje iz VTXO-a nastalog u krugu
//   transfer  pre-potpi A → B (NE broadcasta se)
//   exit      vlasnikov unilateralni exit nakon CSV-a
//   conflict  dvije proturječne pre-potpise istog VTXO-a (dokaz prijevare)
//   audit     provjeri dokaziv lanac i vlasništvo
//   show      ispiši stanje
//
// Build: test/build.sh ga gradi kao `bec-l2`.

#include "l2_state.hpp"

#include <iostream>
#include <fstream>

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
static std::string arg_req(int argc, char** argv, const std::string& n) {
    std::string v = arg_value(argc, argv, n);
    if (v.empty()) die("nedostaje " + n);
    return v;
}

static bool txid_rev(const std::string& hex, unsigned char out[32]) {
    unsigned char t[32];
    if (!from_hex32(hex, t)) return false;
    for (int i = 0; i < 32; i++) out[i] = t[31 - i];
    return true;
}

static void write_hex(const std::string& path, const std::vector<unsigned char>& raw) {
    std::ofstream o(path);
    if (!o.good()) die("ne mogu pisati " + path);
    o << to_hex(raw) << "\n";
}

// ================================================================ init
// Početno stanje = jedan VTXO iz kruga, s vlasnikom i njegovim exit listom.
static int cmd_init(int argc, char** argv) {
    const std::string round = arg_req(argc, argv, "--round");
    const size_t user = (size_t)std::stoul(arg_req(argc, argv, "--user"));
    const std::string txid_hex = arg_req(argc, argv, "--txid");
    const uint32_t vout = (uint32_t)std::stoul(arg_value(argc, argv, "--vout", "0"));
    const std::string out_path = arg_req(argc, argv, "--out");

    std::map<std::string, std::string> m;
    {
        std::ifstream f(round);
        if (!f.good()) die("ne mogu otvoriti " + round);
        std::string l;
        while (std::getline(f, l)) {
            while (!l.empty() && (l.back() == '\r' || l.back() == ' ')) l.pop_back();
            size_t eq = l.find('=');
            if (eq != std::string::npos) m[l.substr(0, eq)] = l.substr(eq + 1);
        }
    }
    auto get = [&](const std::string& k) -> std::string {
        auto it = m.find(k);
        if (it == m.end()) die("round.txt: nedostaje '" + k + "'");
        return it->second;
    };

    L2State s;
    s.delay = (uint32_t)std::stoul(get("delay"));
    s.hrp   = get("hrp");
    if (!from_hex(get("op_sk"), s.op_sk) || s.op_sk.size() != 32) die("round.txt: op_sk");
    if (!from_hex32(get("op_x"), s.op_x)) die("round.txt: op_x");

    const std::string p = "user" + std::to_string(user) + "_";
    L2Vtxo v;
    if (!txid_rev(txid_hex, v.txid)) die("neispravan --txid");
    v.vout   = vout;
    v.id     = txid_hex + ":" + std::to_string(vout);
    v.amount = std::stoull(get(p + "amount"));
    if (!from_hex32(get(p + "output"), v.output)) die("output");
    if (!from_hex32(get(p + "internal"), v.internal)) die("internal");
    v.parity = std::stoi(get(p + "parity"));
    if (!from_hex(get(p + "sk"), v.owner_sk) || v.owner_sk.size() != 32) die("owner sk");
    if (!from_hex32(get(p + "x"), v.owner_x)) die("owner x");

    // exit list se rekonstruira iz vlasnikovog ključa — isti koji je krug ugradio
    v.leaf = csv_checksig_script(v.owner_x, s.delay);

    s.vtxos.push_back(v);
    append_transition(s, "genesis", "-", v.id, v.amount, v.id);
    s.save(out_path);

    std::cout << "========== L2 GENESIS ==========\n";
    std::cout << "  VTXO                  : " << v.id << "\n";
    std::cout << "  Iznos                 : " << v.amount << " sats\n";
    std::cout << "  Vlasnik (xonly)       : " << to_hex(v.owner_x, 32) << "\n";
    std::cout << "  CSV delay             : " << s.delay << " blokova\n";
    std::cout << "  chain tip             : " << to_hex(s.chain.back().digest, 32) << "\n";
    std::cout << "=================================\n";
    return 0;
}

// ================================================================ zajedničko
// Izgradi transfer tx: troši VTXO key-pathom (MuSig2 operator+vlasnik) i
// stvara novi VTXO za primatelja. Transakcija se NE broadcasta.
struct TransferBuild {
    Tx tx;
    VtxoKeys nk;                 // novi VTXO (primatelja)
    std::string new_id;
    uint64_t new_amount = 0;
};

static TransferBuild build_transfer(const L2State& s, const L2Vtxo& v,
                                    const std::vector<unsigned char>& recip_sk,
                                    uint64_t fee) {
    MusigAggregator agg;
    unsigned char osk[32];
    std::memcpy(osk, s.op_sk.data(), 32);

    Signer op, owner, recip;
    if (!MusigAggregator::make_signer(agg.ctx, osk, op)) die("operatorov ključ");
    if (!MusigAggregator::make_signer(agg.ctx, v.owner_sk.data(), owner)) die("vlasnikov ključ");
    if (!MusigAggregator::make_signer(agg.ctx, recip_sk.data(), recip)) die("primateljev ključ");
    secure_zero(osk, 32);

    unsigned char rx[32];
    secp256k1_xonly_pubkey_serialize(agg.ctx, rx, &recip.xonly);

    // novi VTXO: internal = MuSig2(operator, primatelj), isti CSV delay
    std::vector<secp256k1_pubkey> npks = { op.pk, recip.pk };
    TransferBuild b;
    compute_vtxo_keys(agg.ctx, npks, rx, s.delay, b.nk);
    b.new_amount = v.amount - fee;

    Tx tx;
    tx.version = 2;
    TxIn in;
    std::memcpy(in.txid, v.txid, 32);
    in.vout = v.vout;
    in.sequence = 0xfffffffd;          // bez CSV-a: key-path, valjan odmah
    tx.vin.push_back(in);

    TxOut o;
    o.value = b.new_amount;
    o.script = p2tr_script(b.nk.output);
    tx.vout.push_back(o);
    b.tx = tx;
    b.new_id = tx.txid() + ":0";

    // stari VTXO je tweakan svojim exit listom → potpis mora ići kroz tweak
    unsigned char leaf_h[32];
    tapleaf_hash(v.leaf, leaf_h);
    TaprootCommitment c;
    std::memcpy(c.internal, v.internal, 32);
    tap_tweak(v.internal, leaf_h, c);

    std::vector<TxOut> spent(1);
    spent[0].value = v.amount;
    spent[0].script = p2tr_script(v.output);

    std::vector<Signer> signers = { op, owner };
    std::vector<secp256k1_pubkey> pks = { op.pk, owner.pk };
    unsigned char sig[64];
    sign_musig_keypath(signers, pks, c.tweak, b.tx, spent, 0, sig);
    b.tx.vin[0].witness.clear();
    b.tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    return b;
}

// ================================================================ transfer
static int cmd_transfer(int argc, char** argv) {
    const std::string sp = arg_req(argc, argv, "--state");
    L2State s = L2State::load(sp);
    const std::string id = arg_req(argc, argv, "--vtxo");
    const std::string out_path = arg_req(argc, argv, "--out");
    const uint64_t fee = std::stoull(arg_value(argc, argv, "--fee", "1000"));

    L2Vtxo* v = s.find_mut(id);
    if (!v) die("nema VTXO-a " + id);
    if (v->spent) die("VTXO je već potrošen: " + id);
    if (fee >= v->amount) die("fee >= iznos");

    std::vector<unsigned char> rsk;
    if (!from_hex(arg_req(argc, argv, "--to-sk"), rsk) || rsk.size() != 32) die("--to-sk <64 hex>");

    TransferBuild b = build_transfer(s, *v, rsk, fee);
    write_hex(out_path, b.tx.serialize(true));

    const std::string old_id = v->id;
    const uint64_t old_amount = v->amount;
    v->spent = true;

    L2Vtxo nv;
    nv.id = b.new_id;
    nv.vout = 0;
    {
        // txid u internom poretku = reverse prikazanog hexa
        unsigned char t[32];
        if (!from_hex32(b.tx.txid(), t)) die("txid");
        for (int i = 0; i < 32; i++) nv.txid[i] = t[31 - i];
    }
    nv.amount = b.new_amount;
    std::memcpy(nv.output, b.nk.output, 32);
    std::memcpy(nv.internal, b.nk.internal, 32);
    nv.parity = b.nk.parity;
    nv.leaf = b.nk.leaf;
    nv.owner_sk = rsk;
    {
        MusigAggregator agg;
        Signer r;
        if (!MusigAggregator::make_signer(agg.ctx, rsk.data(), r)) die("primateljev ključ");
        secp256k1_xonly_pubkey_serialize(agg.ctx, nv.owner_x, &r.xonly);
    }
    nv.spent = false;
    s.vtxos.push_back(nv);

    append_transition(s, "transfer", old_id, nv.id, nv.amount, b.tx.txid());
    s.save(sp);
    secure_zero(rsk.data(), rsk.size());

    std::cout << "========== L2 TRANSFER (pre-potpisan, NIJE broadcastan) ==========\n";
    std::cout << "  iz    : " << old_id << "  (" << old_amount << " sats)\n";
    std::cout << "  u     : " << nv.id << "  (" << nv.amount << " sats, fee " << fee << ")\n";
    std::cout << "  tx    : " << out_path << "  (" << b.tx.serialize(true).size() << " B)\n";
    std::cout << "  txid  : " << b.tx.txid() << "\n";
    std::cout << "  potpis: MuSig2(operator + vlasnik), key-path kroz taptweak\n";
    std::cout << "  stanje: stari VTXO označen kao potrošen, vlasništvo prešlo off-chain\n";
    std::cout << "  chain tip : " << to_hex(s.chain.back().digest, 32) << "\n";
    std::cout << "==================================================================\n";
    return 0;
}

// ================================================================ exit
static int cmd_exit(int argc, char** argv) {
    const std::string sp = arg_req(argc, argv, "--state");
    L2State s = L2State::load(sp);
    const std::string id = arg_req(argc, argv, "--vtxo");
    const std::string out_path = arg_req(argc, argv, "--out");
    const uint64_t fee = std::stoull(arg_value(argc, argv, "--fee", "1000"));

    const L2Vtxo* v = s.find(id);
    if (!v) die("nema VTXO-a " + id);
    if (v->spent) die("VTXO je već potrošen: " + id);

    std::vector<unsigned char> dest;
    if (!from_hex(arg_req(argc, argv, "--dest-script"), dest)) die("--dest-script");

    Tx tx;
    tx.version = 2;
    TxIn in;
    std::memcpy(in.txid, v->txid, 32);
    in.vout = v->vout;
    in.sequence = (uint32_t)std::stoul(arg_value(argc, argv, "--sequence", std::to_string(s.delay)));
    tx.vin.push_back(in);

    if (fee >= v->amount) die("fee >= iznos");
    TxOut o;
    o.value = v->amount - fee;
    o.script = dest;
    tx.vout.push_back(o);

    std::vector<TxOut> spent(1);
    spent[0].value = v->amount;
    spent[0].script = p2tr_script(v->output);

    unsigned char leaf_h[32];
    tapleaf_hash(v->leaf, leaf_h);
    unsigned char sh[32];
    sighash_taproot(tx, spent, 0, 0x00, 1, leaf_h, sh);

    // --as-sk namjerno potpisuje tuđim ključem (negativni test)
    std::vector<unsigned char> sk = v->owner_sk;
    if (arg_present(argc, argv, "--as-sk")) {
        std::vector<unsigned char> alt;
        if (!from_hex(arg_value(argc, argv, "--as-sk"), alt) || alt.size() != 32) die("--as-sk");
        sk = alt;
    }
    MusigAggregator agg;
    Signer signer;
    if (!MusigAggregator::make_signer(agg.ctx, sk.data(), signer)) die("ključ");
    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, signer, sh, sig)) die("potpis");

    TaprootCommitment c;
    std::memcpy(c.internal, v->internal, 32);
    std::vector<unsigned char> cb = control_block(c, v->parity, {});

    tx.vin[0].witness.clear();
    tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    tx.vin[0].witness.push_back(v->leaf);
    tx.vin[0].witness.push_back(cb);
    write_hex(out_path, tx.serialize(true));

    std::cout << "========== L2 EXIT (script-path, CSV " << s.delay << ") ==========\n";
    std::cout << "  VTXO          : " << v->id << "  (" << v->amount << " sats)\n";
    std::cout << "  nSequence     : " << tx.vin[0].sequence << "\n";
    std::cout << "  Izlaz         : " << o.value << " sats\n";
    std::cout << "  txid          : " << tx.txid() << "\n";
    std::cout << "  Napomena      : vrijedi tek " << s.delay << " blokova nakon nastanka VTXO-a\n";
    std::cout << "==================================================================\n";
    return 0;
}

// ================================================================ conflict
// Dvije proturječne pre-potpise istog VTXO-a. Obje su kriptografski valjane —
// to je dokaz prijevare. Lanac može potvrditi samo jednu.
static int cmd_conflict(int argc, char** argv) {
    const std::string sp = arg_req(argc, argv, "--state");
    L2State s = L2State::load(sp);
    const std::string id = arg_req(argc, argv, "--vtxo");
    const std::string out_a = arg_req(argc, argv, "--out-a");
    const std::string out_b = arg_req(argc, argv, "--out-b");
    const uint64_t fee = std::stoull(arg_value(argc, argv, "--fee", "1000"));

    const L2Vtxo* v = s.find(id);
    if (!v) die("nema VTXO-a " + id);
    if (v->spent) die("VTXO je već potrošen: " + id);

    std::vector<unsigned char> ska, skb;
    if (!from_hex(arg_req(argc, argv, "--to-sk-a"), ska) || ska.size() != 32) die("--to-sk-a");
    if (!from_hex(arg_req(argc, argv, "--to-sk-b"), skb) || skb.size() != 32) die("--to-sk-b");

    TransferBuild a = build_transfer(s, *v, ska, fee);
    TransferBuild b = build_transfer(s, *v, skb, fee);
    write_hex(out_a, a.tx.serialize(true));
    write_hex(out_b, b.tx.serialize(true));

    std::cout << "========== L2 KONFLIKT (A potpisuje isti VTXO dvaput) ==========\n";
    std::cout << "  VTXO              : " << v->id << "  (" << v->amount << " sats)\n";
    std::cout << "  prijenos 1        : " << a.tx.txid() << "\n";
    std::cout << "  prijenos 2        : " << b.tx.txid() << "\n";
    std::cout << "  isti outpoint     : " << v->id << " u obje transakcije\n";
    std::cout << "  oba potpisa       : valjana (MuSig2 operator + A)\n";
    std::cout << "  → to je dokaz da je A dvaput potpisao isti VTXO\n";
    std::cout << "  → lanac može potvrditi SAMO jednu; druga je mrtva\n";
    std::cout << "================================================================\n";
    return 0;
}

// ================================================================ audit
static int cmd_audit(int argc, char** argv) {
    L2State s = L2State::load(arg_req(argc, argv, "--state"));
    AuditResult r = audit(s);

    std::cout << "========== L2 AUDIT ==========\n";
    std::cout << "  VTXO-a ukupno     : " << r.n_vtxos << "\n";
    std::cout << "  potrošeno         : " << r.n_spent << "\n";
    std::cout << "  aktivno           : " << r.n_unspent << "  (" << r.total_unspent << " sats)\n";
    std::cout << "  prijelaza         : " << s.chain.size() << "\n";
    std::cout << "  chain tip         : " << to_hex(r.tip, 32) << "\n";
    std::cout << "  lanac             : " << (r.chain_ok ? "OK (svaki digest odgovara prethodnom)" : "POKVAREN") << "\n";
    std::cout << "  vlasništvo        : " << (r.ownership_ok ? "OK (nijedan VTXO nije potrošen dvaput)" : "POKVARENO") << "\n";
    if (!r.err.empty()) std::cout << "  greška            : " << r.err << "\n";
    std::cout << "==============================\n";
    return (r.chain_ok && r.ownership_ok) ? 0 : 1;
}

// ================================================================ show
static int cmd_show(int argc, char** argv) {
    L2State s = L2State::load(arg_req(argc, argv, "--state"));
    std::cout << "========== L2 STANJE ==========\n";
    std::cout << "  CSV delay : " << s.delay << " blokova\n\n";
    for (const L2Vtxo& v : s.vtxos) {
        std::cout << "  " << (v.spent ? "[potrošen] " : "[aktivan]  ") << v.id << "\n"
                  << "      iznos   : " << v.amount << " sats\n"
                  << "      vlasnik : " << to_hex(v.owner_x, 32) << "\n";
    }
    std::cout << "\n  povijest:\n";
    for (const L2Transition& t : s.chain)
        std::cout << "    " << t.kind << "  " << t.from << " → " << t.to
                  << "  (" << t.amount << " sats)\n";
    std::cout << "===============================\n";
    return 0;
}

// ================================================================ main
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "bec-l2 — L2 sloj: off-chain prijelazi, exit, konflikti\n\n"
                  << "  init      --round round.txt --user I --txid <hex> --vout N --out state.txt\n"
                  << "  transfer  --state state.txt --vtxo <id> --to-sk <hex> [--fee S] --out tx.hex\n"
                  << "  exit      --state state.txt --vtxo <id> --dest-script <hex> [--fee S]\n"
                  << "            [--sequence D] [--as-sk <hex>] --out exit.hex\n"
                  << "  conflict  --state state.txt --vtxo <id> --to-sk-a <hex> --to-sk-b <hex>\n"
                  << "            [--fee S] --out-a a.hex --out-b b.hex\n"
                  << "  audit     --state state.txt\n"
                  << "  show      --state state.txt\n";
        return 0;
    }
    std::string cmd = argv[1];
    try {
        if (cmd == "init")     return cmd_init(argc, argv);
        if (cmd == "transfer") return cmd_transfer(argc, argv);
        if (cmd == "exit")     return cmd_exit(argc, argv);
        if (cmd == "conflict") return cmd_conflict(argc, argv);
        if (cmd == "audit")    return cmd_audit(argc, argv);
        if (cmd == "show")     return cmd_show(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Nepoznata naredba: " << cmd << "\n";
    return 1;
}
