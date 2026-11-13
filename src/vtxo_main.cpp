// vtxo_main.cpp — CLI za VTXO settlement (jedan output po korisniku)
//
//   opkey   generiraj operatorski ključ i ispiši adresu za financiranje
//   round   izgradi i potpiši krug: funding tx + grupne tx + po jedan VTXO
//   exit    korisnik unilateralno izlazi iz SVOG VTXO-a nakon CSV-a
//   forge   pokušaj prijevare: alternativna grupna tx s tuđim potpisom (mora pasti)
//   scale   plan za veliki broj korisnika (broj tx-ova, bajtova, potpisnika)
//
// Build: test/build.sh ga gradi kao `bec-vtxo`.

#include "vtxo_round.hpp"

#include <iostream>
#include <fstream>
#include <algorithm>

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

// učita krug iz manifesta + svih ključeva (za exit i forge)
static Round load_round(const std::string& path) {
    Round R;
    auto m = vtxo_read_kv(path);
    R.n_users     = vtxo_kv_sz(m, "n_users");
    R.fanout      = vtxo_kv_sz(m, "fanout");
    R.delay       = (uint32_t)vtxo_kv_sz(m, "delay");
    R.group_fee   = vtxo_kv_u64(m, "group_fee");
    R.funding_fee = vtxo_kv_u64(m, "funding_fee");
    R.hrp         = vtxo_kv(m, "hrp");
    R.fund_amount = vtxo_kv_u64(m, "fund_amount");
    R.fund_vout   = (uint32_t)vtxo_kv_sz(m, "fund_vout");

    // fund_txid je u manifestu u internom (little-endian) poretku
    if (!from_hex32(vtxo_kv(m, "fund_txid"), R.fund_txid)) die("manifest: fund_txid");

    std::vector<unsigned char> v;
    if (!from_hex(vtxo_kv(m, "change_script"), v)) die("manifest: change_script");
    R.op_change_script = v;
    if (!from_hex(vtxo_kv(m, "op_sk"), v) || v.size() != 32) die("manifest: op_sk");
    R.op_sk = v;

    R.user_sk.resize(R.n_users);
    R.amounts.resize(R.n_users);
    for (size_t i = 0; i < R.n_users; i++) {
        const std::string p = "user" + std::to_string(i) + "_";
        if (!from_hex(vtxo_kv(m, p + "sk"), v) || v.size() != 32) die("manifest: " + p + "sk");
        R.user_sk[i] = v;
        R.amounts[i] = vtxo_kv_u64(m, p + "amount");
    }

    R.build_keys();
    R.build_plan();
    return R;
}

// ================================================================ opkey
static int cmd_opkey(int argc, char** argv) {
    MusigAggregator agg;
    unsigned char sk[32];
    Rng rng; rng.fill(sk, 32);
    Signer s;
    if (!MusigAggregator::make_signer(agg.ctx, sk, s)) die("ključ");
    unsigned char x[32];
    secp256k1_xonly_pubkey_serialize(agg.ctx, x, &s.xonly);
    std::string addr;
    if (!taproot_address(arg_value(argc, argv, "--hrp", "bcrt"), x, addr)) die("bech32m");

    std::cout << "operator_sk=" << to_hex(sk, 32) << "\n"
              << "operator_x="  << to_hex(x, 32) << "\n"
              << "address="     << addr << "\n";
    secure_zero(sk, 32);
    return 0;
}

// ================================================================ round
static int cmd_round(int argc, char** argv) {
    Round R;
    R.n_users     = (size_t)std::stoul(arg_value(argc, argv, "--users", "12"));
    R.fanout      = (size_t)std::stoul(arg_value(argc, argv, "--fanout", "4"));
    R.delay       = (uint32_t)std::stoul(arg_value(argc, argv, "--delay", "144"));
    R.group_fee   = std::stoull(arg_value(argc, argv, "--group-fee", "400"));
    R.funding_fee = std::stoull(arg_value(argc, argv, "--funding-fee", "500"));
    R.hrp         = arg_value(argc, argv, "--hrp", "bcrt");
    const std::string dir = arg_value(argc, argv, "--out-dir", ".");
    R.fund_amount = std::stoull(arg_req(argc, argv, "--fund-amount"));
    R.fund_vout   = (uint32_t)std::stoul(arg_value(argc, argv, "--fund-vout", "0"));
    const uint64_t per = std::stoull(arg_value(argc, argv, "--amount", "1000"));
    if (!vtxo_txid_rev(arg_req(argc, argv, "--fund-txid"), R.fund_txid)) die("neispravan --fund-txid");
    if (!from_hex(arg_req(argc, argv, "--change-script"), R.op_change_script)) die("neispravan --change-script");
    if (R.fanout < 2) die("--fanout >= 2");

    unsigned char opsk[32];
    if (!from_hex32(arg_req(argc, argv, "--op-key"), opsk)) die("--op-key <64 hex>");
    R.op_sk.assign(opsk, opsk + 32);
    secure_zero(opsk, 32);

    Rng rng;
    R.user_sk.resize(R.n_users);
    R.amounts.assign(R.n_users, per);
    for (size_t i = 0; i < R.n_users; i++) {
        R.user_sk[i].assign(32, 0);
        rng.fill(R.user_sk[i].data(), 32);
    }

    R.build_keys();
    R.build_plan();
    R.build_funding();
    R.build_group_txs();
    R.sign_funding();
    R.sign_all_groups();

    // zapiši sve tx-ove: tx_000 = funding, tx_001.. = grupne
    std::vector<std::string> files;
    char nm[32];
    std::snprintf(nm, sizeof(nm), "tx_%03d.hex", 0);
    vtxo_write_hex(dir + "/" + nm, R.funding.serialize(true));
    files.push_back(nm);
    for (size_t g = 0; g < R.gtxs.size(); g++) {
        std::snprintf(nm, sizeof(nm), "tx_%03zu.hex", g + 1);
        vtxo_write_hex(dir + "/" + nm, R.gtxs[g].serialize(true));
        files.push_back(nm);
    }

    uint64_t total = 0;
    for (uint64_t a : R.amounts) total += a;
    size_t maxg = 0;
    for (const GroupPlan& g : R.groups) maxg = std::max(maxg, g.users.size());

    std::cout << "\n========== VTXO KRUG — jedan output po korisniku ==========\n";
    std::cout << "  Korisnika                            : " << R.n_users << "\n";
    std::cout << "  Grupa (fanout " << R.fanout << ")                      : " << R.groups.size() << "\n";
    std::cout << "  Ukupno korisničkih balansa           : " << total << " sats\n";
    std::cout << "  CSV delay za unilateralni exit       : " << R.delay << " blokova\n";
    std::cout << "  On-chain tx-ova                      : " << (1 + R.gtxs.size())
              << "  (1 funding + " << R.gtxs.size() << " grupnih)\n";
    std::cout << "  Potpisnika u najvećoj grupnoj tx     : " << (maxg + 1)
              << "  (operator + " << maxg << " korisnika)\n";
    std::cout << "\n  funding txid   : " << R.funding.txid() << "\n";
    std::cout << "  funding veličina: " << R.funding.serialize(true).size() << " B (uklj. witness)\n";
    std::cout << "\n  VTXO po korisniku (svaki output nosi TOČAN balans):\n";
    size_t shown = 0;
    for (size_t u = 0; u < R.n_users && shown < 4; u++, shown++) {
        std::string addr;
        taproot_address(R.hrp, R.vtxos[u].output, addr);
        std::cout << "    korisnik " << u << " : " << R.amounts[u] << " sats -> " << addr << "\n";
    }
    if (R.n_users > shown) std::cout << "    ... i još " << (R.n_users - shown) << "\n";

    std::ofstream mf(dir + "/round.txt");
    if (!mf.good()) die("ne mogu pisati round.txt");
    mf << "version=1\n"
       << "n_users=" << R.n_users << "\n"
       << "fanout=" << R.fanout << "\n"
       << "delay=" << R.delay << "\n"
       << "group_fee=" << R.group_fee << "\n"
       << "funding_fee=" << R.funding_fee << "\n"
       << "hrp=" << R.hrp << "\n"
       << "op_sk=" << to_hex(R.op_sk) << "\n"
       << "op_x=" << to_hex(R.op_x) << "\n"
       << "change_script=" << to_hex(R.op_change_script) << "\n"
       << "fund_txid=" << to_hex(R.fund_txid, 32) << "\n"
       << "fund_vout=" << R.fund_vout << "\n"
       << "fund_amount=" << R.fund_amount << "\n"
       << "funding_txid=" << R.funding.txid() << "\n"
       << "n_groups=" << R.groups.size() << "\n";
    for (size_t g = 0; g < R.groups.size(); g++)
        mf << "group" << g << "_total=" << (R.groups[g].total + R.group_fee) << "\n";
    for (size_t u = 0; u < R.n_users; u++) {
        const std::string p = "user" + std::to_string(u) + "_";
        mf << p << "sk=" << to_hex(R.user_sk[u]) << "\n"
           << p << "x=" << to_hex(R.ux(u), 32) << "\n"
           << p << "amount=" << R.amounts[u] << "\n"
           << p << "group=" << R.group_of(u) << "\n"
           << p << "vout=" << R.vout_of(u) << "\n"
           << p << "output=" << to_hex(R.vtxos[u].output, 32) << "\n"
           << p << "internal=" << to_hex(R.vtxos[u].internal, 32) << "\n"
           << p << "parity=" << R.vtxos[u].parity << "\n";
    }
    mf.close();

    std::cout << "\n[round] zapisano: round.txt + " << files.size() << " tx datoteka\n";
    std::cout << "===========================================================\n";
    return 0;
}

// ================================================================ exit
static int cmd_exit(int argc, char** argv) {
    Round R = load_round(arg_req(argc, argv, "--round"));
    const size_t user = (size_t)std::stoul(arg_req(argc, argv, "--user"));
    // --as-user namjerno potpisuje tuđim ključem (negativni test)
    const size_t who = arg_present(argc, argv, "--as-user")
                     ? (size_t)std::stoul(arg_value(argc, argv, "--as-user")) : user;
    if (user >= R.n_users || who >= R.n_users) die("--user izvan granica");

    Tx tx;
    tx.version = 2;
    TxIn in;
    if (!vtxo_txid_rev(arg_req(argc, argv, "--txid"), in.txid)) die("neispravan --txid");
    in.vout = (uint32_t)std::stoul(arg_req(argc, argv, "--vout"));
    in.sequence = (uint32_t)std::stoul(arg_value(argc, argv, "--sequence", std::to_string(R.delay)));
    tx.vin.push_back(in);

    const uint64_t amount = std::stoull(arg_req(argc, argv, "--amount"));
    const uint64_t fee = std::stoull(arg_value(argc, argv, "--fee", "1000"));
    if (fee >= amount) die("fee >= amount");

    std::vector<unsigned char> dest;
    if (!from_hex(arg_req(argc, argv, "--dest-script"), dest)) die("neispravan --dest-script");
    TxOut o;
    o.value = amount - fee;
    o.script = dest;
    tx.vout.push_back(o);

    std::vector<TxOut> spent(1);
    spent[0].value = amount;
    spent[0].script = p2tr_script(R.vtxos[user].output);

    unsigned char leaf_h[32];
    tapleaf_hash(R.vtxos[user].leaf, leaf_h);

    unsigned char sh[32];
    sighash_taproot(tx, spent, 0, 0x00, 1, leaf_h, sh);

    MusigAggregator agg;
    Signer signer;
    if (!MusigAggregator::make_signer(agg.ctx, R.user_sk[who].data(), signer)) die("ključ");
    unsigned char sig[64];
    if (!schnorr_sign(agg.ctx, signer, sh, sig)) die("potpis");

    TaprootCommitment c;
    std::memcpy(c.internal, R.vtxos[user].internal, 32);
    std::vector<unsigned char> cb = control_block(c, R.vtxos[user].parity, {});

    tx.vin[0].witness.clear();
    tx.vin[0].witness.push_back(std::vector<unsigned char>(sig, sig + 64));
    tx.vin[0].witness.push_back(R.vtxos[user].leaf);
    tx.vin[0].witness.push_back(cb);

    std::cout << "========== VTXO EXIT (korisnik " << user << ") ==========\n";
    std::cout << "  VTXO iznos            : " << amount << " sats  (točno njegov balans)\n";
    std::cout << "  Potpisnik             : korisnik " << who
              << (who == user ? "  (vlasnik)" : "  ← NIJE vlasnik") << "\n";
    std::cout << "  nSequence             : " << tx.vin[0].sequence
              << "  (CSV traži >= " << R.delay << ")\n";
    std::cout << "  Izlaz                 : " << o.value << " sats\n";
    std::cout << "  Witness               : " << tx.serialize(true).size() << " B\n";

    vtxo_write_hex(arg_req(argc, argv, "--out"), tx.serialize(true));
    std::cout << "  txid                  : " << tx.txid() << "\n";
    std::cout << "=========================================================\n";
    return 0;
}

// ================================================================ forge
// Alternativna grupna tx: jedan korisnik dobiva više, drugi manje.
// U witness ide ISPRAVAN potpis za poštenu tx — jer potpis za ovu ne postoji.
static int cmd_forge(int argc, char** argv) {
    Round R = load_round(arg_req(argc, argv, "--round"));
    R.build_funding();
    R.build_group_txs();

    const size_t g = (size_t)std::stoul(arg_value(argc, argv, "--group", "0"));
    const uint64_t bump = std::stoull(arg_value(argc, argv, "--bump", "1000"));
    if (g >= R.gtxs.size()) die("--group izvan granica");
    if (R.groups[g].users.size() < 2) die("grupa ima manje od 2 korisnika");
    if (bump >= R.amounts[R.groups[g].users.back()]) die("--bump prevelik");

    // pošteni potpis — ovaj potpis postoji samo za poštenu transakciju
    unsigned char honest_sig[64];
    sign_musig_keypath(R.group_signers(g), R.group_pks(g), nullptr,
                       R.gtxs[g], R.group_spent(g), 0, honest_sig);

    Tx evil = R.gtxs[g];
    evil.vin[0].witness.clear();
    evil.vout[0].value += bump;
    evil.vout[evil.vout.size() - 1].value -= bump;
    evil.vin[0].witness.push_back(std::vector<unsigned char>(honest_sig, honest_sig + 64));

    const size_t thief = R.groups[g].users.front();
    const size_t victim = R.groups[g].users.back();

    std::cout << "========== FORGE (pokušaj prijevare) ==========\n";
    std::cout << "  Grupa                 : " << g << "\n";
    std::cout << "  Napadač (korisnik " << thief << ") traži  : " << R.amounts[thief] + bump
              << " sats  (umjesto " << R.amounts[thief] << ")\n";
    std::cout << "  Žrtva   (korisnik " << victim << ") gubi   : " << bump << " sats\n";
    std::cout << "  Zbroj outputa         : " << R.groups[g].total << " sats  (nepromijenjen)\n";
    std::cout << "  Potpis                : pošteni 64 B, jer potpis za ovu tx NE POSTOJI\n";
    std::cout << "  Očekivano             : node odbija — Invalid Schnorr signature\n";

    vtxo_write_hex(arg_req(argc, argv, "--out"), evil.serialize(true));
    std::cout << "  txid                  : " << evil.txid() << "\n";
    std::cout << "================================================\n";
    return 0;
}

// ================================================================ scale
static int cmd_scale(int argc, char** argv) {
    const size_t n      = (size_t)std::stoul(arg_value(argc, argv, "--users", "5000"));
    const size_t fanout = (size_t)std::stoul(arg_value(argc, argv, "--fanout", "64"));
    const uint64_t amt  = std::stoull(arg_value(argc, argv, "--amount", "100000"));

    std::vector<uint64_t> amounts(n, amt);
    std::vector<GroupPlan> gs = plan_groups(amounts, fanout);

    const size_t out_bytes   = 43 + 8 + 1;                       // P2TR output + value + len
    const size_t inputs_part = 4 + 1 + (32 + 4 + 1 + 4);         // version, count, outpoint, scriptSig len, sequence
    const size_t funding_bytes = inputs_part + 1 + gs.size() * out_bytes + 1 * out_bytes + 4;
    const size_t witness_bytes = 1 + 1 + 64;                     // count, len, 64 B

    size_t max_group = 0;
    for (const GroupPlan& g : gs) max_group = std::max(max_group, g.users.size());

    uint64_t total_bytes = funding_bytes;
    for (const GroupPlan& g : gs)
        total_bytes += inputs_part + 1 + g.users.size() * out_bytes + 4 + witness_bytes;

    std::cout << "\n========== SKALA — " << n << " korisnika ==========\n";
    std::cout << "  Fanout po grupi                      : " << fanout << "\n";
    std::cout << "  Grupa                                : " << gs.size() << "\n";
    std::cout << "  On-chain tx-ova                      : " << (1 + gs.size()) << "\n";
    std::cout << "  Najveća grupa                        : " << max_group
              << " korisnika (" << (max_group + 1) << " potpisnika)\n";
    std::cout << "  Funding tx (procjena)                : " << funding_bytes << " B\n";
    std::cout << "  Ukupno on-chain (procjena)           : " << total_bytes << " B\n";
    std::cout << "  Po korisniku                         : " << (double)total_bytes / n << " B\n";
    std::cout << "  Najveći MuSig2 skup                  : " << (max_group + 1) << " potpisnika\n";
    std::cout << "  (nema MuSig2 skupa veličine N — to je ključna razlika)\n";
    std::cout << "=====================================================\n";
    return 0;
}

// ================================================================ main
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "bec-vtxo — VTXO settlement (jedan output po korisniku)\n\n"
                  << "  opkey  [--hrp bcrt]\n"
                  << "  round  --users N --fanout F --amount S --delay D\n"
                  << "         --op-key <hex> --fund-txid <hex> --fund-vout N --fund-amount S\n"
                  << "         --change-script <hex> [--group-fee S] [--out-dir .]\n"
                  << "  exit   --round round.txt --user I --txid <hex> --vout N --amount S\n"
                  << "         --dest-script <hex> --fee S [--sequence D] [--as-user J] --out exit.hex\n"
                  << "  forge  --round round.txt --group G --bump S --out forge.hex\n"
                  << "  scale  --users N --fanout F\n";
        return 0;
    }
    std::string cmd = argv[1];
    try {
        if (cmd == "opkey") return cmd_opkey(argc, argv);
        if (cmd == "round") return cmd_round(argc, argv);
        if (cmd == "exit")  return cmd_exit(argc, argv);
        if (cmd == "forge") return cmd_forge(argc, argv);
        if (cmd == "scale") return cmd_scale(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Nepoznata naredba: " << cmd << "\n";
    return 1;
}
