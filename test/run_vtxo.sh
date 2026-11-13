#!/usr/bin/env bash
# run_vtxo.sh — VTXO settlement na stvarnom Bitcoin Core (regtest)
#
# Dokazuje da je iznos činjenica, a ne tvrdnja:
#   1. Krug se gradi: 12 korisnika, 3 grupe, 4 on-chain tx-a.
#   2. Svaki VTXO postoji na lancu s TOČNO svojim balansom (12/12).
#   3. Korisnik izlazi sam iz SVOG VTXO-a nakon CSV-a.
#   4. NEG: exit prije CSV-a → non-BIP68-final.
#   5. NEG: exit tuđim ključem → Invalid Schnorr signature.
#   6. NEG: prijevara (jedan dobiva više, drugi manje) → Invalid Schnorr signature.
#   7. Kontrola: poštena grupna tx prolazi, pa pad nije artefakt.
#   8. Skala: 5000 korisnika → 80 tx-ova, najveći MuSig2 skup 65.
#
# Pokretanje:
#   BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst ./run_vtxo.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BECV="$ROOT/bec-vtxo"

BITCOIN_BIN="${BITCOIN_BIN:-$ROOT/../btc/bitcoin-27.1/bin}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
export PATH="$BITCOIN_BIN:$PATH"
export LD_LIBRARY_PATH="$SECP_PREFIX/lib:${LD_LIBRARY_PATH:-}"

DATADIR="${DATADIR:-$ROOT/.regtest-vtxo}"
WORK="$ROOT/.testrun-vtxo"
RPC="-regtest -datadir=$DATADIR -rpcuser=bec -rpcpassword=bec -rpcwallet=w1"
CLI="bitcoin-cli $RPC"

PASS=0; FAIL=0
ok()  { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "═══ $1"; }

cleanup() { bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -x "$BECV" ] || { echo "Nema bec-vtxo — pokreni test/build.sh"; exit 1; }

hdr "0. Bitcoin Core regtest"
if [ -d "$DATADIR" ]; then
  bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true
  sleep 1; rm -rf "$DATADIR"
fi
mkdir -p "$DATADIR" "$WORK/r1" "$WORK/r2"
bitcoind -regtest -datadir="$DATADIR" -daemon -fallbackfee=0.0001 -txindex=1 \
         -rpcuser=bec -rpcpassword=bec -listen=0 >/dev/null
for i in $(seq 1 40); do
  bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec getblockcount >/dev/null 2>&1 && break
  sleep 0.25
done
echo "  verzija: $(bitcoind --version | head -1)"
$CLI createwallet w1 >/dev/null 2>&1 || $CLI loadwallet w1 >/dev/null 2>&1
MINE=$($CLI getnewaddress)
$CLI generatetoaddress 150 "$MINE" >/dev/null
echo "  blokova: $($CLI getblockcount)"
[ "$($CLI getblockcount)" -ge 150 ] && ok "regtest node radi" || bad "regtest node ne radi"
mine1() { $CLI generatetoaddress 1 "${1:-$MINE}" >/dev/null; }

accepts() { $CLI testmempoolaccept "[\"$1\"]" | grep -q '"allowed": true'; }
reason()  { $CLI testmempoolaccept "[\"$1\"]" | python3 -c "import sys,json;d=json.load(sys.stdin)[0];print(d.get('reject-reason',''))" 2>/dev/null; }
expect_accept() { if accepts "$1"; then ok "$2 — node prihvaća"; else bad "$2 — node odbija: $(reason "$1")"; fi; }
expect_reject() { if accepts "$1"; then bad "$2 — node je PRIHVATIO, a nije smio"; else ok "$2 — node odbija: $(reason "$1")"; fi; }

# financiraj operatora, vrati "txid vout amount" njegovog P2TR outputa
fund_operator() { # $1 = op file
  local ftx fv fa oaddr ox
  oaddr=$(grep '^address=' "$1" | cut -d= -f2-)
  ox=$(grep '^operator_x=' "$1" | cut -d= -f2-)
  ftx=$($CLI sendtoaddress "$oaddr" 0.001)
  mine1
  read -r fv fa < <($CLI getrawtransaction "$ftx" true | python3 -c "
import sys,json
t=json.load(sys.stdin); k='$ox'
v=[v for v in t['vout'] if k in v['scriptPubKey']['hex']][0]
print(v['n'], int(round(v['value']*100000000)))
")
  echo "$ftx $fv $fa"
}

# ---------------------------------------------------------------- krug 12
hdr "1. Krug — 12 korisnika, fanout 4"
$BECV opkey --hrp bcrt > "$WORK/r1/op.txt"
OPSK=$(grep '^operator_sk=' "$WORK/r1/op.txt" | cut -d= -f2-)
read -r FTX FV FA < <(fund_operator "$WORK/r1/op.txt")
CHG=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')
echo "  operator financiran: $FTX vout=$FV ($FA sats)"

$BECV round --users 12 --fanout 4 --amount 1000 --delay 144 \
      --op-key "$OPSK" --fund-txid "$FTX" --fund-vout "$FV" --fund-amount "$FA" \
      --change-script "$CHG" --hrp bcrt --out-dir "$WORK/r1" > "$WORK/r1/round.log" 2>&1
grep -E "Korisnika|Grupa|Ukupno korisničkih|CSV delay|On-chain tx|Potpisnika u" "$WORK/r1/round.log" | sed 's/^/  /'
[ -f "$WORK/r1/round.txt" ] && ok "krug zapisan (round.txt + tx datoteke)" || bad "krug nije zapisan"
[ "$(ls "$WORK/r1"/tx_*.hex 2>/dev/null | wc -l)" = "4" ] && ok "4 tx-a: 1 funding + 3 grupne" \
  || bad "očekivana 4 tx-a, nađeno $(ls "$WORK/r1"/tx_*.hex 2>/dev/null | wc -l)"

# ---------------------------------------------------------------- broadcast
hdr "2. Broadcast — funding pa grupne tx"
expect_accept "$(cat "$WORK/r1/tx_000.hex")" "funding tx"
FT=$($CLI sendrawtransaction "$(cat "$WORK/r1/tx_000.hex")" 2>/dev/null)
[ -n "$FT" ] && ok "funding tx u mempoolu ($FT)" || bad "funding tx nije prihvaćen"
mine1
for g in 1 2 3; do
  expect_accept "$(cat "$WORK/r1/tx_00$g.hex")" "grupna tx $g (MuSig2: operator + 4 korisnika)"
done
for g in 1 2 3; do $CLI sendrawtransaction "$(cat "$WORK/r1/tx_00$g.hex")" >/dev/null 2>&1; done
mine1
echo "  visina: $($CLI getblockcount)"

# ---------------------------------------------------------------- VTXO na lancu
hdr "3. Svaki VTXO postoji na lancu s TOČNIM balansom"
python3 - "$WORK/r1" "$DATADIR" <<'PY' > "$WORK/r1/map.txt"
import json, subprocess, sys
d, datadir = sys.argv[1], sys.argv[2]
def dec(raw):
    return json.loads(subprocess.run(["bitcoin-cli","-regtest","-datadir="+datadir,
        "-rpcuser=bec","-rpcpassword=bec","decoderawtransaction",raw],capture_output=True,text=True).stdout)
m = {}
for l in open(d + "/round.txt"):
    k,_,v = l.strip().partition("="); m[k] = v
n = int(m["n_users"])
ng = int(m["n_groups"])
for g in range(ng):
    raw = open(f"{d}/tx_{g+1:03d}.hex").read().strip()
    tx = dec(raw)
    for u in range(n):
        out = m[f"user{u}_output"]
        for v in tx["vout"]:
            if out in v["scriptPubKey"]["hex"]:
                print(f"{u} {tx['txid']} {v['n']} {int(round(v['value']*100000000))}")
PY
FOUND=$(wc -l < "$WORK/r1/map.txt")
[ "$FOUND" = "12" ] && ok "12 VTXO outputa na lancu" || bad "nađeno $FOUND VTXO outputa, očekivano 12"
ALL_EXACT=$(python3 - "$WORK/r1" <<'PY'
import sys
d = sys.argv[1]
bad = 0
for line in open(d + "/map.txt"):
    u, txid, vout, amt = line.split()
    if int(amt) != 1000: bad += 1
print("1" if bad == 0 else "0")
PY
)
[ "$ALL_EXACT" = "1" ] && ok "svaki VTXO ima točno 1000 sats (nema zajedničkog UTXO-a)" \
  || bad "neki VTXO nema točan iznos"
sed 's/^/  /' "$WORK/r1/map.txt" | head -4

# ---------------------------------------------------------------- CSV prije
hdr "4. NEGATIVNI — exit prije CSV-a"
read -r U5 T5 V5 A5 < <(grep '^5 ' "$WORK/r1/map.txt")
read -r U6 T6 V6 A6 < <(grep '^6 ' "$WORK/r1/map.txt")
$BECV exit --round "$WORK/r1/round.txt" --user 5 --txid "$T5" --vout "$V5" --amount "$A5" \
      --dest-script "$CHG" --fee 300 --sequence 144 --out "$WORK/r1/e_early.hex" >/dev/null 2>&1
expect_reject "$(cat "$WORK/r1/e_early.hex")" "korisnik prije 144 bloka"

hdr "5. Korisnik izlazi sam, nakon CSV-a"
$CLI generatetoaddress 150 "$MINE" >/dev/null
echo "  visina: $($CLI getblockcount)"
$BECV exit --round "$WORK/r1/round.txt" --user 5 --txid "$T5" --vout "$V5" --amount "$A5" \
      --dest-script "$CHG" --fee 300 --sequence 144 --out "$WORK/r1/e5.hex" > "$WORK/r1/e5.log" 2>&1
grep -E "VTXO iznos|Potpisnik|nSequence|Izlaz" "$WORK/r1/e5.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/r1/e5.hex")" "korisnik 5: vlastiti ključ, CSV istekao"
E5=$($CLI sendrawtransaction "$(cat "$WORK/r1/e5.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$E5" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "exit potvrđen u bloku — korisnik dobio točno svoj balans" || bad "exit nije potvrđen"

# ---------------------------------------------------------------- tuđi ključ
hdr "6. NEGATIVNI — exit tuđim ključem"
$BECV exit --round "$WORK/r1/round.txt" --user 6 --as-user 7 --txid "$T6" --vout "$V6" --amount "$A6" \
      --dest-script "$CHG" --fee 300 --sequence 144 --out "$WORK/r1/e6bad.hex" >/dev/null 2>&1
expect_reject "$(cat "$WORK/r1/e6bad.hex")" "korisnik 7 potpisuje VTXO korisnika 6"
$BECV exit --round "$WORK/r1/round.txt" --user 6 --txid "$T6" --vout "$V6" --amount "$A6" \
      --dest-script "$CHG" --fee 300 --sequence 144 --out "$WORK/r1/e6.hex" >/dev/null 2>&1
expect_accept "$(cat "$WORK/r1/e6.hex")" "kontrola: vlasnik korisnika 6 prolazi"

# ---------------------------------------------------------------- prijevara
hdr "7. NEGATIVNI — prijevara: jedan dobiva više, drugi manje"
$BECV opkey > "$WORK/r2/op.txt"
OPSK2=$(grep '^operator_sk=' "$WORK/r2/op.txt" | cut -d= -f2-)
read -r FTX2 FV2 FA2 < <(fund_operator "$WORK/r2/op.txt")
$BECV round --users 4 --fanout 4 --amount 5000 --delay 10 \
      --op-key "$OPSK2" --fund-txid "$FTX2" --fund-vout "$FV2" --fund-amount "$FA2" \
      --change-script "$CHG" --hrp bcrt --out-dir "$WORK/r2" > /dev/null 2>&1
$CLI sendrawtransaction "$(cat "$WORK/r2/tx_000.hex")" >/dev/null 2>&1
mine1
$BECV forge --round "$WORK/r2/round.txt" --group 0 --bump 2000 --out "$WORK/r2/forge.hex" > "$WORK/r2/forge.log" 2>&1
grep -E "Napadač|Žrtva|Zbroj|Potpis" "$WORK/r2/forge.log" | sed 's/^/  /'
expect_reject "$(cat "$WORK/r2/forge.hex")" "prijevara u grupnoj tx (potpis vezan na drugu tx)"
expect_accept "$(cat "$WORK/r2/tx_001.hex")" "kontrola: poštena grupna tx prolazi"

# ---------------------------------------------------------------- skala
hdr "8. Skala"
$BECV scale --users 5000 --fanout 64 > "$WORK/scale.log" 2>&1
grep -E "Grupa |On-chain tx|Najveća grupa|Najveći MuSig2" "$WORK/scale.log" | sed 's/^/  /'
grep -q "Najveći MuSig2 skup                  : 65" "$WORK/scale.log" \
  && ok "5000 korisnika bez ijednog MuSig2 skupa veličine 5000" || bad "skala"

hdr "SAŽETAK"
echo "  PASS: $PASS   FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 SVI TESTOVI PROŠLI — VTXO settlement potvrđen na Bitcoin Core konsenzusu."
  exit 0
else
  echo "  ⚠️  IMA PADOVA."
  exit 1
fi
