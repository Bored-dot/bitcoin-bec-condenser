#!/usr/bin/env bash
# run_l2.sh — L2 sloj (off-chain prijelazi, exit, konflikti) na stvarnom Bitcoin Core
#
# Dokazuje petlju koja od settlementa pravi protokol:
#   1. Genesis: VTXO iz kruga postaje L2 stanje.
#   2. Transfer A→B je pre-potpisan, valjan ODMAH, i NIJE broadcastan.
#   3. A ne može izaći prije CSV-a (non-BIP68-final).
#   4. Transfer se objavi → potvrdi u 1 bloku.
#   5. A nakon CSV-a pokuša izaći → VTXO je već potrošen (missing-inputs).
#   6. B izlazi iz svog novog VTXO-a — sam, bez operatora.
#   7. NEG: netko drugi potpisuje B-ov exit → Invalid Schnorr.
#   8. Konflikt: A dvaput potpiše isti VTXO → oba valjana, samo jedan preživi.
#   9. Revizija: dokaziv lanac i vlasništvo su ispravni.
#
# Pokretanje:
#   BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst ./run_l2.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BEC="$ROOT/bec"
BECV="$ROOT/bec-vtxo"
BECL="$ROOT/bec-l2"

BITCOIN_BIN="${BITCOIN_BIN:-$ROOT/../btc/bitcoin-27.1/bin}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
export PATH="$BITCOIN_BIN:$PATH"
export LD_LIBRARY_PATH="$SECP_PREFIX/lib:${LD_LIBRARY_PATH:-}"

DATADIR="${DATADIR:-$ROOT/.regtest-l2}"
WORK="$ROOT/.testrun-l2"
RPC="-regtest -datadir=$DATADIR -rpcuser=bec -rpcpassword=bec -rpcwallet=w1"
CLI="bitcoin-cli $RPC"

PASS=0; FAIL=0
ok()  { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "═══ $1"; }

cleanup() { bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

for b in "$BEC" "$BECV" "$BECL"; do
  [ -x "$b" ] || { echo "Nema $(basename "$b") — pokreni test/build.sh"; exit 1; }
done

hdr "0. Bitcoin Core regtest"
if [ -d "$DATADIR" ]; then
  bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true
  sleep 1; rm -rf "$DATADIR"
fi
mkdir -p "$DATADIR" "$WORK"
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

# ---------------------------------------------------------------- krug
hdr "1. Krug — 3 korisnika, VTXO-i na lancu"
$BECV opkey --hrp bcrt > "$WORK/op.txt"
OPSK=$(grep '^operator_sk=' "$WORK/op.txt" | cut -d= -f2-)
OADR=$(grep '^address=' "$WORK/op.txt" | cut -d= -f2-)
OX=$(grep '^operator_x=' "$WORK/op.txt" | cut -d= -f2-)

FTX=$($CLI sendtoaddress "$OADR" 0.001)
mine1
read -r FV FA < <($CLI getrawtransaction "$FTX" true | python3 -c "
import sys,json
t=json.load(sys.stdin); k='$OX'
v=[v for v in t['vout'] if k in v['scriptPubKey']['hex']][0]
print(v['n'], int(round(v['value']*100000000)))
")
CHG=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')

$BECV round --users 3 --fanout 3 --amount 20000 --delay 20 \
      --op-key "$OPSK" --fund-txid "$FTX" --fund-vout "$FV" --fund-amount "$FA" \
      --change-script "$CHG" --hrp bcrt --out-dir "$WORK" > "$WORK/round.log" 2>&1
grep -E "Korisnika|Grupa|CSV delay|On-chain tx" "$WORK/round.log" | sed 's/^/  /'
$CLI sendrawtransaction "$(cat "$WORK/tx_000.hex")" >/dev/null 2>&1
mine1
GTX=$($CLI sendrawtransaction "$(cat "$WORK/tx_001.hex")" 2>/dev/null)
mine1
[ -n "$GTX" ] && ok "krug potvrđen, VTXO-i postoje na lancu" || bad "krug nije potvrđen"
echo "  grupna tx: $GTX"

# ---------------------------------------------------------------- genesis
hdr "2. L2 genesis"
$BECL init --round "$WORK/round.txt" --user 0 --txid "$GTX" --vout 0 --out "$WORK/s0.txt" > "$WORK/init.log" 2>&1
grep -E "VTXO|Iznos|CSV delay|chain tip" "$WORK/init.log" | sed 's/^/  /'
[ -f "$WORK/s0.txt" ] && ok "početno stanje zapisano" || bad "stanje nije zapisano"
VID=$(grep '^v0_id=' "$WORK/s0.txt" | cut -d= -f2-)
[ -n "$VID" ] && ok "VTXO registriran u stanju ($VID)" || bad "VTXO nije u stanju"

# ---------------------------------------------------------------- transfer
hdr "3. Transfer A → B (pre-potpisan, NIJE broadcastan)"
$BEC genkeys --count 1 --out "$WORK/b.txt" >/dev/null
$BEC genkeys --count 1 --out "$WORK/c.txt" >/dev/null
BSK=$(cat "$WORK/b.txt"); CSK=$(cat "$WORK/c.txt")

cp "$WORK/s0.txt" "$WORK/s0_pre.txt"      # kopija prije prijenosa: A još ima ključ i stanje
$BECL transfer --state "$WORK/s0.txt" --vtxo "$VID" --to-sk "$BSK" --fee 1000 \
      --out "$WORK/t1.hex" > "$WORK/t1.log" 2>&1
grep -E "iz |u  |txid|potpis" "$WORK/t1.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/t1.hex")" "transfer tx je valjan ODMAH (key-path, bez CSV-a)"
NEW=$(grep '^v1_id=' "$WORK/s0.txt" | cut -d= -f2-)
[ -n "$NEW" ] && ok "novi VTXO upisan u stanje ($NEW)" || bad "novi VTXO nije upisan"
grep -q '^v0_spent=1' "$WORK/s0.txt" && ok "stari VTXO označen kao potrošen off-chain" || bad "stari VTXO nije označen"
$BECL show --state "$WORK/s0.txt" | grep -q '\[aktivan\]' && ok "B je vlasnik off-chain, bez ijedne on-chain transakcije" || bad "vlasništvo nije prešlo"

# ---------------------------------------------------------------- CSV
hdr "4. NEGATIVNI — A pokušava izaći prije CSV-a"
$BECL exit --state "$WORK/s0_pre.txt" --vtxo "$VID" --dest-script "$CHG" \
      --fee 1000 --sequence 20 --out "$WORK/e1.hex" >/dev/null 2>&1
expect_reject "$(cat "$WORK/e1.hex")" "A-ov exit prije 20 blokova"

hdr "5. Transfer kroz lanac — i A-ov exit postaje mrtav"
$CLI sendrawtransaction "$(cat "$WORK/t1.hex")" >/dev/null 2>&1 && mine1
echo "  visina: $($CLI getblockcount)"
$CLI generatetoaddress 25 "$MINE" >/dev/null
echo "  nakon CSV prozora: visina $($CLI getblockcount)"
$BECL exit --state "$WORK/s0_pre.txt" --vtxo "$VID" --dest-script "$CHG" \
      --fee 1000 --sequence 20 --out "$WORK/e2.hex" >/dev/null 2>&1
expect_reject "$(cat "$WORK/e2.hex")" "A-ov exit nakon CSV-a (VTXO potrošen transferom)"

# ---------------------------------------------------------------- B exit
hdr "6. B izlazi sam iz novog VTXO-a"
$BECL exit --state "$WORK/s0.txt" --vtxo "$NEW" --dest-script "$CHG" \
      --fee 1000 --sequence 20 --out "$WORK/eb.hex" > "$WORK/eb.log" 2>&1
grep -E "VTXO |nSequence|Izlaz" "$WORK/eb.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/eb.hex")" "B-ov unilateralni exit (bez operatora)"
EB=$($CLI sendrawtransaction "$(cat "$WORK/eb.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$EB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "B-ov exit potvrđen u bloku" || bad "B-ov exit nije potvrđen"

hdr "7. NEGATIVNI — netko drugi potpisuje B-ov exit"
# svjež VTXO (prethodni je potrošen u sekciji 6), i namjerno DRUGAČIJA fee
# da txid bude različit — inače bi test pao na "txn-already-known", ne na potpis
$BECL init --round "$WORK/round.txt" --user 1 --txid "$GTX" --vout 1 --out "$WORK/s0b.txt" >/dev/null
VID2=$(grep '^v0_id=' "$WORK/s0b.txt" | cut -d= -f2-)
$BECL transfer --state "$WORK/s0b.txt" --vtxo "$VID2" --to-sk "$BSK" --fee 1000 --out "$WORK/t1b.hex" >/dev/null 2>&1
NEWB=$(grep '^v1_id=' "$WORK/s0b.txt" | cut -d= -f2-)
# novi VTXO postaje stvaran na lancu tek kad se pre-potpisani transfer objavi
$CLI sendrawtransaction "$(cat "$WORK/t1b.hex")" >/dev/null 2>&1 && mine1
$CLI generatetoaddress 22 "$MINE" >/dev/null
$BECL exit --state "$WORK/s0b.txt" --vtxo "$NEWB" --as-sk "$CSK" --dest-script "$CHG" \
      --fee 1500 --sequence 20 --out "$WORK/ebbad.hex" >/dev/null 2>&1
expect_reject "$(cat "$WORK/ebbad.hex")" "tuđi ključ na B-ovom VTXO-u"
echo "  kontrola: isti iznos i fee, ISPRAVAN ključ mora proći"
$BECL exit --state "$WORK/s0b.txt" --vtxo "$NEWB" --dest-script "$CHG" \
      --fee 1500 --sequence 20 --out "$WORK/ebok.hex" >/dev/null 2>&1
expect_accept "$(cat "$WORK/ebok.hex")" "kontrola: vlasnikov potpis s istim fee prolazi"

# ---------------------------------------------------------------- konflikt
hdr "8. KONFLIKT — A dvaput potpiše isti VTXO"
$BECL init --round "$WORK/round.txt" --user 2 --txid "$GTX" --vout 2 --out "$WORK/s1.txt" >/dev/null
V1=$(grep '^v0_id=' "$WORK/s1.txt" | cut -d= -f2-)
$BECL conflict --state "$WORK/s1.txt" --vtxo "$V1" --to-sk-a "$BSK" --to-sk-b "$CSK" \
      --fee 1000 --out-a "$WORK/ca.hex" --out-b "$WORK/cb.hex" > "$WORK/cf.log" 2>&1
grep -E "VTXO |prijenos|isti outpoint|→" "$WORK/cf.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/ca.hex")" "prijenos 1 je valjan"
expect_accept "$(cat "$WORK/cb.hex")" "prijenos 2 je valjan (to JE dokaz prijevare)"
$CLI sendrawtransaction "$(cat "$WORK/ca.hex")" >/dev/null 2>&1 && mine1
expect_reject "$(cat "$WORK/cb.hex")" "prijenos 2 nakon što je prijenos 1 potvrđen"

# ---------------------------------------------------------------- revizija
hdr "9. Revizija dokazivog lanca"
$BECL audit --state "$WORK/s0.txt" > "$WORK/audit.log" 2>&1
grep -E "VTXO-a|potrošeno|aktivno|prijelaza|lanac|vlasništvo" "$WORK/audit.log" | sed 's/^/  /'
grep -q "lanac             : OK" "$WORK/audit.log" && ok "digest lanac je ispravan" || bad "digest lanac je pokvaren"
grep -q "vlasništvo        : OK" "$WORK/audit.log" && ok "nijedan VTXO nije potrošen dvaput" || bad "vlasništvo je pokvareno"
$BECL audit --state "$WORK/s0.txt" >/dev/null 2>&1 && ok "audit vraća exit 0 kad je sve ispravno" || bad "audit exit kod"

hdr "SAŽETAK"
echo "  PASS: $PASS   FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 SVI TESTOVI PROŠLI — L2 petlja potvrđena na Bitcoin Core konsenzusu."
  exit 0
else
  echo "  ⚠️  IMA PADOVA."
  exit 1
fi
