#!/usr/bin/env bash
# run_matrix.sh — test BitVM2 matrice skriptova na stvarnom Bitcoin Core (regtest)
#
# Dokazuje, na lancu:
#   1. Matrica se gradi: 37 gatea × 8 listova + timeout = 297 listova, dubina 9.
#   2. Prover dokazuje KONZISTENTAN gate (konzistentna kombinacija + njegov ključ).
#   3. To vrijedi i za zadnji gate (indeks 291 — ne-potencija dvojke).
#   4. Osporavatelj dokazuje NEKONZISTENTAN gate i preuzima bond, potvrđeno u bloku.
#   5. NEG: konzistentan list potpisan osporavateljevim ključem → odbijen.
#   6. NEG: nekonzistentan list potpisan proverovim ključem  → odbijen.
#   7. NEG: pogrešan preimage (ne hashira na commitment)     → OP_EQUALVERIFY pada.
#   8. NEG: timeout prije CSV-a → odbijen.
#   9. Timeout nakon CSV-a → prihvaćen i potvrđen.
#
# Pokretanje:
#   BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst ./run_matrix.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BEC="$ROOT/bec"
BECM="$ROOT/bec-matrix"

BITCOIN_BIN="${BITCOIN_BIN:-$ROOT/../btc/bitcoin-27.1/bin}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
export PATH="$BITCOIN_BIN:$PATH"
export LD_LIBRARY_PATH="$SECP_PREFIX/lib:${LD_LIBRARY_PATH:-}"

DATADIR="${DATADIR:-$ROOT/.regtest-matrix}"
WORK="$ROOT/.testrun-matrix"
RPC="-regtest -datadir=$DATADIR -rpcuser=bec -rpcpassword=bec -rpcwallet=w1"
CLI="bitcoin-cli $RPC"

PASS=0; FAIL=0
ok()  { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "═══ $1"; }

cleanup() { bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -x "$BECM" ] || { echo "Nema bec-matrix — pokreni test/build.sh"; exit 1; }
[ -x "$BEC" ]  || { echo "Nema bec — pokreni test/build.sh"; exit 1; }

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

expect_accept() {
  local r; r=$($CLI testmempoolaccept "[\"$1\"]")
  if echo "$r" | grep -q '"allowed": true'; then ok "$2 — node prihvaća"; else bad "$2 — node odbija: $r"; fi
}
expect_reject() {
  local r reason; r=$($CLI testmempoolaccept "[\"$1\"]")
  reason=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin)[0];print(d.get('reject-reason',''))" 2>/dev/null)
  if echo "$r" | grep -q '"allowed": false'; then ok "$2 — node odbija: $reason"
  else bad "$2 — node je PRIHVATIO, a nije smio"; fi
}

# ---------------------------------------------------------------- setup
hdr "1. Matrica skriptova — 8-bitni zbrajač"
$BEC genkeys --count 1 --out "$WORK/prover.txt" >/dev/null
$BEC genkeys --count 1 --out "$WORK/challenger.txt" >/dev/null
PK=$(cat "$WORK/prover.txt"); CK=$(cat "$WORK/challenger.txt")

$BECM build --bits 8 --csv 96 --prover-key "$PK" --challenger-key "$CK" \
      --hrp bcrt --out "$WORK/matrix.txt" > "$WORK/build.log" 2>&1
grep -E "Žica|Gatea|Listova ukupno|proverovi|osporavateljevi|Dubina skriptnog|bech32m" "$WORK/build.log" | sed 's/^/  /'
MADDR=$(grep '^address=' "$WORK/matrix.txt" | cut -d= -f2-)
NLEAVES=$(grep '^n_leaves=' "$WORK/matrix.txt" | cut -d= -f2-)
NGATES=$(grep '^n_gates=' "$WORK/matrix.txt" | cut -d= -f2-)
[ "$NLEAVES" = "297" ] && ok "297 listova (37 gatea × 8 + timeout)" || bad "broj listova je $NLEAVES, očekivano 297"
[ "$NGATES" = "37" ] && ok "37 gatea za 8-bitni zbrajač" || bad "broj gatea je $NGATES"

MDEST=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')

fund() { # → "txid vout"
  local t v
  t=$($CLI sendtoaddress "$MADDR" 0.01)
  mine1
  v=$($CLI getrawtransaction "$t" true | python3 -c "
import sys,json
t=json.load(sys.stdin)
key=open('$WORK/matrix.txt').read()
key=[l.split('=',1)[1].strip() for l in key.strip().split(chr(10)) if l.startswith('output=')][0]
for x in t['vout']:
    if key in x['scriptPubKey']['hex']:
        print(x['n'])
")
  echo "$t $v"
}

# ---------------------------------------------------------------- proverov put
hdr "2. Prover dokazuje KONZISTENTAN gate (gate 0, 200+100)"
read -r T1 V1 < <(fund)
echo "  funding: $T1 vout=$V1"
$BECM proof-ok --matrix "$WORK/matrix.txt" --gate 0 --a 200 --b 100 --txid "$T1" --vout "$V1" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --prover-key "$PK" --out "$WORK/ok0.hex" > "$WORK/ok0.log" 2>&1
grep -E "Gate |Otkriveno|Kombinacija|Indeks lista|Potpisnik" "$WORK/ok0.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/ok0.hex")" "prover: konzistentan gate + njegov ključ"
ID=$($CLI sendrawtransaction "$(cat "$WORK/ok0.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$ID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "dokaz konzistentnosti potvrđen u bloku" || bad "nije potvrđen"

# ---------------------------------------------------------------- zadnji gate
hdr "3. Zadnji gate (36) — indeks 291, ne-potencija dvojke"
read -r T2 V2 < <(fund)
$BECM proof-ok --matrix "$WORK/matrix.txt" --gate 36 --a 255 --b 1 --txid "$T2" --vout "$V2" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --prover-key "$PK" --out "$WORK/ok36.hex" > "$WORK/ok36.log" 2>&1
grep -E "Gate |Otkriveno|Indeks lista" "$WORK/ok36.log" | sed 's/^/  /'
echo "  255+1=256 → 8 bitova sume 0 + carry out 1"
expect_accept "$(cat "$WORK/ok36.hex")" "zadnji gate (carry out) konzistentan"
ID=$($CLI sendrawtransaction "$(cat "$WORK/ok36.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$ID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "zadnji gate potvrđen u bloku" || bad "zadnji gate nije potvrđen"

# ---------------------------------------------------------------- osporavateljev put
hdr "4. Osporavatelj dokazuje NEKONZISTENTAN gate i preuzima bond"
read -r T3 V3 < <(fund)
$BECM proof-bad --matrix "$WORK/matrix.txt" --gate 20 --a 200 --b 100 --txid "$T3" --vout "$V3" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --challenger-key "$CK" --out "$WORK/bad20.hex" > "$WORK/bad20.log" 2>&1
grep -E "Gate |Otkriveno|Kombinacija|Indeks lista|Potpisnik" "$WORK/bad20.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/bad20.hex")" "osporavatelj: nekonzistentan gate + njegov ključ"
ID=$($CLI sendrawtransaction "$(cat "$WORK/bad20.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$ID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "osporavatelj preuzeo bond (potvrđeno u bloku)" || bad "osporavanje nije potvrđeno"

# ---------------------------------------------------------------- negativni
hdr "5. NEGATIVNI — konzistentan list, potpisao OSPORAVATELJ"
read -r T4 V4 < <(fund)
$BECM proof-ok --matrix "$WORK/matrix.txt" --gate 0 --a 200 --b 100 --txid "$T4" --vout "$V4" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --challenger-key "$CK" --as-challenger --out "$WORK/n1.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/n1.hex")" "konzistentan list + pogrešan potpisnik"

hdr "6. NEGATIVNI — nekonzistentan list, potpisao PROVER"
read -r T5 V5 < <(fund)
$BECM proof-bad --matrix "$WORK/matrix.txt" --gate 20 --a 200 --b 100 --txid "$T5" --vout "$V5" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --prover-key "$PK" --as-prover --out "$WORK/n2.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/n2.hex")" "nekonzistentan list + pogrešan potpisnik"

hdr "7. NEGATIVNI — pogrešan preimage (ne hashira na commitment)"
read -r T6 V6 < <(fund)
$BECM proof-ok --matrix "$WORK/matrix.txt" --gate 0 --a 200 --b 100 --txid "$T6" --vout "$V6" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 1 \
      --prover-key "$PK" --wrong-preimage --out "$WORK/n3.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/n3.hex")" "pogrešan preimage"

# ---------------------------------------------------------------- timeout
hdr "8. NEGATIVNI — timeout prije CSV-a"
read -r T7 V7 < <(fund)
$BECM timeout --matrix "$WORK/matrix.txt" --txid "$T7" --vout "$V7" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 96 \
      --prover-key "$PK" --out "$WORK/to_early.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/to_early.hex")" "timeout prije CSV-a"

hdr "9. Timeout nakon CSV-a"
$CLI generatetoaddress 97 "$MINE" >/dev/null
echo "  visina: $($CLI getblockcount)"
$BECM timeout --matrix "$WORK/matrix.txt" --txid "$T7" --vout "$V7" \
      --amount 1000000 --dest-script "$MDEST" --fee 2000 --sequence 96 \
      --prover-key "$PK" --out "$WORK/to.hex" > "$WORK/to.log" 2>&1
grep -E "Indeks lista" "$WORK/to.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/to.hex")" "timeout nakon CSV-a"
ID=$($CLI sendrawtransaction "$(cat "$WORK/to.hex")" 2>/dev/null); mine1
[ "$($CLI gettransaction "$ID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')" -ge 1 ] \
  && ok "prover vratio bond nakon CSV-a (potvrđeno)" || bad "timeout nije potvrđen"

hdr "SAŽETAK"
echo "  PASS: $PASS   FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 SVI TESTOVI PROŠLI — matrica skriptova potvrđena na Bitcoin Core konsenzusu."
  exit 0
else
  echo "  ⚠️  IMA PADOVA."
  exit 1
fi
