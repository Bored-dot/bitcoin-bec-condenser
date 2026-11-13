#!/usr/bin/env bash
# run_bitvm.sh — test BitVM jezgre na stvarnom Bitcoin Core (regtest)
#
# Dokazuje, na lancu:
#   1. Bond se gradi i commitment hashevi su u skriptu.
#   2. Kazna prolazi SAMO s oba preimagea istog bita (ekvivokacija dokazana).
#   3. Pogrešan preimage  → OP_EQUALVERIFY pada.
#   4. Samo jedan preimage → OP_EQUALVERIFY pada.
#   5. Ispravan dokaz, pogrešan potpisnik → Invalid Schnorr signature.
#   6. Proverov timeout prije CSV-a → odbijen.
#   7. Proverov timeout nakon CSV-a → prihvaćen i potvrđen.
#
# Pokretanje:
#   BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst ./run_bitvm.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BEC="$ROOT/bec"
BECBITVM="$ROOT/bec-bitvm"

BITCOIN_BIN="${BITCOIN_BIN:-$ROOT/../btc/bitcoin-27.1/bin}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
export PATH="$BITCOIN_BIN:$PATH"
export LD_LIBRARY_PATH="$SECP_PREFIX/lib:${LD_LIBRARY_PATH:-}"

DATADIR="${DATADIR:-$ROOT/.regtest-bitvm}"
WORK="$ROOT/.testrun-bitvm"
RPC="-regtest -datadir=$DATADIR -rpcuser=bec -rpcpassword=bec -rpcwallet=w1"
CLI="bitcoin-cli $RPC"

PASS=0; FAIL=0
ok()  { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "═══ $1"; }

cleanup() { bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

[ -x "$BECBITVM" ] || { echo "Nema bec-bitvm — pokreni test/build.sh"; exit 1; }
[ -x "$BEC" ]      || { echo "Nema bec — pokreni test/build.sh"; exit 1; }

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

# nađi vout koji odgovara bond output keyu
fund() { # $1 = adresa, $2 = BTC, $3 = bond file
  local addr="$1" btc="$2" bf="$3" txid vout amt
  txid=$($CLI sendtoaddress "$addr" "$btc")
  mine1
  read -r vout amt < <($CLI getrawtransaction "$txid" true | python3 -c "
import sys,json
t=json.load(sys.stdin)
key=open('$bf').read()
key=[l.split('=',1)[1].strip() for l in key.strip().split(chr(10)) if l.startswith('output=')][0]
for v in t['vout']:
    if key in v['scriptPubKey']['hex']:
        print(v['n'], int(round(v['value']*100000000)))
")
  echo "$txid $vout $amt"
}

expect_accept() {
  local r; r=$($CLI testmempoolaccept "[\"$1\"]")
  if echo "$r" | grep -q '"allowed": true'; then ok "$2 — node prihvaća"; else bad "$2 — node odbija: $r"; fi
}
expect_reject() {
  local r reason; r=$($CLI testmempoolaccept "[\"$1\"]")
  reason=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin)[0];print(d.get('reject-reason',''))" 2>/dev/null)
  if echo "$r" | grep -q '"allowed": false'; then
    ok "$2 — node odbija: $reason"
  else
    bad "$2 — node je PRIHVATIO, a nije smio"
  fi
}

# ---------------------------------------------------------------- setup
hdr "1. Bond"
$BEC genkeys --count 1 --out "$WORK/prover.txt" >/dev/null
$BEC genkeys --count 1 --out "$WORK/challenger.txt" >/dev/null
$BEC genkeys --count 1 --out "$WORK/wrong.txt" >/dev/null
BPK=$(cat "$WORK/prover.txt"); BCK=$(cat "$WORK/challenger.txt"); BWRONG=$(cat "$WORK/wrong.txt")

$BECBITVM bond --bits 8 --csv 96 --prover-key "$BPK" --challenger-key "$BCK" \
     --hrp bcrt --out "$WORK/bond.txt" > "$WORK/bond.log" 2>&1
grep -E "Bitova|Timeout CSV|Dubina skriptnog|Internal key|bech32m adresa" "$WORK/bond.log" | sed 's/^/  /'
BADDR=$(grep '^address=' "$WORK/bond.txt" | cut -d= -f2-)
[ -n "$BADDR" ] && ok "bond output izgrađen (8 penalty listova + 1 timeout)" || bad "bond se ne gradi"
grep -q '^h0=' "$WORK/bond.txt" && grep -q '^h1=' "$WORK/bond.txt" \
  && ok "commitment hashevi h0/h1 zapisani za svaki bit" || bad "commitment hashevi"

BDEST=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')

# ---------------------------------------------------------------- A) kazna s oba preimagea
hdr "2. Kazna — ekvivokacija dokazana (OBA preimagea)"
read -r BTX1 BV1 BA1 < <(fund "$BADDR" 0.01 "$WORK/bond.txt")
echo "  funding: $BTX1 vout=$BV1 ($BA1 sats)"
$BECBITVM penalty --bond "$WORK/bond.txt" --index 3 --txid "$BTX1" --vout "$BV1" \
     --amount "$BA1" --dest-script "$BDEST" --fee 2000 --sequence 1 \
     --challenger-key "$BCK" --out "$WORK/b_pen.hex" > "$WORK/b_pen.log" 2>&1
grep -E "Indeks bita|Dubina dokaza" "$WORK/b_pen.log" | sed 's/^/  /'
expect_accept "$(cat "$WORK/b_pen.hex")" "kazna s OBA preimagea"
BPTX=$($CLI sendrawtransaction "$(cat "$WORK/b_pen.hex")" 2>/dev/null)
mine1
BCONF=$($CLI gettransaction "$BPTX" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$BCONF" -ge 1 ] && ok "osporavatelj preuzeo bond (potvrđeno u bloku)" || bad "kazna nije potvrđena"

# ---------------------------------------------------------------- B) pogrešan preimage
hdr "3. NEGATIVNI — kazna s POGREŠNIM preimageom"
read -r BTX2 BV2 BA2 < <(fund "$BADDR" 0.01 "$WORK/bond.txt")
$BECBITVM penalty --bond "$WORK/bond.txt" --index 3 --txid "$BTX2" --vout "$BV2" \
     --amount "$BA2" --dest-script "$BDEST" --fee 2000 --sequence 1 \
     --challenger-key "$BCK" --bad-preimage --out "$WORK/b_bad.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/b_bad.hex")" "kazna s POGREŠNIM preimageom"

# ---------------------------------------------------------------- C) samo jedan preimage
hdr "4. NEGATIVNI — kazna sa SAMO JEDNIM preimageom"
read -r BTX3 BV3 BA3 < <(fund "$BADDR" 0.01 "$WORK/bond.txt")
$BECBITVM penalty --bond "$WORK/bond.txt" --index 3 --txid "$BTX3" --vout "$BV3" \
     --amount "$BA3" --dest-script "$BDEST" --fee 2000 --sequence 1 \
     --challenger-key "$BCK" --single-preimage --out "$WORK/b_one.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/b_one.hex")" "kazna sa SAMO JEDNIM preimageom"

# ---------------------------------------------------------------- D) pogrešan potpisnik
hdr "5. NEGATIVNI — ispravan dokaz, POGREŠAN potpisnik"
read -r BTX4 BV4 BA4 < <(fund "$BADDR" 0.01 "$WORK/bond.txt")
$BECBITVM penalty --bond "$WORK/bond.txt" --index 3 --txid "$BTX4" --vout "$BV4" \
     --amount "$BA4" --dest-script "$BDEST" --fee 2000 --sequence 1 \
     --challenger-key "$BWRONG" --out "$WORK/b_wrong.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/b_wrong.hex")" "kazna s pogrešnim potpisnikom"

# ---------------------------------------------------------------- E) timeout prije CSV-a
hdr "6. NEGATIVNI — proverov timeout PRIJE CSV-a"
$BECBITVM timeout --bond "$WORK/bond.txt" --txid "$BTX4" --vout "$BV4" \
     --amount "$BA4" --dest-script "$BDEST" --fee 2000 --sequence 96 \
     --prover-key "$BPK" --out "$WORK/b_to_early.hex" > /dev/null 2>&1
expect_reject "$(cat "$WORK/b_to_early.hex")" "timeout prije CSV-a"

# ---------------------------------------------------------------- F) timeout nakon CSV-a
hdr "7. Proverov timeout NAKON CSV-a"
$CLI generatetoaddress 97 "$MINE" >/dev/null
echo "  visina nakon CSV-a: $($CLI getblockcount)"
$BECBITVM timeout --bond "$WORK/bond.txt" --txid "$BTX4" --vout "$BV4" \
     --amount "$BA4" --dest-script "$BDEST" --fee 2000 --sequence 96 \
     --prover-key "$BPK" --out "$WORK/b_to.hex" > "$WORK/b_to.log" 2>&1
expect_accept "$(cat "$WORK/b_to.hex")" "timeout nakon CSV-a"
BTXID=$($CLI sendrawtransaction "$(cat "$WORK/b_to.hex")" 2>/dev/null)
mine1
BTCONF=$($CLI gettransaction "$BTXID" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$BTCONF" -ge 1 ] && ok "prover vratio bond nakon CSV-a (potvrđeno)" || bad "timeout nije potvrđen"

hdr "SAŽETAK"
echo "  PASS: $PASS   FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 SVI TESTOVI PROŠLI — BitVM jezgra potvrđena na Bitcoin Core konsenzusu."
  exit 0
else
  echo "  ⚠️  IMA PADOVA."
  exit 1
fi
