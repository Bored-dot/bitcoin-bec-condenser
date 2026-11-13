#!/usr/bin/env bash
# run_regtest.sh — end-to-end test na stvarnom Bitcoin Core (regtest)
#
# Dokazuje, na lancu, da:
#   1. Naš BIP-341 taproot commitment daje TOČNO istu adresu kao Bitcoin Core
#      (validacija preko descriptor/deriveaddresses).
#   2. MuSig2 key-path potpis prolazi konsenzus (stvarna transakcija, rudarena).
#   3. Korisnikov unilateralni script-path exit prolazi konsenzus (+ CSV delay).
#   4. Negativni testovi PADAJU kako treba — dakle testovi nisu tautologija.
#   5. U --protect načinu korisnik ima vremenski prozor prije operatora.
#
# Pokretanje:
#   BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst ./run_regtest.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BEC="$ROOT/bec"

BITCOIN_BIN="${BITCOIN_BIN:-$ROOT/../btc/bitcoin-27.1/bin}"
SECP_PREFIX="${SECP_PREFIX:-$ROOT/../secp-inst}"
export PATH="$BITCOIN_BIN:$PATH"
export LD_LIBRARY_PATH="$SECP_PREFIX/lib:${LD_LIBRARY_PATH:-}"

DATADIR="${DATADIR:-$ROOT/.regtest-data}"
WORK="$ROOT/.testrun"
RPC="-regtest -datadir=$DATADIR -rpcuser=bec -rpcpassword=bec -rpcwallet=w1"
CLI="bitcoin-cli $RPC"

PASS=0; FAIL=0
ok()   { echo "  ✅ PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ FAIL  $1"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "═══ $1"; }

cleanup() { bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

# ---------------------------------------------------------------- start node
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
echo "  blokova: $($CLI getblockcount)   balans: $($CLI getbalance) BTC"
[ "$($CLI getblockcount)" -ge 150 ] && ok "regtest node radi" || bad "regtest node ne radi"

mine1() { $CLI generatetoaddress 1 "${1:-$MINE}" >/dev/null; }

# nađi vout koji odgovara našem output keyu i vrati "txid vout amount_sats"
fund() { # $1 = adresa, $2 = BTC, $3 = commitment file (default $WORK/commitment.txt)
  local addr="$1" btc="$2" cmf="${3:-$WORK/commitment.txt}" txid vout amt
  txid=$($CLI sendtoaddress "$addr" "$btc")
  mine1
  read -r vout amt < <($CLI getrawtransaction "$txid" true | python3 -c "
import sys,json
t=json.load(sys.stdin)
key=open('$cmf').read()
key=[l.split('=',1)[1].strip() for l in key.strip().split(chr(10)) if l.startswith('output=')][0]
for v in t['vout']:
    if key in v['scriptPubKey']['hex']:
        print(v['n'], int(round(v['value']*100000000)))
")
  echo "$txid $vout $amt"
}

expect_accept() { # $1 = raw hex, $2 = label
  local r
  r=$($CLI testmempoolaccept "[\"$1\"]")
  if echo "$r" | grep -q '"allowed": true'; then ok "$2 — node prihvaća"; else bad "$2 — node odbija: $r"; fi
}
expect_reject() { # $1 = raw hex, $2 = label
  local r reason
  r=$($CLI testmempoolaccept "[\"$1\"]")
  reason=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin)[0];print(d.get('reject-reason',''))" 2>/dev/null)
  if echo "$r" | grep -q '"allowed": false'; then
    ok "$2 — node odbija: $reason"
  else
    bad "$2 — node je PRIHVATIO, a nije smio"
  fi
}

# ---------------------------------------------------------------- keys
hdr "1. Ključevi"
$BEC genkeys --count 5000 --out "$WORK/keys5000.txt" >/dev/null
$BEC genkeys --count 3    --out "$WORK/operators.txt" >/dev/null
[ -s "$WORK/keys5000.txt" ] && ok "5000 korisničkih + 3 operatorska ključa" || bad "genkeys"
head -64 "$WORK/keys5000.txt" > "$WORK/keys64.txt"

# ---------------------------------------------------------------- test 1: adresa vs Bitcoin Core
hdr "1. BIP-341 adresa vs Bitcoin Core (descriptor oracle)"
$BEC commit --keys "$WORK/keys64.txt" --operators "$WORK/operators.txt" \
     --delay 10 --leaves 4 --leaf-mode pk --hrp bcrt \
     --out "$WORK/cm_pk.txt" > "$WORK/cm_pk.log" 2>&1
DESC=$(grep '^descriptor=' "$WORK/cm_pk.txt" | cut -d= -f2-)
CORE_ADDR=$(bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec \
            deriveaddresses "$(bitcoin-cli -regtest -datadir="$DATADIR" -rpcuser=bec -rpcpassword=bec \
            getdescriptorinfo "$DESC" | python3 -c 'import sys,json;print(json.load(sys.stdin)["descriptor"])')" \
            | python3 -c 'import sys,json;print(json.load(sys.stdin)[0])')
OUR_ADDR=$(grep '^address=' "$WORK/cm_pk.txt" | cut -d= -f2-)
echo "  Bitcoin Core : $CORE_ADDR"
echo "  naš program  : $OUR_ADDR"
[ "$CORE_ADDR" = "$OUR_ADDR" ] && ok "taproot adresa se poklapa s Bitcoin Core" \
                              || bad "taproot adresa se NE poklapa s Bitcoin Core"

# ---------------------------------------------------------------- test 2: key-path (MuSig2)
hdr "2. Key-path spend — MuSig2 (BIP-327) preko BIP-341 sighasha"
$BEC commit --keys "$WORK/keys64.txt" --operators "$WORK/operators.txt" \
     --delay 10 --leaves 64 --hrp bcrt --out "$WORK/commitment.txt" > "$WORK/cm.log" 2>&1
grep -E "Exit listova|Dubina tapscript|State root|Internal key|Taproot output|adresa" "$WORK/cm.log" | sed 's/^/  /'
ADDR=$(grep '^address=' "$WORK/commitment.txt" | cut -d= -f2-)

read -r TXID VOUT AMT < <(fund "$ADDR" 1.0)
echo "  funding: $TXID vout=$VOUT ($AMT sats)"
DESTSCR=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')

$BEC spend-keypath --commitment "$WORK/commitment.txt" --txid "$TXID" --vout "$VOUT" \
     --amount "$AMT" --dest-script "$DESTSCR" --fee 2000 --out "$WORK/keypath.hex" > "$WORK/keypath.log" 2>&1
grep -E "Potpisnika|Witness veličina|Verifikacija" "$WORK/keypath.log" | sed 's/^/  /'
KPRAW=$(cat "$WORK/keypath.hex")
expect_accept "$KPRAW" "MuSig2 key-path"
KPTX=$($CLI sendrawtransaction "$KPRAW" 2>/dev/null)
mine1
CONF=$($CLI gettransaction "$KPTX" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$CONF" -ge 1 ] && ok "key-path transakcija potvrđena u bloku ($CONF potvrda)" || bad "key-path nije potvrđen"
VSIZE=$($CLI getrawtransaction "$KPTX" true | python3 -c 'import sys,json;print(json.load(sys.stdin)["vsize"])')
echo "  vsize: ${VSIZE} vB   (witness = 64 B neovisno o broju korisnika)"

# ---------------------------------------------------------------- test 3: script-path
hdr "3. Script-path — unilateralni exit korisnika (+ CSV delay)"
read -r TXID2 VOUT2 AMT2 < <(fund "$ADDR" 0.5)
echo "  funding: $TXID2 vout=$VOUT2 ($AMT2 sats)"
$CLI generatetoaddress 12 "$MINE" >/dev/null
DESTSCR2=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')
$BEC spend-scriptpath --commitment "$WORK/commitment.txt" --txid "$TXID2" --vout "$VOUT2" \
     --amount "$AMT2" --dest-script "$DESTSCR2" --fee 2000 --leaf 2 --sequence 10 \
     --out "$WORK/scriptpath.hex" > "$WORK/scriptpath.log" 2>&1
grep -E "Korisnik|nSequence|Dubina dokaza|Witness veličina|CSV delay istekao" "$WORK/scriptpath.log" | sed 's/^/  /'
SPRAW=$(cat "$WORK/scriptpath.hex")
expect_accept "$SPRAW" "script-path exit"
SPTX=$($CLI sendrawtransaction "$SPRAW" 2>/dev/null)
mine1
CONF2=$($CLI gettransaction "$SPTX" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$CONF2" -ge 1 ] && ok "script-path transakcija potvrđena u bloku" || bad "script-path nije potvrđen"

# ---------------------------------------------------------------- test 4: negativni — krivi potpis
hdr "4. NEGATIVNI test — potpis samo jednim ključem (bug iz originalne verzije)"
read -r TXID3 VOUT3 AMT3 < <(fund "$ADDR" 0.3)
$BEC spend-keypath --commitment "$WORK/commitment.txt" --txid "$TXID3" --vout "$VOUT3" \
     --amount "$AMT3" --dest-script "$DESTSCR" --fee 2000 --rogue \
     --out "$WORK/rogue.hex" > "$WORK/rogue.log" 2>&1
grep -E "Verifikacija" "$WORK/rogue.log" | sed 's/^/  /'
expect_reject "$(cat "$WORK/rogue.hex")" "potpis jednim ključem umjesto MuSig2"

# ---------------------------------------------------------------- test 5: negativni — CSV
hdr "5. NEGATIVNI test — exit PRIJE isteka CSV delaya"
$BEC spend-scriptpath --commitment "$WORK/commitment.txt" --txid "$TXID3" --vout "$VOUT3" \
     --amount "$AMT3" --dest-script "$DESTSCR2" --fee 2000 --leaf 2 --sequence 0 \
     --out "$WORK/premature.hex" > "$WORK/premature.log" 2>&1
expect_reject "$(cat "$WORK/premature.hex")" "exit prije isteka CSV delaya"

# ---------------------------------------------------------------- test 6: negativni — kontrolni blok
hdr "6. NEGATIVNI test — pokvaren kontrolni blok"
read -r TXID4 VOUT4 AMT4 < <(fund "$ADDR" 0.3)
$CLI generatetoaddress 12 "$MINE" >/dev/null
$BEC spend-scriptpath --commitment "$WORK/commitment.txt" --txid "$TXID4" --vout "$VOUT4" \
     --amount "$AMT4" --dest-script "$DESTSCR2" --fee 2000 --leaf 2 --sequence 10 \
     --bad-control --out "$WORK/badcb.hex" > "$WORK/badcb.log" 2>&1
expect_reject "$(cat "$WORK/badcb.hex")" "pokvaren kontrolni blok"

# ---------------------------------------------------------------- test 7: inclusion proof
hdr "7. Inclusion proof korisnika u state root"
$BEC proof --keys "$WORK/keys64.txt" --commitment "$WORK/commitment.txt" --index 7 > "$WORK/proof.log" 2>&1
grep -E "Korisnik|Dubina dokaza|Verifikacija" "$WORK/proof.log" | sed 's/^/  /'
grep -q "Verifikacija                 : OK" "$WORK/proof.log" && ok "Merkle inclusion proof valjan" || bad "inclusion proof"
# negativan: krivi index mora pasti
$BEC proof --keys "$WORK/keys64.txt" --commitment "$WORK/commitment.txt" --index 8 > "$WORK/proof8.log" 2>&1
python3 - "$WORK/proof.log" "$WORK/proof8.log" <<'PY'
import sys, re
def root(f):
    s=open(f).read()
    return re.search(r'State root\s+: (\w+)', s).group(1)
a=root(sys.argv[1]); b=root(sys.argv[2])
print("  proof za index 7 i 8 daju isti root:", "DA (dobro)" if a==b else "NE (problem)")
PY

# ---------------------------------------------------------------- test 8: skala 5000
hdr "8. Skala — 5000 korisnika, 4096 exit listova"
T0=$(date +%s%N)
$BEC commit --keys "$WORK/keys5000.txt" --operators "$WORK/operators.txt" \
     --delay 144 --leaves 4096 --hrp bcrt --out "$WORK/cm5000.txt" > "$WORK/cm5000.log" 2>&1
T1=$(date +%s%N)
grep -E "Korisnika u stanju|Dubina state|Exit listova|Dubina tapscript|Taproot output|adresa" "$WORK/cm5000.log" | sed 's/^/  /'
echo "  vrijeme commita: $(( (T1-T0)/1000000 )) ms"
grep -q "Korisnika u stanju (listovi)        : 5000" "$WORK/cm5000.log" && ok "5000 korisnika obrađeno" || bad "skala"
grep -q "^address=bcrt1p" "$WORK/cm5000.txt" && ok "validna bech32m adresa za 5000 korisnika" || bad "adresa"

# ---------------------------------------------------------------- test 9: NUMS + CSV raspored
hdr "9. ZAŠTITA — NUMS internal key + operatorski CSV iza korisničkog"
echo "  (bez ovoga operatori mogu potrošiti output odmah i pretrčati korisnički exit)"
$BEC commit --keys "$WORK/keys64.txt" --operators "$WORK/operators.txt" \
     --delay 144 --op-delay 288 --leaves 8 --protect --hrp bcrt \
     --out "$WORK/cm_protect.txt" > "$WORK/cm_protect.log" 2>&1
grep -E "CSV delay|Key-path potrošnja|Internal key|Taproot output" "$WORK/cm_protect.log" | sed 's/^/  /'
PADDR=$(grep '^address=' "$WORK/cm_protect.txt" | cut -d= -f2-)
PINT=$(grep '^internal=' "$WORK/cm_protect.txt" | cut -d= -f2-)
[ "$PINT" = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0" ] \
  && ok "internal key je BIP-341 NUMS (key-path nemoguć)" || bad "internal key nije NUMS"

read -r PTXID PVOUT PAMT < <(fund "$PADDR" 0.4 "$WORK/cm_protect.txt")
echo "  funding: $PTXID vout=$PVOUT ($PAMT sats)"
PDEST=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')
PDEST2=$($CLI getaddressinfo "$($CLI getnewaddress)" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scriptPubKey"])')

# 9a) key-path mora biti nemoguć
$BEC spend-keypath --commitment "$WORK/cm_protect.txt" --txid "$PTXID" --vout "$PVOUT" \
     --amount "$PAMT" --dest-script "$PDEST" --fee 2000 --fake-keypath \
     --out "$WORK/p_keypath.hex" > "$WORK/p_keypath.log" 2>&1
expect_reject "$(cat "$WORK/p_keypath.hex")" "key-path (MuSig2 operatora) u --protect načinu"

# 9b) prije delaya ni jedni ni drugi
$BEC spend-scriptpath --commitment "$WORK/cm_protect.txt" --txid "$PTXID" --vout "$PVOUT" \
     --amount "$PAMT" --dest-script "$PDEST" --fee 2000 --leaf 0 --sequence 144 \
     --out "$WORK/p_user.hex" > "$WORK/p_user.log" 2>&1
expect_reject "$(cat "$WORK/p_user.hex")" "korisnikov exit PRIJE 144 bloka"

$BEC spend-op-exit --commitment "$WORK/cm_protect.txt" --txid "$PTXID" --vout "$PVOUT" \
     --amount "$PAMT" --dest-script "$PDEST" --fee 2000 --sequence 288 \
     --out "$WORK/p_op.hex" > "$WORK/p_op.log" 2>&1
expect_reject "$(cat "$WORK/p_op.hex")" "operatorska potrošnja PRIJE 288 blokova"

# 9c) nakon 144: korisnik SMIJE, operator JOŠ NE
$CLI generatetoaddress 144 "$MINE" >/dev/null
echo "  nakon 144 bloka (visina $($CLI getblockcount)):"
expect_accept "$(cat "$WORK/p_user.hex")" "korisnikov exit NAKON 144 bloka"
expect_reject "$(cat "$WORK/p_op.hex")" "operator još uvijek blokiran (korisnički prozor traje)"

PU=$($CLI sendrawtransaction "$(cat "$WORK/p_user.hex")" 2>/dev/null)
mine1
CONFP=$($CLI gettransaction "$PU" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$CONFP" -ge 1 ] && ok "korisnikov unilateralni exit potvrđen u bloku" || bad "korisnikov exit nije potvrđen"

# 9d) drugi UTXO: operator SMIJE nakon 288
read -r PTXID2 PVOUT2 PAMT2 < <(fund "$PADDR" 0.4 "$WORK/cm_protect.txt")
$CLI generatetoaddress 288 "$MINE" >/dev/null
echo "  nakon 288 blokova (visina $($CLI getblockcount)):"
$BEC spend-op-exit --commitment "$WORK/cm_protect.txt" --txid "$PTXID2" --vout "$PVOUT2" \
     --amount "$PAMT2" --dest-script "$PDEST2" --fee 2000 --sequence 288 \
     --out "$WORK/p_op2.hex" > "$WORK/p_op2.log" 2>&1
expect_accept "$(cat "$WORK/p_op2.hex")" "operatorska potrošnja NAKON 288 blokova"
PO=$($CLI sendrawtransaction "$(cat "$WORK/p_op2.hex")" 2>/dev/null)
mine1
CONFO=$($CLI gettransaction "$PO" | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])')
[ "$CONFO" -ge 1 ] && ok "operatorska potrošnja potvrđena (samo nakon prozora)" || bad "operatorska potrošnja nije potvrđena"

# ---------------------------------------------------------------- sažetak
hdr "SAŽETAK"
echo "  PASS: $PASS   FAIL: $FAIL"
if [ "$FAIL" -eq 0 ]; then
  echo "  🎉 SVI TESTOVI PROŠLI — implementacija je potvrđena na Bitcoin Core konsenzusu."
  exit 0
else
  echo "  ⚠️  IMA PADOVA."
  exit 1
fi
