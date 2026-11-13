# Bitcoin BEC Condenser — VTXO settlement + L2 prijelazi

MuSig2 (BIP-327) + Taproot (BIP-341) settlement za L2 stanje, **testirano na Bitcoin Core konsenzusu**.

Ovaj projekt je prošao kroz četiri arhitekture i README to ne skriva:

1. **Simulacija** (originalna verzija) — lažni hash, potpis jednim ključem, "covenant verified"
   koji ništa nije provjeravao. Uklonjeno.
2. **Jedan UTXO + exit listovi** — pravi MuSig2 i Taproot, ali sa strukturnim problemom:
   skripta ne vidi iznos, pa korisnik koji izađe podigne cijeli UTXO.
3. **VTXO — jedan output po korisniku** — iznos nije tvrdnja u skripti, nego činjenica
   na lancu.
4. **L2 sloj — prijelazi stanja** — vrijednost prelazi od A do B pre-potpisanom
   transakcijom koja se ne broadcasta, a konflikte rješava konsenzus.

Sve u ovom repou potvrđeno je stvarnim transakcijama u Bitcoin Core regtestu — ne ispisom u terminalu.

---

## Rezultat testova

```
════════════════════════════════════════════════════════════════
  test/run_regtest.sh   MuSig2 / Taproot / exiti / challenge      28/28
  test/run_bitvm.sh     BitVM jezgra (bit-commitment bond)         11/11
  test/run_matrix.sh    BitVM2 matrica skriptova (8-bit zbrajač)   15/15
  test/run_vtxo.sh      VTXO settlement                            18/18
  test/run_l2.sh        L2 prijelazi, exit, konflikti              20/20
────────────────────────────────────────────────────────────────
  UKUPNO: 92 provjere, 17 negativnih
════════════════════════════════════════════════════════════════
```

Negativni testovi su namjerno tu: test koji uvijek prolazi ne dokazuje ništa.
Svaki pad nosi **točnu konsenzus grešku koju Bitcoin Core stvarno vraća**.

Detaljni rezultati: `test/expected_output*.txt`.

---

## Zašto je model promijenjen

**Skripta ne vidi iznose.** Tapscript izvršava uvjete nad podacima koje mu witness preda;
nema pristup outputima transakcije koja ga troši. Zato nijedan skript ne može provjeriti
*"odgovara li ovaj izlaz mom balansu"*.

Iz toga slijedi da model s **jednim zajedničkim UTXO-om** ima posljedicu koju treba izgovoriti:
korisnik koji izađe podigne **cijeli UTXO**. Pošten izlaz i prijevara su u tom trenutku
ekonomski identični — i jedan i drugi unište tuđa sredstva.

Challenge/response to čini *kažnjivim*, ali ne i *nemogućim*: digest je u skriptu, ali skript
ga samo `OP_DROP`-a. Lanac provjerava *"osporavatelj zna ista 48 bajta"*, ne *"iznos je točan"*.

**Rješenje ne treba covenant.** Ako nema zajedničkog UTXO-a, problem iznosa prestaje
postojati — jer se iznos ne provjerava, nego **upisuje**. To je VTXO model.

---

## VTXO — jedan output po korisniku

```
  funding tx  (operator plaća)
       │
       ├── grupni output 0  = zbroj balansa grupe 0    ┐
       ├── grupni output 1  = zbroj balansa grupe 1    │  ključ: MuSig2(operator + svi u grupi)
       └── grupni output 2  = zbroj balansa grupe 2    ┘  → nitko sam ne može potrošiti
                   │
                   │  grupna tx (pre-potpisana od SVIm u grupi + operator)
                   ▼
       ┌───────────┬───────────┬───────────┬───────────┐
    VTXO 0      VTXO 1      VTXO 2      VTXO 3        svaki = TOČNO svoj balans
       │
       └─ internal key = MuSig2(operator, korisnik)
          leaf         = <delay> CSV DROP <korisnik> CHECKSIG
```

Dvije putanje po VTXO-u:

| putanja | što treba | kad |
|---|---|---|
| **key-path** | MuSig2(operator, korisnik) — oba potpisa | kooperativno, bilo kad |
| **script-path** | samo korisnikov potpis, nakon CSV-a | unilateralni exit, bez operatora |

**Zašto je ovo sigurno bez ijedne pretpostavke o promatraču:**

- Operator **ne može** uzeti VTXO — key-path traži i korisnikov potpis.
- Korisnik **ne može** uzeti tuđi VTXO — drugi ključ, drugi output.
- Korisnik **ne može** uzeti više od svog balansa — toliki output je jedini koji postoji.
- Nema watchtowera za sigurnost VTXO-a: korisnik izlazi sam, bez da ikoga čeka.

### Zašto grupna tx ne može biti lažna

Grupni output traži **MuSig2(operator + svi u grupi)**. Grupnu tx potpisuju svi.
Parcijalni MuSig2 potpis je vezan na **jedan** sighash — ne može se prenijeti na drugu
transakciju. Tko odbije potpisati izmijenjenu tx, ta tx nikad neće imati valjan potpis,
jer drugi potpis matematički ne postoji.

Provjereno (`test/run_vtxo.sh`, sekcija 7):

```
Napadač (korisnik 0) traži  : 7000 sats (umjesto 5000)
Žrtva   (korisnik 3) gubi   : 2000 sats
Zbroj outputa               : 20000 sats (nepromijenjen)
Potpis                      : pošteni 64 B, jer potpis za ovu tx NE POSTOJI
→ node odbija: Invalid Schnorr signature
→ kontrola: poštena grupna tx prolazi u istom trenutku
```

### Skala

Za 5000 korisnika, fanout 64: **79 grupa, 80 on-chain tx-ova, 273 533 B, 54.7 B po
korisniku, najveći MuSig2 skup 65 potpisnika.**

Nema ijednog skupa veličine 5000 — dakle nema scenarija u kojem jedan offline korisnik
zamrzne sva sredstva.

---

## L2 sloj — prijelazi stanja

VTXO settlement rješava *koliko kome pripada na lancu*. Ne rješava *kako vrijednost prelazi
od A do B bez on-chain transakcije*. To je ovaj sloj, i on zatvara petlju.

### Transfer je pre-potpisana transakcija koja se ne objavljuje

```
A prenosi B-u:
   tx:  VTXO(A) ──key-path MuSig2(op, A), bez CSV-a──► VTXO(B)

   · potpisuju operator i A        → valjana odmah
   · NE broadcasta se              → ostaje off-chain
   · B je vlasnik u stanju         → njegov ključ, njegov exit list
```

### Zašto A ne može uzeti i jedno i drugo

Mehanizam je vremenski, ne kriptografski:

| | valjan od | potvrđuje se |
|---|---|---|
| **transfer tx** (key-path, bez CSV-a) | odmah | 1 blok |
| **A-ov exit** (script-path, CSV D) | D blokova nakon nastanka VTXO-a | nakon toga |

A **mora** čekati D blokova da bi uopće dobio pravo na exit. Transfer je valjan u prvoj
sekundi. Dakle operator ili B imaju D blokova prednosti da objave transfer prije nego A
uopće dođe do prava na izlaz. Provjereno:

```
A-ov exit prije CSV-a (20 blokova)          → non-BIP68-final
transfer tx, ista sekunda                   → prihvaćen, potvrđen u 1 bloku
A-ov exit nakon CSV-a                       → missing-inputs (VTXO je potrošen)
```

Treći red je poanta: kad A konačno dobije pravo na exit, **nema što trošiti**.

### B ne treba operatora

Ako operator nestane, B ima pre-potpisanu transakciju i može je objaviti sam. Time dobiva
VTXO na lancu, pa izlazi nakon CSV-a svojim ključem. Provjereno: B-ov unilateralni exit
prolazi bez ijednog operatorovog potpisa u toj transakciji.

### Konflikt rješava konsenzus

Ako A pokuša prenijeti isti VTXO i B-u i C-u, nastaju dvije kriptografski valjane
transakcije koje troše **isti outpoint**:

```
prijenos 1 → valjan
prijenos 2 → valjan
prijenos 1 potvrđen u bloku
prijenos 2 → missing-inputs   (mrtav, zauvijek)
```

Dvije stvari su time istovremeno istinite:

1. **Prijevara je dokaziva.** B i C zajedno imaju dva potpisa na isti outpoint — to je
   neporeciv dokaz da je A dvaput potpisao.
2. **Prijevara ne može uspjeti dvaput.** Lanac ne može potvrditi obje; druga je mrtva bez
   obzira što je potpis valjan.

Operator odlučuje *koja* od dvije prolazi — to je stvarna pretpostavka i piše dolje.

### Dokaziv lanac stanja

Svaki prijelaz ima digest koji uključuje prethodni:

```
digest_i = SHA256("BEC/L2/v1" ‖ digest_{i-1} ‖ kind ‖ from ‖ to ‖ amount ‖ txid)
```

`bec-l2 audit` ponovno računa cijeli lanac i provjerava da nijedan VTXO nije potrošen
dvaput. Operator ne može tiho prepisati povijest, a stranke mogu dokazati što se dogodilo.

---

## Stari model — jedan UTXO, 4096 exit listova

Ostaje u kodu (`bec commit`, `bec spend-scriptpath`, `--protect`, `--challenge`) jer je
kriptografski ispravan i koristan kao referenca. Ali **nije put za L2** i to je sada
eksplicitno, a ne u fusnoti.

```
  tapscript stablo (4096 listova)
     list 0    :  <288> CSV DROP <op_agg> CHECKSIG        ← operatori, CSV 288
     list 1..N :  <state_root> DROP <144> CSV DROP <user> ← korisnici, CSV 144
  internal key = BIP-341 NUMS (key-path nemoguć)
```

Što u njemu **stvarno radi** i dokazano je na lancu:

- BIP-341 adresa identična Bitcoin Core deskriptoru.
- MuSig2 key-path: 99 vB, 64-bajtni potpis, potvrđeno u bloku.
- NUMS + CSV zaštita: operator **ne može** pretrčati korisnika (CSV 288 > 144).
- Challenge/response: lažna tvrdnja je kažnjiva i dokaziva na lancu.

Što u njemu **ne radi**: iznos (skripta ga ne vidi) i tuđa sredstva (jedan UTXO znači da
svaki exit dira sve ostale).

---

## BitVM — dva sloja, oba iskrena o sebi

### BitVM jezgra (`src/bitvm.hpp`, `bec-bitvm`)

Bit-commitment bond: za svaki indeks bita postoje `h0(i)` i `h1(i)`, a penalty list prihvaća
**samo oba preimagea**. Ekvivokacija time nije tvrdnja koju netko mora dokazati — ona je
**uvjet bez kojeg skript ne prolazi**. Provjereno 11/11.

**Nije BitVM2:** nema garbled circuits ni bisectiona, i na lancu se ne dokazuje da je
otkriveni bit lažan za tvrdnju — samo da su otkrivena dva proturječna.

### Matrica skriptova (`src/gate_matrix.hpp`, `bec-matrix`)

8-bitni zbrajač kao 37 gatea × 8 listova + timeout = **297 listova**. Za svaku kombinaciju
`(va,vb,vc)` postoji vlastiti list: konzistentne potpisuje prover, nekonzistentne
osporavatelj. Bez OP_CAT — svaka žica se provjerava zasebnim commitmentom.

**Nije BitVM2 protokol:** jedan gate po transakciji, bez bisectiona.

---

## Što je u kodu

| Datoteka | Sadržaj |
|---|---|
| `src/crypto.hpp` | Pravi SHA-256, `tagged_hash` (BIP-340), hex, **bech32m** (BIP-350) |
| `src/taproot.hpp` | Merkle + dokaz, tapscript, **BIP-341** skriptno stablo, taptweak, kontrolni blok, **sighash**, serijalizacija |
| `src/musig.hpp` | **BIP-327**: agregacija ključeva, dvije runde, agregacija potpisa, taptweak kroz cache |
| `src/protect.hpp` | NUMS internal key + CSV listovi |
| `src/challenge.hpp` | claim/challenge listovi, `claim_digest` |
| `src/bitvm.hpp` | bit commitment, penalty list, bond timeout |
| `src/gate_matrix.hpp` | **matrica skriptova**: žičani commitmenti, 8 listova po gateu, 8-bitni zbrajač |
| `src/vtxo.hpp` | **VTXO**: ključevi po korisniku, grupni ključ, plan kruga, MuSig2 key-path |
| `src/vtxo_round.hpp` | model kruga: funding tx, grupne tx, potpisivanje, manifest |
| `src/l2_state.hpp` | **L2 stanje**: vlasništvo, prijelazi, dokaziv digest lanac, revizija |
| `src/main.cpp` | CLI `bec`: `genkeys`, `commit`, `spend-*`, `proof` |
| `src/bitvm_main.cpp` | CLI `bec-bitvm`: `bond`, `penalty`, `timeout` |
| `src/matrix_main.cpp` | CLI `bec-matrix`: `build`, `proof-ok`, `proof-bad`, `timeout` |
| `src/vtxo_main.cpp` | CLI `bec-vtxo`: `opkey`, `round`, `exit`, `forge`, `scale` |
| `src/l2_main.cpp` | CLI `bec-l2`: `init`, `transfer`, `exit`, `conflict`, `audit`, `show` |
| `test/run_regtest.sh` | 28 provjera |
| `test/run_bitvm.sh` | 11 provjera |
| `test/run_matrix.sh` | 15 provjera |
| `test/run_vtxo.sh` | 18 provjera |
| `test/run_l2.sh` | 20 provjera |

Nema vanjskih ovisnosti osim `libsecp256k1`. Nema OpenSSL-a, nema boost-a, nema Bitcoin Core
libraryja — namjerno, da se svaki korak može pročitati.

---

## Instalacija

```bash
# 1. libsecp256k1 iz izvora (OBAVEZNO — distribucijski paket nema musig modul)
git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
cd secp256k1 && ./autogen.sh
./configure --enable-module-musig --enable-experimental \
            --enable-module-extrakeys --enable-module-schnorrsig \
            --prefix=$PWD/../secp-inst
make -j"$(nproc)" && make install && cd ..

# 2. svi programi (bec, bec-bitvm, bec-matrix, bec-vtxo, bec-l2)
bash test/build.sh
```

Bitcoin Core za test: [bitcoincore.org/bin](https://bitcoincore.org/bin/bitcoin-core-27.1/).

---

## Korištenje

### VTXO krug

```bash
export LD_LIBRARY_PATH=../secp-inst/lib

# 1) operatorov ključ i adresa za financiranje
./bec-vtxo opkey --hrp bcrt > op.txt

# 2) nakon uplate na tu adresu: krug
./bec-vtxo round --users 5000 --fanout 64 --amount 100000 --delay 144 \
        --op-key <hex> --fund-txid <txid> --fund-vout <n> --fund-amount <sats> \
        --change-script <hex> --out-dir .            # round.txt + tx_000.hex …

# 3) broadcast u redoslijedu: funding, pa grupne tx
bitcoin-cli sendrawtransaction $(cat tx_000.hex)
for f in tx_001.hex tx_002.hex …; do bitcoin-cli sendrawtransaction $(cat $f); done

# 4) korisnik izlazi sam, nakon CSV-a
./bec-vtxo exit --round round.txt --user 5 --txid <vtxo-txid> --vout 1 \
        --amount 100000 --dest-script <hex> --fee 1000 --sequence 144 --out exit.hex

# 5) plan za veliki krug, bez ijedne transakcije
./bec-vtxo scale --users 5000 --fanout 64
```

### L2 sloj — prijelazi između korisnika

```bash
# 1) početno stanje iz VTXO-a koji postoji na lancu
./bec-l2 init --round round.txt --user 0 --txid <grupna-txid> --vout 0 --out state.txt

# 2) A prenosi B-u — pre-potpisano, NE broadcasta se
./bec-l2 transfer --state state.txt --vtxo <id> --to-sk <B-sk-hex> \
        --fee 1000 --out transfer.hex

# 3) ako operator nestane: B sam objavi transfer, pa izađe nakon CSV-a
bitcoin-cli sendrawtransaction $(cat transfer.hex)
./bec-l2 exit --state state.txt --vtxo <novi-id> --dest-script <hex> \
        --fee 1000 --sequence 144 --out exit.hex

# 4) dokaz prijevare: A dvaput potpiše isti VTXO
./bec-l2 conflict --state state.txt --vtxo <id> \
        --to-sk-a <B-sk> --to-sk-b <C-sk> --out-a a.hex --out-b b.hex

# 5) revizija lanca i vlasništva (exit 0 ako je sve ispravno)
./bec-l2 audit --state state.txt
./bec-l2 show  --state state.txt
```

---

## Testovi

```bash
export BITCOIN_BIN=/put/do/bitcoin-27.1/bin
export SECP_PREFIX=/put/do/secp-inst

bash test/run_regtest.sh   # 28 — MuSig2, Taproot, exiti, challenge
bash test/run_bitvm.sh     # 11 — BitVM bond, ekvivokacija, timeout
bash test/run_matrix.sh    # 15 — matrica, 8-bitni zbrajač
bash test/run_vtxo.sh      # 18 — VTXO krug, exit, prijevara
bash test/run_l2.sh        # 20 — off-chain transfer, exit, konflikt, revizija
```

Svaka skripta diže **vlastiti** regtest node (`.regtest-data/`, `.regtest-bitvm/`,
`.regtest-matrix/`, `.regtest-vtxo/`, `.regtest-l2/`), rudari svoje blokove i gasi ga na kraju.
Ne dira postojeći node i ne dijele stanje.

---

## Ograničenja — što još NIJE napravljeno

**1. L2 petlja je zatvorena, ali protokol nije.** Prijelazi, unilateralni exit, konflikti
i dokaziv lanac rade i testirani su. Nedostaje *operativni* sloj: mrežni transport za dvije
runde MuSig2, perzistentno stanje s oporavkom, gossip, i watchtower kao servis. Bez toga
je ovo biblioteka s CLI-jem, ne mreža.

**2. Krug traži sve potpisnike online.** Grupna tx se ne može potpisati ako netko nedostaje.
Jednokratno je, prije nego grupni output postoji, ali je stvarno usko grilo.

**2b. Operator bira pobjednika kad A dvaput potpiše.** U konfliktu su oba prijenosa valjana,
a operator odlučuje koji ide dalje. Ne može ukrasti — nema ključeve — ali može proizvoljno
odabrati. Prijevara je time *dokaziva*, ali ne *spriječena*. Rješenje traži duži exit prozor
i kaznu, ne kod.

**3. Netko mora biti živ unutar CSV prozora.** Ako A izađe i nitko ne objavi transfer u D
blokova, A pobjeđuje. Ista pretpostavka kao kod svakog optimistic protokola.

**4. Nema state machine za prijelaze veće od jednog VTXO-a.** Nema dijeljenja VTXO-a
(split/merge), nema plaćanja u više izlaza, nema atomskog swap-a.

**5. Nema data availability jamstva.** Korisnik mora imati svoje podatke: ako izgubi
`state.txt` i svoj ključ, izgubio je novac. To je najčešći stvarni gubitak u ovakvim
sustavima, ne kriptografski napad.

**6. Nonce management nije produkcijski.** `secnonce` se drži u memoriji i nulira na kraju.
Produkcijski potpisnik mora koristiti `musig_nonce_gen_counter` s perzistentnim brojačem i
nikad ne smije serijalizirati `secnonce`. Ponovna upotreba = gubitak ključa.

**7. Iznos se ne provjerava U SKRIPTI — i to ostaje tako.** U VTXO modelu to nije problem,
jer se iznos ne provjerava nego upisuje. Za covenant bi trebao CTV (BIP-119, još draft)
ili OP_CAT (BIP-347, specifikacija dovršena, **nije aktiviran**).

**8. Matrica provjerava jedan gate.** Bez bisectiona osporavanje košta O(n) transakcija.

**9. Likvidnost.** Operator mora vezati kapital za svaki krug. To je ekonomski, ne tehnički
problem — i obično onaj koji ovakve projekte ubije.

---

## Sigurnosne napomene

- `secp256k1_musig` je **eksperimentalni modul**. Build ispisuje *"Experimental features do
  not have stable APIs or properties, and may not be safe for production use."*
- Ovo nije kod za držanje stvarnih sredstava bez vanjskog audita.
- `op.txt`, `state.txt`, `round.txt`, `keys.txt`, `operators.txt` i `*.hex` sadrže **tajne u
  čistom tekstu**. Nikad ih ne commitaj. U `.gitignore` su.

---

## Licenca

MIT (kao i libsecp256k1). Koristi na vlastitu odgovornost.
