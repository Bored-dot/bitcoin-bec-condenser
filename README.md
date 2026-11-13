# Bitcoin BEC Condenser — VTXO settlement na Bitcoinu

MuSig2 (BIP-327) + Taproot (BIP-341) settlement za L2 stanje, **testirano na Bitcoin Core konsenzusu**.

Ovaj projekt je prošao kroz tri arhitekture i README to ne skriva:

1. **Simulacija** (originalna verzija) — lažni hash, potpis jednim ključem, "covenant verified"
   koji ništa nije provjeravao. Uklonjeno.
2. **Jedan UTXO + exit listovi** — pravi MuSig2 i Taproot, ali sa strukturnim problemom:
   skripta ne vidi iznos, pa korisnik koji izađe podigne cijeli UTXO. Dokumentirano dolje
   kao *Zašto je model promijenjen*.
3. **VTXO — jedan output po korisniku** — trenutna arhitektura. Iznos nije tvrdnja u skripti,
   nego činjenica na lancu.

Sve u ovom repou potvrđeno je stvarnim transakcijama u Bitcoin Core regtestu — ne ispisom u terminalu.

---

## Rezultat testova

```
════════════════════════════════════════════════════════════════
  test/run_regtest.sh   MuSig2 / Taproot / exiti / challenge      28/28
  test/run_bitvm.sh     BitVM jezgra (bit-commitment bond)         11/11
  test/run_matrix.sh    BitVM2 matrica skriptova (8-bit zbrajač)   15/15
  test/run_vtxo.sh      VTXO settlement                            18/18
────────────────────────────────────────────────────────────────
  UKUPNO: 72 provjere, 14 negativnih
════════════════════════════════════════════════════════════════
```

Negativni testovi su namjerno tu: test koji uvijek prolazi ne dokazuje ništa.
Svaki pad nosi **točnu konsenzus grešku koju Bitcoin Core stvarno vraća**.

Detaljni rezultati: `test/expected_output*.txt`.

---

## Zašto je model promijenjen

Ovo je najvažnija sekcija u dokumentu i zato je na početku.

**Skripta ne vidi iznose.** Tapscript izvršava uvjete nad podacima koje mu witness preda;
nema pristup outputima transakcije koja ga troši. Zato nijedan skript ne može provjeriti
*"odgovara li ovaj izlaz mom balansu"*.

Iz toga slijedi da model s **jednim zajedničkim UTXO-om** ima posljedicu koju treba izgovoriti:
korisnik koji izađe podigne **cijeli UTXO**. Pošten izlaz i prijevara su u tom trenutku
ekonomski identični — i jedan i drugi unište tuđa sredstva.

Challenge/response iz PR #3 to čini *kažnjivim*, ali ne i *nemogućim*: digest je u skriptu,
ali skript ga samo `OP_DROP`-a. Lanac provjerava *"osporavatelj zna ista 48 bajta"*, ne
*"iznos je točan"*. To sam u PR #2 trebao reći jasnije.

**Rješenje ne treba covenant.** Ako se odustane od zajedničkog UTXO-a, problem iznosa
prestaje postojati — jer se iznos ne provjerava, nego **upisuje**. To je VTXO model.

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

Ovo je mehanizam koji zamjenjuje covenant, i provjeren je na lancu.

Grupni output traži **MuSig2(operator + svi u grupi)**. Grupnu tx potpisuju svi.
Parcijalni MuSig2 potpis je vezan na **jedan** sighash — ne može se prenijeti na drugu
transakciju. Dakle: tko god odbije potpisati izmijenjenu tx, ta tx nikad neće imati valjan
potpis, jer drugi potpis matematički ne postoji.

Provjereno (`test/run_vtxo.sh`, sekcija 7):

```
Napadač (korisnik 0) traži  : 7000 sats (umjesto 5000)
Žrtva   (korisnik 3) gubi   : 2000 sats
Zbroj outputa               : 20000 sats (nepromijenjen)
Potpis                      : pošteni 64 B, jer potpis za ovu tx NE POSTOJI
→ node odbija: Invalid Schnorr signature
```

I kontrolni test u istom trenutku: **poštena** grupna tx prolazi. Pad nije artefakt testa.

### Cijena

Nema covenanta, ali nema ni besplatnog ručka. Poštena cijena je:

| što | posljedica |
|---|---|
| svi u grupi moraju potpisati grupnu tx | jednokratno, prije nego grupni output postoji |
| MuSig2 skup ≤ fanout + 1 | ne treba 5000-potpisni skup, ali treba 65-potpisni |
| više outputa na lancu | ~55 B po korisniku (vidi `bec-vtxo scale`) |

Skala za 5000 korisnika, fanout 64:

```
Grupa                        : 79
On-chain tx-ova              : 80   (1 funding + 79 grupnih)
Najveća grupa                : 64 korisnika (65 potpisnika)
Ukupno on-chain (procjena)   : 273 533 B
Po korisniku                 : 54.7 B
```

**Nema ijednog MuSig2 skupa veličine 5000.** To je ključna razlika u odnosu na ideju
"svih 5000 u jedan agregat", gdje jedan offline korisnik zamrzne sva sredstva.

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
- NUMS + CSV zaštita: operator **ne može** pretrčati korisnika (CSV 288 > 144), potvrđeno
  na visinama prije/poslije 144 i 288.
- Challenge/response: lažna tvrdnja je kažnjiva i dokaziva na lancu.

Što u njemu **ne radi**:

- Iznos. Skripta ga ne vidi, pa korisnik podigne cijeli UTXO.
- Tuđa sredstva. Jedan UTXO znači da svaki exit dira sve ostale.

Zato je VTXO model zamjena, a ne dodatak.

---

## BitVM — dva sloja, oba iskrena o sebi

### BitVM jezgra (`src/bitvm.hpp`, `bec-bitvm`)

Bit-commitment bond: za svaki indeks bita postoje `h0(i)` i `h1(i)`, a penalty list prihvaća
**samo oba preimagea**:

```
OP_SHA256 <h1(i)> OP_EQUALVERIFY OP_SHA256 <h0(i)> OP_EQUALVERIFY <challenger> CHECKSIG
```

Ekvivokacija time nije tvrdnja koju netko mora dokazati — ona je **uvjet bez kojeg skript
ne prolazi**. Provjereno 11/11, uključujući četiri negativna scenarija.

**Nije BitVM2:** nema garbled circuits, nema bisectiona, i na lancu se ne dokazuje da je
otkriveni bit lažan za tvrdnju — samo da su otkrivena dva proturječna.

### Matrica skriptova (`src/gate_matrix.hpp`, `bec-matrix`)

8-bitni zbrajač kao 37 gatea × 8 listova + timeout = **297 listova**. Za svaku kombinaciju
`(va,vb,vc)` postoji vlastiti list: konzistentne potpisuje prover, nekonzistentne
osporavatelj. Bez OP_CAT — svaka žica se provjerava zasebnim commitmentom.

Provjereno 15/15, uključujući ključni par: isti list potpisan pogrešnim ključem pada.

**Nije BitVM2 protokol:** jedan gate po transakciji, bez bisectiona. Osporavanje cijelog
zbrajača košta do 37 transakcija umjesto `O(log 37) ≈ 6`.

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
| `src/main.cpp` | CLI `bec`: `genkeys`, `commit`, `spend-*`, `proof` |
| `src/bitvm_main.cpp` | CLI `bec-bitvm`: `bond`, `penalty`, `timeout` |
| `src/matrix_main.cpp` | CLI `bec-matrix`: `build`, `proof-ok`, `proof-bad`, `timeout` |
| `src/vtxo_main.cpp` | CLI `bec-vtxo`: `opkey`, `round`, `exit`, `forge`, `scale` |
| `test/run_regtest.sh` | 28 provjera |
| `test/run_bitvm.sh` | 11 provjera |
| `test/run_matrix.sh` | 15 provjera |
| `test/run_vtxo.sh` | 18 provjera |

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

# 2. svi programi
bash test/build.sh
```

Bitcoin Core za test: [bitcoincore.org/bin](https://bitcoincore.org/bin/bitcoin-core-27.1/).

---

## Korištenje — VTXO krug

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

# 5) pokušaj prijevare (mora pasti)
./bec-vtxo forge --round round.txt --group 0 --bump 1000 --out forge.hex

# 6) plan za veliki krug, bez ijedne transakcije
./bec-vtxo scale --users 5000 --fanout 64
```

Ostali programi (`bec`, `bec-bitvm`, `bec-matrix`) opisani su u svojim sekcijama iznad.

---

## Testovi

```bash
export BITCOIN_BIN=/put/do/bitcoin-27.1/bin
export SECP_PREFIX=/put/do/secp-inst

bash test/run_regtest.sh   # 28 — MuSig2, Taproot, exiti, challenge
bash test/run_bitvm.sh     # 11 — BitVM bond, ekvivokacija, timeout
bash test/run_matrix.sh    # 15 — matrica, 8-bitni zbrajač
bash test/run_vtxo.sh      # 18 — VTXO krug, exit, prijevara
```

Svaka skripta diže **vlastiti** regtest node (`.regtest-data/`, `.regtest-bitvm/`,
`.regtest-matrix/`, `.regtest-vtxo/`), rudari svoje blokove i gasi ga na kraju.
Ne dira postojeći node i ne dijele stanje.

---

## Ograničenja — što još NIJE napravljeno

Pošten popis, ne marketinški.

**1. Ovo nije L2 protokol.** Nema konsenzusa među operatorima, nema gossip-a, nema
perzistentnog stanja, nema oporavka od pada. VTXO je **settlement sloj** koji L2 može
koristiti, ne gotov L2.

**2. Krug traži sve potpisnike online.** Grupna tx se ne može potpisati ako netko nedostaje.
To je jednokratno i prije nego grupni output postoji, ali je stvarno usko grilo. Ark rješava
istu stvar na isti način.

**3. Nema state machine.** Prijelazi stanja, rješavanje konflikta dvaju valjanih prijelaza i
pravila tko smije potpisati — nije napisano.

**4. Nema watchtowera ni data availability jamstva.** Za VTXO sigurnost watchtower nije
potreban (korisnik izlazi sam). Ali korisnik mora **imati** svoje podatke: ako izgubi
`round.txt` i svoj ključ, izgubio je novac. To je najčešći stvarni gubitak u ovakvim
sustavima, ne kriptografski napad.

**5. Nonce management nije produkcijski.** `secnonce` se drži u memoriji i nulira na kraju.
Produkcijski potpisnik mora koristiti `musig_nonce_gen_counter` s perzistentnim brojačem i
nikad ne smije serijalizirati `secnonce`. Ponovna upotreba = gubitak ključa.

**6. Iznos se ne provjerava U SKRIPTI — i to ostaje tako.** U VTXO modelu to nije problem,
jer se iznos ne provjerava nego upisuje. Ali to znači da rješenje nije "covenant u skripti",
nego "arhitektura bez zajedničkog UTXO-a". Za covenant bi trebao CTV (BIP-119, još draft)
ili OP_CAT (BIP-347, specifikacija dovršena, **nije aktiviran**).

**7. Matrica provjerava jedan gate.** Bez bisectiona osporavanje košta O(n) transakcija.

**8. Likvidnost.** Operator mora vezati kapital za svaki krug. To je ekonomski, ne tehnički
problem — i obično onaj koji ovakve projekte ubije.

---

## Sigurnosne napomene

- `secp256k1_musig` je **eksperimentalni modul**. Build ispisuje *"Experimental features do
  not have stable APIs or properties, and may not be safe for production use."*
- Ovo nije kod za držanje stvarnih sredstava bez vanjskog audita.
- `op.txt`, `round.txt`, `keys.txt`, `operators.txt` i `*.hex` sadrže **tajne u čistom
  tekstu**. Nikad ih ne commitaj. U `.gitignore` su.

---

## Licenca

MIT (kao i libsecp256k1). Koristi na vlastitu odgovornost.
