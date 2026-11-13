# Bitcoin BEC Condenser — stvarna implementacija

MuSig2 (BIP-327) + Taproot (BIP-341) settlement za L2 stanje, **testirano na Bitcoin Core konsenzusu**.

Ovo nije samo benchmark agregacije ključeva. Ovo je program koji:
- izgradi stvarni Taproot output koji komitira cijelo L2 stanje,
- potpiše ga **pravim MuSig2 protokolom u dvije runde**,
- i omogući korisniku **unilateralni exit koji stvarno drži** — jer je operatorima
  key-path matematički onemogućen, a njihov CSV stroži od korisničkog,
- a lažni izlaz se **oduzima javnim dokazom** unutar challenge prozora,
- i ima **BitVM jezgru** u kojoj prover fizički ne može lagati o bitu bez gubitka bonda.

Sve gore navedeno potvrđeno je stvarnim transakcijama u Bitcoin Core regtestu — ne ispisom u terminalu.

---

## Rezultat testa

```
════════════════════════════════════════════════════════════════
 0. Bitcoin Core regtest            Bitcoin Core v27.1.0
 1. BIP-341 adresa vs Bitcoin Core  ✅ adresa identična (descriptor oracle)
 2. Key-path spend — MuSig2         ✅ prihvaćen + potvrđen u bloku (99 vB)
 3. Script-path — unilateralni exit ✅ prihvaćen + potvrđen u bloku (364 B witness)
 4. NEGATIVNI: potpis 1 ključem     ✅ odbijen — "Invalid Schnorr signature"
 5. NEGATIVNI: exit prije CSV       ✅ odbijen — "Locktime requirement not satisfied"
 6. NEGATIVNI: pokvaren control blk ✅ odbijen — "Witness program hash mismatch"
 7. Inclusion proof                 ✅ valjan (dubina 6, 192 B)
 8. Skala: 5000 korisnika           ✅ 4096 exit listova, dubina 12
 9. ZAŠTITA (NUMS + CSV)            ✅ 8 provjera — exita ne može pretrčati operator
    · key-path (MuSig2 operatora)  ✅ odbijen — Invalid Schnorr signature
    · korisnik prije 144 bloka     ✅ odbijen — non-BIP68-final
    · operator prije 288 blokova   ✅ odbijen — non-BIP68-final
    · korisnik nakon 144 bloka     ✅ prihvaćen + potvrđen u bloku
    · operator još na 144 bloka    ✅ odbijen (korisnički prozor traje)
    · operator nakon 288 blokova   ✅ prihvaćen + potvrđen u bloku
10. CHALLENGE/RESPONSE              ✅ 6 provjera — lažni izlaz se oduzima
    · tvrdnja prije prozora        ✅ odbijen — non-BIP68-final
    · osporavanje, pogrešan dokaz  ✅ odbijen — OP_EQUALVERIFY failed
    · osporavanje, ispravan dokaz  ✅ prihvaćen + potvrđen u bloku
    · tvrdnja nakon prozora        ✅ prihvaćen + potvrđen u bloku
────────────────────────────────────────────────────────────────
   test/run_regtest.sh:   PASS: 28   FAIL: 0
════════════════════════════════════════════════════════════════

════════════════════════════════════════════════════════════════
 11. BITVM JEZGRO                  (test/run_bitvm.sh)
 1. Bond                           ✅ 8 penalty listova + timeout, h0/h1 u skriptu
 2. Kazna s OBA preimagea          ✅ prihvaćen + potvrđen — ekvivokacija dokazana
 3. NEGATIVNI: pogrešan preimage   ✅ odbijen — OP_EQUALVERIFY
 4. NEGATIVNI: samo jedan preimage ✅ odbijen — OP_EQUALVERIFY
 5. NEGATIVNI: pogrešan potpisnik  ✅ odbijen — Invalid Schnorr signature
 6. NEGATIVNI: timeout prije CSV   ✅ odbijen — non-BIP68-final
 7. Timeout nakon CSV-a            ✅ prihvaćen + potvrđen
────────────────────────────────────────────────────────────────
   test/run_bitvm.sh:     PASS: 11   FAIL: 0
════════════════════════════════════════════════════════════════
```

Negativni testovi su namjerno tu: test koji uvijek prolazi ne dokazuje ništa.
Testovi 4–6, sekcije 9 i 10 te testovi 3–6 BitVM suitea padaju s **točno onim
konsenzus greškama koje Bitcoin Core stvarno vraća**.

---

## Arhitektura

```
   L2 stanje: 5000 korisnika (xonly ključ + balans)
        │
        ├── Merkle stablo stanja ──────────► state root  (13 razina, dokaz 416 B)
        │
        ├── tapscript stablo (4096 listova)
        │      list 0     :  <288> CSV DROP <op_agg> CHECKSIG        ← operatori
        │      list 1..N  :  <state_root> DROP <144> CSV DROP <user> ← korisnici
        │      └─ state root je U SVAKOM LISTU → output key obavezno komitira stanje
        │
        └── internal key = BIP-341 NUMS točka (key-path NEMOGUĆ)
                                                          │
                              BIP-341 taptweak:  t = H("TapTweak", internal ‖ script_root)
                                                          │
                                                Taproot output key (32 B)
                                                          │
                                            bech32m adresa (bcrt1p…)

  TROŠENJE:
    script-path (korisnik, CSV 144)  →  potpis + kontrolni blok   [unilateralni exit]
    script-path (operatori, CSV 288) →  MuSig2 dvije runde         [kooperativni settlement]
    key-path                        →  NEMOGUĆ (NUMS internal key)
```

**Zašto ovo radi, a MuSig2-sam-za-5000-korisnika ne bi:** MuSig2 se koristi za **3 operatora**
(mali, uvijek dostupan skup). 5000 korisnika je u **skriptnom stablu** i Merkle dokazu — svaki
korisnik izlazi sam, bez rundi komunikacije i bez mogućnosti da ga bilo ko blokira.

---

## Instalacija

```bash
# 1. libsecp256k1 iz izvora (OBAVEZNO — distribucijski paket nema musig modul)
git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-musig --enable-experimental \
            --enable-module-extrakeys --enable-module-schnorrsig \
            --prefix=$PWD/../secp-inst
make -j"$(nproc)" && make install
cd ..

# 2. programi (bec + bec-bitvm)
bash test/build.sh
```

Bitcoin Core za test: [bitcoincore.org/bin](https://bitcoincore.org/bin/bitcoin-core-27.1/)
(preuzeti `bitcoin-27.1-x86_64-linux-gnu.tar.gz`, raspakirati).

---

## Korištenje

```bash
export LD_LIBRARY_PATH=../secp-inst/lib

# 1) ključevi
./bec genkeys --count 5000 --out keys.txt
./bec genkeys --count 3    --out operators.txt

# 2) commitment — --protect je PREPORUČENI način:
#    NUMS internal key + operatorski list s CSV-om 288
./bec commit --keys keys.txt --operators operators.txt \
             --delay 144 --op-delay 288 --protect \
             --leaves 4096 --hrp bcrt --out commitment.txt

#    bez --protect: key-path ostaje moguć (99 vB kooperativno), ali operatori
#    mogu pretrčati korisnički exit — koristi samo za mjerenje veličine

# 3) unilateralni exit korisnika (bez operatora, nakon CSV 144)
./bec spend-scriptpath --commitment commitment.txt \
             --txid <funding-txid> --vout <n> --amount <sats> \
             --dest-script <hex> --fee 2000 \
             --leaf 2 --sequence 144 --out scriptpath.hex

# 4) kooperativni settlement (MuSig2 preko skriptnog lista, tek nakon CSV 288)
./bec spend-op-exit --commitment commitment.txt \
             --txid <funding-txid> --vout <n> --amount <sats> \
             --dest-script <hex> --fee 2000 --sequence 288 --out opexit.hex

# 5) challenge/response (lažni izlaz se oduzima)
./bec commit --keys keys.txt --operators operators.txt \
             --delay 144 --leaves 4096 --protect \
             --challenge --challenge-window 96 \
             --challenger-key <64 hex> --hrp bcrt --out committed.txt

#    korisnik pokušava podići nakon prozora
./bec spend-scriptpath --commitment committed.txt --txid <txid> --vout <n> \
             --amount <sats> --dest-script <hex> --fee 2000 \
             --leaf 2 --sequence 96 --out claim.hex

#    bilo tko s dokazom oduzima izlaz (radi odmah, ne čeka prozor)
./bec spend-challenge --commitment committed.txt --txid <txid> --vout <n> \
             --amount <sats> --dest-script <hex> --fee 2000 --leaf 2 \
             --challenger-key <hex> --sequence 1 --out challenge.hex

# 6) BitVM jezgra: bond + kazna za ekvivokaciju
./bec-bitvm bond --bits 8 --csv 96 \
             --prover-key <hex> --challenger-key <hex> --hrp bcrt --out bond.txt

#    kazna: potrošivo SAMO s oba preimagea istog bita
./bec-bitvm penalty --bond bond.txt --index 3 --txid <txid> --vout <n> \
             --amount <sats> --dest-script <hex> --fee 2000 --sequence 1 \
             --challenger-key <hex> --out penalty.hex

#    prover vraća bond nakon CSV-a
./bec-bitvm timeout --bond bond.txt --txid <txid> --vout <n> \
             --amount <sats> --dest-script <hex> --fee 2000 --sequence 96 \
             --prover-key <hex> --out timeout.hex

# 7) dokaz da je korisnik u stanju
./bec proof --keys keys.txt --commitment commitment.txt --index 7
```

`--hrp`: `bc` (mainnet), `tb` (testnet), `bcrt` (regtest).

---

## Test na Bitcoin Core

```bash
export BITCOIN_BIN=/put/do/bitcoin-27.1/bin
export SECP_PREFIX=/put/do/secp-inst

bash test/run_regtest.sh   # 28 provjera: MuSig2, Taproot, exiti, challenge
bash test/run_bitvm.sh     # 11 provjera: BitVM bond, ekvivokacija, timeout
```

Svaka skripta diže **vlastiti** regtest node (`.regtest-data/` odnosno `.regtest-bitvm/`),
rudari svoje blokove i gasi ga na kraju. Ne dira postojeći node i ne dijele stanje.
Ukupno 39 provjera, od kojih 9 negativnih.

---

## Zaštita unilateralnog exita (NUMS + CSV)

Bez ovoga exit ne vrijedi ništa: output je jedan UTXO s dvije putanje, a operatori su
mogli potrošiti **key-path** odmah — pa su u utrci za isti UTXO trivijalno pobjeđivali
korisnika koji čeka CSV. Exit je tada bio moguć samo ako su operatori pristojni, što je
upravo ono što exit treba pokrivati.

Rješenje (`--protect`):

```
   internal key  = 50929b74…803ac0   ← BIP-341 NUMS točka, diskretni log NEPOZNAT
                                       ⇒ key-path je matematički nemoguć
                                       ⇒ sve ide preko skriptnog stabla

   tapscript stablo:
     list 0        :  <288> CSV DROP <op_agg> CHECKSIG          ← operatori, CSV 288
     list 1..N     :  <state_root> DROP <144> CSV DROP <user> CHECKSIG   ← korisnici, CSV 144
```

Korisnički CSV je **stroži** (manji) od operatorskog, pa korisnik uvijek ima prozor od
144 bloka u kojem **samo on** može potrošiti output. Provjereno na nodeu:

| visina | korisnik (CSV 144) | operator (CSV 288) |
|---|---|---|
| prije 144 | odbijen `non-BIP68-final` | odbijen `non-BIP68-final` |
| nakon 144 | **prihvaćen, potvrđen** | odbijen — prozor još traje |
| nakon 288 | prihvaćen | **prihvaćen, potvrđen** |

Cijena: kooperativna potrošnja seli s key-path na script-path (~+60 vB). I dalje O(1),
ali nije više 99 vB. To je namjerna zamjena — bez nje exit nije garancija.

**Što ovime NIJE riješeno:** bez covenanta se iznos izlaza ne može ograničiti, pa korisnik
koji izađe podiže **cijeli UTXO**, ne samo svoj balans. Zaštita je time "prvi koji izađe
uzima sve", a ne per-korisničko poravnanje.

---

## Challenge/response — lažni izlaz se oduzima

`--protect` rješava *tko smije prvi*. Nije rješavao *koliko smije uzeti*: korisnik
koji izađe podigne **cijeli UTXO**, ne samo svoj balans, i nitko ga ne može kazniti.
Skripta to ne može provjeriti bez covenanta.

Challenge/response to rješava **ekonomski**, na isti način na koji rade optimistic rollupi:

```
  1. CLAIM      korisnik potroši UTXO i veže se na claim_digest (iznos + index + state root)
                → digest je UBAČEN U SKRIPT, pa se tvrdnja ne može promijeniti nakon uplate
  2. WINDOW     96 blokova u kojima korisnik NE MOŽE podići sredstva (OP_CSV)
  3. CHALLENGE  svako s valjanim dokazom preuzima izlaz:
                  OP_SHA256 <claim_digest> OP_EQUALVERIFY ... <challenger> CHECKSIG
                → dokaz mora hashirati na digest; bez toga skript pada
  4. SETTLE     ako prozor prođe bez osporavanja, korisnik preuzima izlaz
```

Provjereno na nodeu:

| scenarij | rezultat |
|---|---|
| tvrdnja prije 96. bloka | odbijen `non-BIP68-final` |
| osporavanje s pogrešnim dokazom | odbijen `OP_EQUALVERIFY failed` |
| osporavanje s ispravnim dokazom | **prihvaćen, izlaz oduzet, potvrđen** |
| tvrdnja nakon prozora (neosporena) | **prihvaćen, potvrđen** |

**Što je time stvarno zatvoreno:** lažna tvrdnja više nije besplatna. Vezana je na
nepromjenjiv digest, mora preživjeti javni prozor, i svako može posegnuti za izlazom
otkrivanjem dokaza — a otkrivanje dokaza je na lancu pa je svaki takav potez
neporeciv i provjerljiv nakon činjenice.

**Što ostaje pretpostavka (i piše u kodu, `src/challenge.hpp`):**
- **Da je tvrdnja lažna provjerava se izvan lanca.** Na lancu se dokazuje samo da je
  osporavatelj otkrio točno onaj dokaz na koji se korisnik vezao.
- **Netko mora gledati.** Ako nitko ne ospori u prozoru, lažna tvrdnja prolazi.
- **Utrka je moguća.** Challenge i claim su konkurentne transakcije na istom UTXO-u.

---

## BitVM jezgra — bit-commitment bond

Challenge/response iz prethodne sekcije ima jednu pretpostavku: *da je tvrdnja lažna
provjerava se izvan lanca*. BitVM ide korak dalje — prover **fizički ne može** lagati
o pojedinom bitu svog međurezultata, jer bi ga to koštalo bonda.

Ovdje je implementirana ta jezgra, i provjerena na nodeu:

```
  za svaki indeks bita i postoje dva commitmenta:
      h0(i) = SHA256( SHA256( 0x00 || 0x00 || i_le32 || salt ) )
      h1(i) = SHA256( SHA256( 0x00 || 0x01 || i_le32 || salt ) )

  penalty list za indeks i:
      OP_SHA256 <h1(i)> OP_EQUALVERIFY
      OP_SHA256 <h0(i)> OP_EQUALVERIFY
      <challenger> OP_CHECKSIG

  → potrošiv SAMO s witnessom [sig, preimage(0,i), preimage(1,i)]
```

To je važna razlika u odnosu na "osporavatelj tvrdi da je laž". Ekvivokacija nije
tvrdnja koju netko mora dokazati — ona je **uvjet bez kojeg skript ne prolazi**.
Tko otvori oba bita istog indeksa, predao je bond; tko ne otvori, ne može ga ni
dotaknuti. Provjereno:

| scenarij | rezultat |
|---|---|
| kazna s oba preimagea | **prihvaćen, bond preuzet, potvrđen** |
| kazna s pogrešnim preimageom | odbijen `OP_EQUALVERIFY failed` |
| kazna sa samo jednim preimageom | odbijen `OP_EQUALVERIFY failed` |
| kazna s ispravnim dokazom, pogrešan potpisnik | odbijen `Invalid Schnorr signature` |
| proverov timeout prije CSV-a | odbijen `non-BIP68-final` |
| proverov timeout nakon CSV-a | **prihvaćen, potvrđen** |

Internal key je NUMS, pa je key-path nemoguć i sve ide preko skriptnog stabla —
ista konstrukcija kao u `--protect`.

### Što je ovo, a što nije

**Ovo je BitVM primitiv, ne BitVM2 protokol.** Razlika je bitna i ne želim je zamutiti:

| BitVM2 ima | Ovdje |
|---|---|
| garbled circuits / matrice skriptova koje provjeravaju cijeli izraz | ✗ — provjerava se **jedan bit**, ne izraz |
| bisection protokol preko razina poziva | ✗ — jedan sloj, indeks bira osporavatelj |
| na-lancu provjeru da je otkriveni bit **ispravan za tvrdnju** | ✗ — na lancu se dokazuje samo da su otkrivena **dva proturječna** bita |
| commit na cijeli program i njegove međurezultate | ✗ — commit na N bitova koje prover sam bira |

Dakle: ono što je stvarno zatvoreno je **ekvivokacija**. Prover koji za isti bit
tvrdi i 0 i 1 gubi bond, i to je dokazivo na lancu bez ikakve pretpostavke o
promatraču. Ono što nije zatvoreno je da je *pojedinačni* otkriveni bit lažan za
tvrdnju — to bi tražilo garbled circuits, što je red veličine veći posao.

Ime je važno. Nazvati ovo "BitVM2" bilo bi isto kao tvrditi da je `sha256_double`
SHA-256 — greška zbog koje je ovaj projekt i počeo.

---

## Što je u kodu

| Datoteka | Sadržaj |
|---|---|
| `src/crypto.hpp` | Pravi SHA-256, `tagged_hash` (BIP-340), hex, **bech32m** (BIP-350) |
| `src/taproot.hpp` | Merkle stablo + dokaz, tapscript gradnja, **BIP-341** skriptno stablo, taptweak, kontrolni blok, **sighash**, serijalizacija tx |
| `src/musig.hpp` | **BIP-327** MuSig2: agregacija ključeva, dvije runde, agregacija potpisa, taptweak kroz keyagg cache |
| `src/protect.hpp` | NUMS internal key + operatorski CSV list (zaštita exita) |
| `src/challenge.hpp` | challenge/response: claim list, challenge list, claim_digest |
| `src/bitvm.hpp` | BitVM jezgra: bit commitment (h0/h1), penalty list, bond timeout |
| `src/bitvm_main.cpp` | CLI `bec-bitvm`: `bond`, `penalty`, `timeout` (zaseban binarij) |
| `src/main.cpp` | CLI: `genkeys`, `commit`, `spend-keypath`, `spend-scriptpath`, `spend-op-exit`, `spend-challenge`, `proof` |
| `test/run_regtest.sh` | MuSig2 / Taproot / exiti / challenge: 28 provjera, 6 negativnih |
| `test/run_bitvm.sh` | BitVM jezgra: 11 provjera, 4 negativne |

Nema vanjskih ovisnosti osim `libsecp256k1`. Nema OpenSSL-a, nema boost-a, nema Bitcoin Core
libraryja — namjerno, da se svaki korak može pročitati.

---

## Što je ispravljeno u odnosu na originalnu verziju

| Original | Sada |
|---|---|
| `sha256_double` = `(x*33)^0x5C` po bajtu | pravi SHA-256 + `tagged_hash` |
| Merkle root = `H(jedan list ‖ 0xAA…)` | pravo stablo nad svih 5000 listova + dokaz |
| potpis `batch[0]` ključem, verifikacija protiv `batch[0]` | MuSig2 dvije runde, verifikacija protiv **tweakane output točke** |
| nema MuSig2 rundi | `nonce_gen` → `nonce_agg` → `nonce_process` → `partial_sign` → `partial_sig_agg` |
| taptweak = sirovi Merkle root | `t = H("TapTweak", internal ‖ script_root)` |
| operatori mogu potrošiti odmah i pretrčati exit | `--protect`: NUMS internal key + operatorski CSV 288 > korisnički 144 |
| lažni izlaz nije kažnjiv | `--challenge`: digest u skriptu + prozor + oduzimanje uz dokaz |
| "Covenant verified" = tautologija | stvarni CSV exit koji Bitcoin Core prihvaća |
| `Main2.cpp` se ne kompajlira | jedan program, jedan `main.cpp` |
| nema validacije ulaza | strogi hex, provjera svake povratne vrijednosti |
| nema `context_randomize` | randomiziran kontekst, `secure_zero` nad tajnama |
| — | **bug nađen i popravljen:** promovirani čvor u ne-potenciji dvojke dobivao je lažni sibling |

---

## Ograničenja — što još NIJE napravljeno

Ovo je pošteni popis, ne marketinški.

**0. Iznos izlaza se ne može provjeriti U SKRIPTI — brani se ekonomski, ne kriptografski.**
`--challenge` čini lažnu tvrdnju kažnjivom, a BitVM jezgra čini ekvivokaciju dokazivom
na lancu. Ali skripta i dalje **ne zna** koliko korisniku pripada, niti da je pojedini
otkriveni bit lažan za tvrdnju — to se provjerava izvan lanca. Za kriptografsku
garanciju treba covenant (CTV / OP_CAT) ili pun BitVM2 s garbled circuits.
Najveće preostalo ograničenje i ono koje razdvaja ovaj kod od upotrebljivog L2 rješenja.

**1. Verifikacija Merkle dokaza *unutar* skripte traži OP_CAT.**
OP_CAT (BIP-347) nije aktiviran na Bitcoinu. Bez njega se u tapscriptu ne mogu spojiti dva
32-bajtna hasha u 64-bajtni preimage, pa se inclusion proof ne može provjeriti on-chain.
Zato je ovdje:
- state root **komitiran u output key** (preko svakog exit lista) — mijenjanje stanja mijenja adresu;
- inclusion proof se **provjerava off-chain** (`./bec proof`);
- on-chain exit ide preko **CSV delay + korisnikov ključ** — korisnik stvarno može izaći sam.

**2. Dvije runde komunikacije su stvarno usko grlo.**
U testu su svi potpisnici u istom procesu. U stvarnosti 3 operatora moraju razmijeniti nonce
i parcijalne potpise preko mreže. Kod je struktuiran tako da se to doda (nonce i potpisi su
serijalizabilni preko `secp256k1_musig_pubnonce_serialize` / `partial_sig_serialize`), ali
mrežni sloj nije napisan.

**3. Nonce management nije produkcijski.**
`secnonce` se drži u memoriji i nulira na kraju. Produkcijski potpisnik mora koristiti
`musig_nonce_gen_counter` s perzistentnim brojačem i nikad ne smije serijalizirati `secnonce`.
Ponovna upotreba noncea = gubitak privatnog ključa. To je dokumentirano u kodu, ali nije
riješeno na razini HSM-a.

**4. `--leaves` mora biti potencija dvojke** ako želiš descriptor usporedbu s Bitcoin Core.
Razlog: descriptor jezik ne može izraziti `raw()` unutar `tr()`, pa se usporedba radi s
`pk()` listovima. U `--protect` načinu descriptor se uopće ne ispisuje jer sadrži CSV listove
koje `raw()` ne može opisati unutar `tr()` — adresa se tamo dokazuje potrošnjom, ne deskriptorom.

**4b. Broj exit listova ≤ broj korisnika.** Ako je korisnika 5000, a listova 4096 (i još jedan
za operatore), onda dio korisnika **nema nijednu on-chain putanju** — samo off-chain dokaz,
koji bez covenanta ne vrijedi ništa. U produkciji broj listova mora biti ≥ broj korisnika + 1.

**5. BitVM jezgra je primitiv, ne protokol.** Vidi tablicu u sekciji iznad — nema garbled
circuits ni bisection preko razina poziva, pa se njome ne može provjeriti cijeli izračun.

**6. Ovo nije L2 protokol.** Nema konsenzusa među operatorima, nema gossip-a, nema
perzistentnog stanja, nema oporavka od pada. To je kriptografska jezgra settlementa —
temelj na koji se L2 priča može graditi, ne gotov L2.

---

## Sigurnosne napomene

- `secp256k1_musig` je **eksperimentalni modul**. Njegov API nije stabilan. Sam build ispisuje
  *"Experimental features do not have stable APIs or properties, and may not be safe for
  production use."* Ovo nije kod za držanje stvarnih sredstava bez vanjskog audita.
- Privatni ključevi u testu su generirani lokalno i namijenjeni isključivo regtestu.
- `keys.txt`, `operators.txt`, `prover.txt`, `challenger.txt` i `bond.txt` sadrže **tajne
  u čistom tekstu**. Nikad ih ne commitaj u git. Dodani su u `.gitignore`.

---

## Licenca

MIT (kao i libsecp256k1). Koristi na vlastitu odgovornost.
