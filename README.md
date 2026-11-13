# Bitcoin BEC Condenser — stvarna implementacija

MuSig2 (BIP-327) + Taproot (BIP-341) settlement za L2 stanje, **testirano na Bitcoin Core konsenzusu**.

Ovo nije samo benchmark agregacije ključeva. Ovo je program koji:
- izgradi stvarni Taproot output koji komitira cijelo L2 stanje,
- potpiše ga **pravim MuSig2 protokolom u dvije runde**,
- potroši ga na lancu **key-path** putanjom (64-bajtni witness, neovisno o broju korisnika),
- i omogući svakom korisniku **unilateralni exit** bez ikakve suradnje operatora.

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
 8. Skala: 5000 korisnika           ✅ 82 ms, 4096 exit listova, dubina 12
────────────────────────────────────────────────────────────────
   PASS: 13   FAIL: 0
════════════════════════════════════════════════════════════════
```

Negativni testovi su namjerno tu: test koji uvijek prolazi ne dokazuje ništa.
Ta tri testa padaju s **točno onim konsenzus greškama koje Bitcoin Core stvarno vraća**.

---

## Arhitektura

```
   L2 stanje: 5000 korisnika (xonly ključ + balans)
        │
        ├── Merkle stablo stanja ──────────► state root  (13 razina, dokaz 416 B)
        │
        ├── tapscript stablo (4096 listova)
        │      svaki list:  <state_root> DROP <delay> CSV DROP <user_key> CHECKSIG
        │      └─ state root je U SVAKOM LISTU → output key obavezno komitira stanje
        │
        └── MuSig2 agregat operatorskih ključeva ──► internal key
                                                          │
                              BIP-341 taptweak:  t = H("TapTweak", internal ‖ script_root)
                                                          │
                                                Taproot output key (32 B)
                                                          │
                                            bech32m adresa (bcrt1p…)

  TROŠENJE:
    key-path    →  MuSig2 dvije runde → 64 B Schnorr potpis   [kooperativni settlement]
    script-path →  user potpis + kontrolni blok + CSV delay    [unilateralni exit]
```

**Zašto ovo radi, a MuSig2-sam-za-5000-korisnika ne bi:** MuSig2 se koristi za **3 operatora**
(mali, uvijek dostupan skup). 5000 korisnika je u **skriptnom stablu** i Merkle dokazu — svaki
korisnik izlazi sam, bez rundi komunikacije i bez mogućnosti da ga bilo ko blokira.
To je jedina podjela koja ima smisla na Bitcoinu danas.

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

# 2. program
g++ -std=c++17 -O2 -I../secp-inst/include src/main.cpp -o bec \
    -L../secp-inst/lib -lsecp256k1

# ili sve odjednom:
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

# 2) commitment: state root + tapscript stablo + MuSig2 internal key + adresa
./bec commit --keys keys.txt --operators operators.txt \
             --delay 144 --leaves 4096 --hrp bcrt --out commitment.txt

# 3) kooperativni settlement (svi operatori, MuSig2, dvije runde)
./bec spend-keypath --commitment commitment.txt \
             --txid <funding-txid> --vout <n> --amount <sats> \
             --dest-script <hex> --fee 2000 --out keypath.hex

# 4) unilateralni exit korisnika (bez operatora, nakon CSV delaya)
./bec spend-scriptpath --commitment commitment.txt \
             --txid <funding-txid> --vout <n> --amount <sats> \
             --dest-script <hex> --fee 2000 \
             --leaf 2 --sequence 144 --out scriptpath.hex

# 5) dokaz da je korisnik u stanju
./bec proof --keys keys.txt --commitment commitment.txt --index 7
```

`--hrp`: `bc` (mainnet), `tb` (testnet), `bcrt` (regtest).

---

## Test na Bitcoin Core

```bash
BITCOIN_BIN=/put/do/bitcoin-27.1/bin SECP_PREFIX=/put/do/secp-inst \
    bash test/run_regtest.sh
```

Skripta diže vlastiti regtest node u `.regtest-data/`, rudari 150 blokova, i vozi svih
13 testova od nule. Traje ~15 sekundi i ne dira nikakav postojeći node.

---

## Što je u kodu

| Datoteka | Sadržaj |
|---|---|
| `src/crypto.hpp` | Pravi SHA-256, `tagged_hash` (BIP-340), hex, **bech32m** (BIP-350) |
| `src/taproot.hpp` | Merkle stablo + dokaz, tapscript gradnja, **BIP-341** skriptno stablo, taptweak, kontrolni blok, **sighash**, serijalizacija tx |
| `src/musig.hpp` | **BIP-327** MuSig2: agregacija ključeva, dvije runde, agregacija potpisa, taptweak kroz keyagg cache |
| `src/main.cpp` | CLI: `genkeys`, `commit`, `spend-keypath`, `spend-scriptpath`, `proof` |
| `test/run_regtest.sh` | End-to-end test na Bitcoin Core + tri negativna testa |

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
| "Covenant verified" = tautologija | stvarni CSV exit koji Bitcoin Core prihvaća |
| `Main2.cpp` se ne kompajlira | jedan program, jedan `main.cpp` |
| nema validacije ulaza | strogi hex, provjera svake povratne vrijednosti |
| nema `context_randomize` | randomiziran kontekst, `secure_zero` nad tajnama |

---

## Ograničenja — što još NIJE napravljeno

Ovo je pošteni popis, ne marketinški.

**1. Verifikacija Merkle dokaza *unutar* skripte traži OP_CAT.**
OP_CAT (BIP-347) nije aktiviran na Bitcoinu. Bez njega se u tapscriptu ne mogu spojiti dva
32-bajtna hasha u 64-bajtni preimage, pa se inclusion proof ne može provjeriti on-chain.
Zato je ovdje:
- state root **komitiran u output key** (preko svakog exit lista) — mijenjanje stanja mijenja adresu;
- inclusion proof se **provjerava off-chain** (`./bec proof`);
- on-chain exit ide preko **CSV delay + korisnikov ključ** — korisnik stvarno može izaći sam.

Alternativa koja radi danas, bez soft forka: **BitVM2** (optimistic exit s challenge periodom).
To je zaseban, velik posao i nije u ovom kodu.

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
`pk()` listovima. Za ne-potencije dvojke stablo je i dalje ispravno (testirano potrošnjom),
samo se ne može jednoznačno opisati deskriptorom.

**5. Ovo nije L2 protokol.** Nema konsenzusa među operatorima, nema gossip-a, nema
perzistentnog stanja, nema oporavka od pada. To je kriptografska jezgra settlementa —
temelj na koji se L2 priča može graditi, ne gotov L2.

---

## Sigurnosne napomene

- `secp256k1_musig` je **eksperimentalni modul**. Njegov API nije stabilan. Sam build ispisuje
  *"Experimental features do not have stable APIs or properties, and may not be safe for
  production use."* Ovo nije kod za držanje stvarnih sredstava bez vanjskog audita.
- Privatni ključevi u testu su generirani lokalno i namijenjeni isključivo regtestu.
- `keys.txt` i `operators.txt` sadrže **privatne ključeve u čistom tekstu**. Nikad ih ne
  commitaj u git. Dodani su u `.gitignore`.

---

## Licenca

MIT (kao i libsecp256k1). Koristi na vlastitu odgovornost.
