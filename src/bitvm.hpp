// bitvm.hpp — BitVM jezgra: bit-commitment bond s dokazivom ekvivokacijom
//
// ŠTO JE BITVM (i što ovdje jest, a što nije)
// BitVM je način da Bitcoin provjeri izračun koji sam ne može izvršiti: prover
// tvrdi "izračunao sam X", a svako ga može uhvatiti u laži tako da ga prisili
// da otvori pojedini bit svog međurezultata. Ako za isti bit otvori dvije
// različite vrijednosti, to je ekvivokacija — i dokazivo je na lancu.
//
// OVDJE JEST:
//   · stvarni bit commitment: za svaki indeks i postoje dva hasha, h0(i) i h1(i)
//   · stvarna kazna: skript koji prihvaća SAMO oba preimagea za isti indeks,
//     pa ekvivokacija nije tvrdnja nego uvjet potrošnje
//   · stvarni timeout: prover vraća bond nakon CSV-a ako nitko ne ospori
//   · sve četiri putanje su testirane na Bitcoin Core konsenzusu
//
// OVDJE NIJE (i ne tvrdim da jest):
//   · nema garbled circuits ni matrica skriptova (Bristol fashion) — to je
//     ono što BitVM2 koristi da provjeri cijeli izraz, a ne jedan bit
//   · nema bisection protokola preko razina poziva — ovdje je jedan sloj
//     (indeks bira osporavatelj, kao jedan korak bisekcije)
//   · nema na-lancu provjere da je otkriveni bit ISPRAVAN za tvrdnju;
//     na lancu se dokazuje samo da su otkrivena DVA proturječna bita
//
// Dakle: ovo je BitVM *primitiv*, ne BitVM2 protokol. Ime je važno.
#pragma once

#include "taproot.hpp"

namespace bec {

// Preimage bita: SHA256(0x00 || v || i_le32 || salt)
// Salt je 32-bajtni master-secret provera; preimage je 38 bajtova.
inline void bit_preimage(unsigned char value, uint32_t index, const unsigned char salt[32],
                         unsigned char out[32]) {
    unsigned char buf[38];
    buf[0] = 0x00;
    buf[1] = value;                       // 0x00 ili 0x01
    for (int b = 0; b < 4; b++) buf[2 + b] = (unsigned char)(index >> (8 * b));
    std::memcpy(buf + 6, salt, 32);
    sha256(buf, sizeof(buf), out);
}

// Commitment bita: SHA256(preimage). Ovo je ono što ide u skript.
// Namjerno obični SHA-256 — skript radi OP_SHA256 <hash> OP_EQUALVERIFY.
inline void bit_commitment(unsigned char value, uint32_t index, const unsigned char salt[32],
                           unsigned char out[32]) {
    unsigned char pre[32];
    bit_preimage(value, index, salt, pre);
    sha256(pre, 32, out);
}

// List kazne za indeks i:
//   OP_SHA256 <h1> OP_EQUALVERIFY OP_SHA256 <h0> OP_EQUALVERIFY <challenger> OP_CHECKSIG
//
// Potrošiv je SAMO ako witness sadrži oba preimagea za isti indeks:
//   witness = [sig, preimage(0,i), preimage(1,i)]
// Time ekvivokacija nije tvrdnja koju netko treba dokazati — ona je uvjet
// bez kojeg skript ne prolazi. Tko otvori oba bita, predao je bond.
inline std::vector<unsigned char> equivocation_penalty_script(const unsigned char h0[32],
                                                              const unsigned char h1[32],
                                                              const unsigned char challenger_xonly[32]) {
    std::vector<unsigned char> s;
    s.push_back(OP_SHA256);
    push_data(s, h1, 32);
    s.push_back(OP_EQUALVERIFY);
    s.push_back(OP_SHA256);
    push_data(s, h0, 32);
    s.push_back(OP_EQUALVERIFY);
    push_data(s, challenger_xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

// Timeout list: prover vraća bond nakon CSV-a ako nitko nije osporio.
inline std::vector<unsigned char> bond_timeout_script(const unsigned char prover_xonly[32],
                                                      uint32_t csv_blocks) {
    std::vector<unsigned char> s;
    push_scriptnum(s, csv_blocks);
    s.push_back(OP_CHECKSEQUENCEVERIFY);
    s.push_back(OP_DROP);
    push_data(s, prover_xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

} // namespace bec
