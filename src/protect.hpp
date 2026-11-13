// protect.hpp — zaštita unilateralnog exita: NUMS internal key + CSV raspored
//
// Bez ovoga exit ne vrijedi ništa: output je jedan UTXO s dvije putanje, a
// operatori su mogli potrošiti key-path ODMAH, pa su u utrci za isti UTXO
// trivijalno pobjeđivali korisnika koji čeka CSV.
//
// Rješenje:
//   internal key = BIP-341 NUMS točka (diskretni log nepoznat) ⇒ key-path nemoguć
//   operatorski list ima CSV STROŽI (veći) od korisničkog  ⇒ korisnik ima prozor
#pragma once

#include "taproot.hpp"

namespace bec {

// Operatorski list:  <op_delay> OP_CSV OP_DROP <op_xonly> OP_CHECKSIG
inline std::vector<unsigned char> csv_checksig_script(const unsigned char xonly[32],
                                                      uint32_t delay_blocks) {
    std::vector<unsigned char> s;
    push_scriptnum(s, delay_blocks);
    s.push_back(OP_CHECKSEQUENCEVERIFY);
    s.push_back(OP_DROP);
    push_data(s, xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

// BIP-341 NUMS ("nothing up my sleeve") internal key.
// Nitko ne zna diskretni logaritam ove točke, pa je key-path potrošnja
// NEMOGUĆA. Output je time trošiv isključivo preko skriptnog stabla.
inline const unsigned char* nums_internal_key() {
    static const unsigned char k[32] = {
        0x50,0x92,0x9b,0x74,0xc1,0xa0,0x49,0x54,0xb7,0x8b,0x4b,0x60,0x35,0xe9,0x7a,0x5e,
        0x07,0x8a,0x5a,0x0f,0x28,0xec,0x96,0xd5,0x47,0xbf,0xee,0x9a,0xce,0x80,0x3a,0xc0};
    return k;
}

} // namespace bec
