// challenge.hpp — challenge/response (optimistic exit) sloj
//
// PROBLEM KOJI RJEŠAVA
// Bez covenanta skripta ne može provjeriti "ovaj izlaz nosi točno moj balans".
// Korisnik koji izađe podigne cijeli UTXO — dobije više nego što mu pripada.
//
// RJEŠENJE (optimistic, kao kod rollupa):
// Izlaz nije konačan. Nakon što korisnik podigne sredstva, postoji prozor u
// kojem SVAKO može uložiti dokaz prijevare i preuzeti izlaz. Korisnik dobiva
// sredstva tek ako prozor prođe bez osporavanja.
//
//   1. CLAIM      korisnik potroši zajednički UTXO u "claim" izlaz i veže se
//                 na digest tvrdnje (claim_digest) koji je dio skripta.
//   2. WINDOW     unutar CHALLENGE_WINDOW blokova nitko ne može potrošiti izlaz.
//   3. CHALLENGE  ako je tvrdnja lažna, osporavatelj otkrije "evidence" čiji
//                 SHA-256 odgovara claim_digest → preuzima izlaz.
//   4. SETTLE     ako prozor prođe bez osporavanja, korisnik preuzima izlaz.
//
// ŠTO JE NA LANCU PROVJERLJIVO
//   · claim_digest je u skriptu → tvrdnja je nepromjenjivo vezana prije uplate
//   · osporavatelj mora otkriti preimage koji hashira na claim_digest
//     (OP_SHA256 + OP_EQUALVERIFY) → dokaz je javan i neporeciv
//   · vremenski prozor je u skriptu (OP_CSV) → ni jedan ni drugi ne mogu preskočiti
//
// ŠTO OSTAJE IZVAN LANCA (pošteno rečeno)
//   · DA JE TVRDNJA LAŽNA provjerava se izvan lanca. On-chain se dokazuje samo
//     da je osporavatelj otkrio točno onaj dokaz na koji se korisnik vezao.
//     BitVM2 bi i tu provjeru doveo na lanac kroz bit-commitments; to je
//     zaseban, mnogo veći posao (vidi README, ograničenje 0).
//   · Nitko ne mora gledati. Ako nitko ne ospori u prozoru, lažna tvrdnja
//     prolazi. To je ista pretpostavka kao kod svakog optimistic rollupa:
//     potreban je barem jedan pošteni promatrač.
#pragma once

#include "taproot.hpp"

namespace bec {

// List kojim korisnik preuzima sredstva nakon što prozor prođe bez osporavanja:
//   <claim_digest> DROP <window> OP_CSV DROP <user_xonly> OP_CHECKSIG
//
// claim_digest je ubačen u skript, pa je tvrdnja (iznos, index, state root)
// nepromjenjivo vezana PRIJE nego što je novac otišao.
inline std::vector<unsigned char> claim_leaf_script(const unsigned char claim_digest[32],
                                                    const unsigned char user_xonly[32],
                                                    uint32_t window_blocks) {
    std::vector<unsigned char> s;
    push_data(s, claim_digest, 32);
    s.push_back(OP_DROP);
    push_scriptnum(s, window_blocks);
    s.push_back(OP_CHECKSEQUENCEVERIFY);
    s.push_back(OP_DROP);
    push_data(s, user_xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

// List kojim osporavatelj preuzima sredstva uz javni dokaz prijevare:
//   OP_SHA256 <claim_digest> OP_EQUALVERIFY <window> OP_CSV DROP <challenger_xonly> OP_CHECKSIG
//
// Witness mora sadržavati preimage (evidence) čiji SHA-256 odgovara
// claim_digest. Bez točnog dokaza skript pada na OP_EQUALVERIFY.
inline std::vector<unsigned char> challenge_leaf_script(const unsigned char claim_digest[32],
                                                        const unsigned char challenger_xonly[32],
                                                        uint32_t window_blocks) {
    std::vector<unsigned char> s;
    s.push_back(OP_SHA256);              // troši evidence iz witnessa
    push_data(s, claim_digest, 32);      // očekivani digest
    s.push_back(OP_EQUALVERIFY);         // dokaz mora odgovarati — inače pad
    push_scriptnum(s, window_blocks);
    s.push_back(OP_CHECKSEQUENCEVERIFY);
    s.push_back(OP_DROP);
    push_data(s, challenger_xonly, 32);
    s.push_back(OP_CHECKSIG);
    return s;
}

// Tvrdnja koju korisnik potpisuje i na koju se veže kroz claim_digest.
// Sve što je u njoj mora biti javno objavljeno prije izlaza, inače je
// osporavatelj ne može provjeriti.
inline void claim_digest_of(const unsigned char state_root[32], size_t user_index,
                            uint64_t claimed_sats, unsigned char out[32]) {
    unsigned char payload[48];
    std::memcpy(payload, state_root, 32);
    for (int b = 0; b < 8; b++) payload[32 + b] = (unsigned char)((uint64_t)user_index >> (8 * b));
    for (int b = 0; b < 8; b++) payload[40 + b] = (unsigned char)(claimed_sats >> (8 * b));
    // NAMJERNO obični SHA-256 (ne tagged_hash): skript radi
    // OP_SHA256 <digest> OP_EQUALVERIFY, pa SHA256(evidence) mora dati digest.
    sha256(payload, sizeof(payload), out);
}

} // namespace bec
