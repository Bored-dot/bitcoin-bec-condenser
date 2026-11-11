#ifndef NODES_HPP
#define NODES_HPP

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

class L2NetworkNode {
public:
    std::string node_id;
    unsigned char private_key[32];
    secp256k1_keypair keypair;
    secp256k1_pubkey full_pubkey;
    secp256k1_xonly_pubkey xonly_pubkey;
    uint64_t l2_balance_sats;

    L2NetworkNode(secp256k1_context* ctx, const std::string& id, const unsigned char* priv_key, uint64_t initial_balance) {
        node_id = id;
        l2_balance_sats = initial_balance;
        std::memcpy(private_key, priv_key, 32);

        if (secp256k1_keypair_create(ctx, &keypair, private_key) == 1) {
            secp256k1_keypair_pub(ctx, &full_pubkey, &keypair);
            secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair);
        } else {
            std::cerr << "[Node Error] Failed to generate cryptographic keys for " << node_id << "\n";
        }
    }

    // Generates a 32-byte deterministic transaction message hash
    void createTxMessageHash(const std::string& receiver_id, uint64_t amount_sats, unsigned char* msg_hash_out) const {
        std::memset(msg_hash_out, 0x3A, 32);
        std::memcpy(msg_hash_out, &amount_sats, sizeof(uint64_t));
        for (size_t i = 0; i < receiver_id.size() && i < 24; ++i) {
            msg_hash_out[8 + i] ^= static_cast<unsigned char>(receiver_id[i]);
        }
    }

    // Signs an off-chain L2 transaction using BIP-340 Schnorr signature
    bool signL2Transaction(secp256k1_context* ctx, const std::string& receiver_id, uint64_t amount_sats, unsigned char* sig_out) const {
        unsigned char msg_hash[32];
        createTxMessageHash(receiver_id, amount_sats, msg_hash);
        return secp256k1_schnorrsig_sign32(ctx, sig_out, msg_hash, &keypair, NULL) == 1;
    }

    // Executes an authenticated off-chain transfer after verifying the sender's Schnorr signature
    bool sendAuthenticatedL2Transaction(secp256k1_context* ctx, L2NetworkNode& receiver, uint64_t amount_sats) {
        if (l2_balance_sats < amount_sats) {
            return false; // Insufficient balance
        }

        // 1. Sender signs the transaction intent
        unsigned char signature[64];
        if (!signL2Transaction(ctx, receiver.node_id, amount_sats, signature)) {
            return false; // Signing failed
        }

        // 2. Network / Receiver verifies the 64-byte Schnorr signature against Sender's X-only PubKey
        unsigned char msg_hash[32];
        createTxMessageHash(receiver.node_id, amount_sats, msg_hash);
        if (secp256k1_schnorrsig_verify(ctx, signature, msg_hash, 32, &xonly_pubkey) != 1) {
            std::cerr << "[Security Alert] Invalid Schnorr signature rejected from " << node_id << "!\n";
            return false; // Cryptographic verification failed
        }

        // 3. State transition executes only after cryptographic proof is confirmed
        l2_balance_sats -= amount_sats;
        receiver.l2_balance_sats += amount_sats;
        return true;
    }

    void exportStatePayload(secp256k1_context* ctx, unsigned char* pubkey_out, unsigned char* balance_out) const {
        secp256k1_xonly_pubkey_serialize(ctx, pubkey_out, &xonly_pubkey);
        std::memcpy(balance_out, &l2_balance_sats, sizeof(uint64_t));
    }
};

#endif // NODES_HPP

