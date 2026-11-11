#ifndef NODES_HPP
#define NODES_HPP

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

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

    bool sendL2Transaction(L2NetworkNode& receiver, uint64_t amount_sats) {
        if (l2_balance_sats < amount_sats) {
            return false;
        }
        l2_balance_sats -= amount_sats;
        receiver.l2_balance_sats += amount_sats;
        return true;
    }

    void exportStatePayload(secp256k1_context* ctx, unsigned char* pubkey_out, unsigned char* balance_out) const {
        secp256k1_xonly_pubkey_serialize(ctx, pubkey_out, &xonly_pubkey);
        std::memcpy(balance_out, &l2_balance_sats, sizeof(uint64_t));
    }
};

#endif

